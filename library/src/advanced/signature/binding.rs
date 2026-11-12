// SPDX-License-Identifier: Apache-2.0
//! Destination ownership for native signatures and mutating cipher keys.
use super::{Kind, SignatureOperation};
use crate::advanced::{record, StateKeyEncoding, StateKeyReference, StateRestoreKeys};
use crate::managed::{NativeIdentity, RevocationTargets};
use crate::session::activity::{AccessMode, RolePlan};
use crate::session::{AdmissionProgress, SessionAccess};
use crate::{Error, MechanismExtension, NativeObjectRef, Result, Session};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};
use std::sync::{atomic::Ordering, Arc};

/// No module owner or session guard is retained by a resident binding.
pub(in crate::advanced) struct Binding {
    pub(in crate::advanced) key: Arc<NativeIdentity>,
    pub(in crate::advanced) authentication: u64,
    pub(in crate::advanced) roles: super::roles::Roles,
    pub(in crate::advanced) contract: MechanismExtension,
    pub(in crate::advanced) own_revocation: bool,
    pub(in crate::advanced) revocation: Option<RevocationTargets>,
}
impl Binding {
    pub(in crate::advanced) fn check(&self, entry: &crate::module::SessionEntry) -> Result<()> {
        if self.key.revoked.load(Ordering::Acquire) && !self.own_revocation {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::RevokedSignatureDestination,
                ),
            ));
        }
        crate::managed::check_creator(self.key.creator())?;
        entry
            .snapshot
            .check_authentication_unchanged(self.authentication)?;
        self.key.access().check(&entry.snapshot)
    }
    pub(in crate::advanced) fn duplicate(&self) -> Result<Self> {
        if self.revocation.is_some() {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::UnsubmittedSignatureBindingCannotBeDuplicated),
            ));
        }
        Ok(Self {
            key: self.key.clone(),
            authentication: self.authentication,
            roles: self.roles.clone(),
            contract: self.contract.clone(),
            own_revocation: self.own_revocation,
            revocation: None,
        })
    }
    /// Called immediately before the first native state-replacement attempt.
    /// The writer remains retained even when that attempt has an uncertain effect.
    pub(in crate::advanced) fn arm(&mut self) {
        if let Some(revocation) = self.revocation.take() {
            self.own_revocation = true;
            drop(revocation.arm());
        }
    }
    pub(in crate::advanced) fn handle(&self, encoding: StateKeyEncoding) -> CK_OBJECT_HANDLE {
        match encoding {
            StateKeyEncoding::Supplied => self.key.handle,
            StateKeyEncoding::Embedded => CK_INVALID_HANDLE,
        }
    }
}

#[derive(Clone, Copy)]
enum Source<'a> {
    Signature(&'a SignatureOperation),
    Cipher(&'a crate::advanced::keys::KeyLease),
}
impl<'a> Source<'a> {
    fn check(self, entry: &crate::module::SessionEntry) -> Result<()> {
        match self {
            Self::Signature(source) => source.check_key(entry),
            Self::Cipher(source) => source.check(entry),
        }
    }
    fn own_revocation(self) -> bool {
        match self {
            Self::Signature(source) => source.own_revocation,
            Self::Cipher(source) => source.owns_revocation(),
        }
    }
    fn authentication(self) -> u64 {
        match self {
            Self::Signature(source) => source.authentication,
            Self::Cipher(source) => source.authentication_stamp(),
        }
    }
    fn roles(self) -> Result<&'a crate::advanced::key_roles::Roles> {
        match self {
            Self::Signature(source) => Ok(&source._roles),
            Self::Cipher(source) => source.writer_roles().ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherWriterPermissionAbsent,
                ),
            )),
        }
    }
}

pub(in crate::advanced) struct Destination<'a> {
    key: &'a NativeObjectRef,
    contract: MechanismExtension,
    source: Option<Source<'a>>,
    roles: Option<RolePlan<'a, 1>>,
    transfer: Option<super::roles::PreparedTransfer>,
    storage: crate::advanced::key_storage::Ready,
}
/// No source borrow remains, but every owned preparation survives until the
/// containing transaction releases session access.
pub(in crate::advanced) struct RetiredDestination {
    _contract: MechanismExtension,
    _roles: Option<crate::session::activity::RetiredRolePlan<1>>,
    _transfer: Option<super::roles::PreparedTransfer>,
    _storage: crate::advanced::key_storage::Ready,
}
impl<'a> Destination<'a> {
    pub(in crate::advanced) fn retire(self) -> RetiredDestination {
        RetiredDestination {
            _contract: self.contract,
            _roles: self.roles.map(RolePlan::retire),
            _transfer: self.transfer,
            _storage: self.storage,
        }
    }

    fn cipher_key(keys: StateRestoreKeys<'a>) -> Result<&'a NativeObjectRef> {
        if keys.authentication.is_some() {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::CipherAuthenticationRoleAbsent,
                ),
            ));
        }
        match keys.encryption.map(|key| key.reference) {
            Some(StateKeyReference::NativeSecret(key)) => Ok(key),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::NativeCipherWriterDestinationRequired,
                ),
            )),
        }
    }
    pub(in crate::advanced) fn cipher_captured(
        session: &Session,
        source: &'a crate::advanced::cipher::CipherOperation,
        keys: StateRestoreKeys<'a>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let key = Self::cipher_key(keys)?;
        let contract = crate::advanced::cipher::extension_binding::captured_contract(
            session,
            source,
            keys.extension,
        )?
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::CipherWriterDeclarationAbsent,
            ),
        ))?;
        let source = source.writer_binding_source()?;
        source.check(&session.entry)?;
        if !Arc::ptr_eq(&session.inner, &key.inner)
            || key.identity.session != session.uid
            || key.identity.slot != session.entry.slot
            || key.identity.generation != session.snapshot.generation
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::ForeignCipherDestination,
                ),
            ));
        }
        let same = Arc::ptr_eq(&key.identity, source.native_identity());
        let transferred = !same
            && key.identity.resource().native() == source.native_identity().resource().native()
            && Arc::ptr_eq(
                key.identity.activity()?,
                source.native_identity().activity()?,
            );
        let transfer = transferred
            .then(|| {
                super::roles::PreparedTransfer::prepare(
                    session,
                    key.identity.activity()?,
                    progress,
                    authentication,
                )
            })
            .transpose()?;
        let mut result = Self {
            key,
            contract,
            source: (same || transferred).then_some(Source::Cipher(source)),
            roles: None,
            transfer,
            storage: crate::advanced::key_storage::Ready::default(),
        };
        result.prepare_roles(session, progress, authentication)?;
        Ok(result)
    }
    pub(in crate::advanced) fn cipher_imported(
        session: &Session,
        descriptor: record::Descriptor,
        messages: &record::Messages<'_>,
        keys: StateRestoreKeys<'a>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let key = Self::cipher_key(keys)?;
        let contract = crate::advanced::cipher::extension_binding::import_contract(
            session,
            descriptor,
            messages,
            keys.extension,
        )?
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::CipherWriterDeclarationAbsent,
            ),
        ))?;
        if !contract.mutates_key() {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::CipherWriterDeclarationRequired,
            )));
        }
        let mut result = Self {
            key,
            contract,
            source: None,
            roles: None,
            transfer: None,
            storage: crate::advanced::key_storage::Ready::default(),
        };
        result.prepare_roles(session, progress, authentication)?;
        Ok(result)
    }

    fn selection(
        keys: StateRestoreKeys<'a>,
    ) -> Result<(&'a NativeObjectRef, Option<&'a MechanismExtension>)> {
        if keys.encryption.is_some() {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureHasNoCipherKeyRole,
                ),
            ));
        }
        match keys.authentication.map(|key| key.reference) {
            Some(StateKeyReference::NativeSignature { key, extension }) => Ok((key, extension)),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::NativeSignatureDestinationRequired,
                ),
            )),
        }
    }
    pub(in crate::advanced) fn captured(
        session: &Session,
        source: &'a SignatureOperation,
        keys: StateRestoreKeys<'a>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let (key, extension) = Self::selection(keys)?;
        source.check_key(&session.entry)?;
        source
            .contract
            .check(&session.inner, source.kind.operation(source.route))?;
        if let Some(extension) = extension {
            extension.check(&session.inner, source.kind.operation(source.route))?;
            if extension.mechanism_number() != source.contract.mechanism_number()
                || extension.constants_edition() != source.contract.constants_edition()
                || extension.mutates_key() != source.contract.mutates_key()
            {
                return Err(Error::Rejected(crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::SignatureDestinationDeclarationChanged)));
            }
        }
        if !Arc::ptr_eq(&session.inner, &key.inner)
            || key.identity.session != session.uid
            || key.identity.slot != session.entry.slot
            || key.identity.generation != session.snapshot.generation
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::ForeignSignatureDestination,
                ),
            ));
        }
        // Module, generation and canonical Activity must agree before borrowing
        // a writer capability. Handle equality by itself grants no permission.
        let same_identity = Arc::ptr_eq(&key.identity, &source.key);
        let transferred_writer = !same_identity
            && source.contract.mutates_key()
            && key.identity.resource().native() == source.key.resource().native()
            && Arc::ptr_eq(key.identity.activity()?, source.key.activity()?);
        let transfer = transferred_writer
            .then(|| {
                super::roles::PreparedTransfer::prepare(
                    session,
                    key.identity.activity()?,
                    progress,
                    authentication,
                )
            })
            .transpose()?;
        let contract = source.contract.clone();
        let source = (same_identity || transferred_writer).then_some(Source::Signature(source));
        let mut result = Self {
            key,
            contract,
            source,
            roles: None,
            transfer,
            storage: crate::advanced::key_storage::Ready::default(),
        };
        // The source operation's declaration is authoritative for a local
        // capture even when the caller selects a different native key.
        result.prepare_roles(session, progress, authentication)?;
        Ok(result)
    }
    pub(in crate::advanced) fn imported(
        session: &Session,
        descriptor: record::Descriptor,
        messages: &record::Messages<'_>,
        keys: StateRestoreKeys<'a>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let (key, extension) = Self::selection(keys)?;
        let message = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureMessageAbsent,
            ),
        ))??;
        let parameters = message.params.signature.ok_or(Error::Rejected(
            crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureParametersAbsent,
            ),
        ))?;
        let kind = Kind::from_profile(descriptor.profile)?;
        let operation = kind.operation(message.route);
        // This mechanism's scalar meaning is not established by its numeric
        // identifier. Require a destination assertion even for a record whose
        // provenance bit incorrectly labels it as a standard layout.
        let contract = if parameters.caller_asserted
            || descriptor.mechanism == fe11_sys::CKM_SHA512_T_HMAC_GENERAL as u64
        {
            let declaration =
                extension.ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::ImportRequiresADestinationAbiDeclaration,
                )))?;
            declaration.check(&session.inner, operation)?;
            declaration.clone()
        } else {
            // No Init is reconstructed or dispatched from these bytes. The
            // graph is locally relocated for retained output/metadata only;
            // C_SetOperationState receives the module's separate opaque state.
            MechanismExtension::standard(
                &session.inner,
                fe11_sys::CK_MECHANISM_TYPE::try_from(descriptor.mechanism).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::OperationRecord(
                        crate::OperationRecordRejection::SignatureMechanismWidth,
                    ))
                })?,
                operation,
            )
        };
        if contract.mechanism_number() != descriptor.mechanism
            || contract.constants_edition() != parameters.edition
            || contract.mutates_key() != parameters.mutates_key
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureImportDeclarationMismatch,
                ),
            ));
        }
        if let Some(extension) = extension {
            extension.check(&session.inner, operation)?;
            if extension.mechanism_number() != descriptor.mechanism
                || extension.constants_edition() != parameters.edition
                || extension.mutates_key() != parameters.mutates_key
            {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::ExplicitSignatureDeclarationMismatch,
                    ),
                ));
            }
        }
        let mut result = Self {
            key,
            contract,
            source: None,
            roles: None,
            transfer: None,
            storage: crate::advanced::key_storage::Ready::default(),
        };
        result.prepare_roles(session, progress, authentication)?;
        Ok(result)
    }
    fn prepare_roles(
        &mut self,
        session: &Session,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<()> {
        if self.source.is_none() && self.roles.is_none() {
            let mode = if self.contract.mutates_key() {
                AccessMode::Write
            } else {
                AccessMode::Read
            };
            self.roles = Some(RolePlan::prepare_advanced_at_epoch(
                session,
                [(Some(self.key), mode)],
                progress,
                authentication,
            )?);
        }
        Ok(())
    }
    pub(in crate::advanced) fn storage_plan(
        &self,
        session: &Session,
        authentication: u64,
    ) -> Result<crate::advanced::key_storage::Plan> {
        Ok(crate::advanced::key_storage::Plan {
            revocation: if self.contract.mutates_key()
                && !self.source.is_some_and(|source| source.own_revocation())
            {
                Some(crate::managed::RevocationShape::discover(
                    session,
                    self.key.identity.resource(),
                    authentication,
                )?)
            } else {
                None
            },
            transfers: [self.transfer.is_some(), false, false, false, false],
            permissions: usize::from(self.roles.is_some()),
        })
    }
    pub(in crate::advanced) fn attach_storage(
        &mut self,
        storage: crate::advanced::key_storage::Ready,
    ) {
        self.storage = storage;
    }
    pub(in crate::advanced) fn try_access<'s>(
        &mut self,
        session: &'s Session,
        progress: &AdmissionProgress,
    ) -> Result<(SessionAccess<'s>, Binding)> {
        let needs_revocation = self.contract.mutates_key()
            && !self.source.is_some_and(|source| source.own_revocation());
        if needs_revocation != self.storage.revocation.is_some()
            || self.transfer.is_some() != self.storage.transfers[0].is_some()
            || self.storage.transfers[1..].iter().any(Option::is_some)
            || self.roles.is_some() != self.storage.permissions.is_some()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::NativeDestinationStorageNotPrepared,
                ),
            ));
        }
        // Successful snapshots and bindings must also outlive local access:
        // later source/role checks may refuse before publication.
        let revocation;
        let binding;
        let access = if let Some(roles) = &self.roles {
            let permissions = self.storage.permissions.take().ok_or(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::NativeDestinationPermissionsAbsent,
                ),
            ))?;
            roles.access_prepared(
                session,
                &crate::ResourceAdmission::Immediate,
                permissions,
                || session.try_advanced_access_progress(progress),
            )?
        } else if self.source.is_some() {
            session.try_advanced_access_progress(progress)?
        } else {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureRolesNotPrepared,
                ),
            ));
        };
        revocation = self
            .storage
            .revocation
            .as_mut()
            .map(|prepared| {
                prepared.bind(&access)?.ok_or(Error::Busy(
                    crate::BusyReason::SignatureContinuation(
                        crate::SignatureContinuationBusy::SignatureRevocationCapacityChanged,
                    ),
                ))
            })
            .transpose()?;
        // Only an empty shell remains after successful transfer. On refusal
        // the earlier return retains the snapshot in storage until access leaves.
        drop(self.storage.revocation.take());
        binding = if let Some(source) = self.source {
            source.check(&session.entry)?;
            Binding {
                key: self.key.identity.clone(),
                authentication: source.authentication(),
                roles: match &self.transfer {
                    Some(transfer) => transfer.bind(
                        self.storage.transfers[0].as_ref().ok_or(Error::Rejected(
                            crate::RejectionReason::SignatureContinuation(
                                crate::SignatureContinuationRejection::NativeTransferStorageAbsent,
                            ),
                        ))?,
                        source.roles()?,
                    )?,
                    None => source.roles()?.clone(),
                },
                contract: self.contract.clone(),
                own_revocation: source.own_revocation(),
                revocation,
            }
        } else {
            session.native_object_handle(&access, self.key)?;
            Binding {
                key: self.key.identity.clone(),
                authentication: session.snapshot.authentication_stamp(),
                roles: super::roles::Roles::Original(access.retain_role_lease()),
                contract: self.contract.clone(),
                own_revocation: false,
                revocation,
            }
        };
        binding.check(&session.entry)?;
        Ok((access, binding))
    }
    pub(in crate::advanced) fn wait_after_contention(
        &mut self,
        session: &Session,
        progress: &AdmissionProgress,
        authentication: u64,
        error: Error,
    ) -> Result<()> {
        self.storage = crate::advanced::key_storage::Ready::default();
        let policy = crate::admission_wait::current();
        if !matches!(error, Error::Busy(_))
            || (matches!(policy, crate::ResourceAdmission::Immediate)
                && matches!(session.admission(), crate::ResourceAdmission::Immediate))
        {
            return Err(error);
        }
        self.prepare_roles(session, progress, authentication)?;
        if let Some(roles) = &self.roles {
            // The candidate and its charged slots have already retired. Probe
            // availability with stack permits under the original role epoch.
            roles.wait_available_in_context(session, &policy, || {
                session.advanced_access_progress_at_epoch(progress, authentication)
            })?;
        } else {
            drop(session.advanced_access_progress_at_epoch(progress, authentication)?);
        }
        Ok(())
    }
    pub(in crate::advanced) fn prepare_with<'s, T>(
        &mut self,
        session: &'s Session,
        progress: &AdmissionProgress,
        authentication: u64,
        mut prepare: impl FnMut(
            crate::advanced::key_storage::Plan,
        ) -> Result<(T, crate::advanced::key_storage::Ready)>,
    ) -> Result<(T, SessionAccess<'s>, Binding)> {
        loop {
            self.prepare_roles(session, progress, authentication)?;
            let (candidate, storage) = prepare(self.storage_plan(session, authentication)?)?;
            self.attach_storage(storage);
            match self.try_access(session, progress) {
                Ok((access, binding)) => return Ok((candidate, access, binding)),
                Err(error @ Error::Busy(_)) => {
                    drop(candidate);
                    self.wait_after_contention(session, progress, authentication, error)?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for Binding {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.key.retain_identity_credit(retained)?;
        super::roles::Roles::retain_unique(Some(&self.roles), [], retained)?;
        self.revocation.retain_credits(retained)?;
        Ok(())
    }
}
