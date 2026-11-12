// SPDX-License-Identifier: Apache-2.0
//! Prepare destination permissions before retaining an unpublished restore frame.
use super::KeyReaders;
use crate::advanced::{
    native_messages, record,
    signature::binding::{Binding, Destination},
    OperationBody, StateRestoreKeys,
};
use crate::session::{AdmissionProgress, SessionAccess};
use crate::{Error, Result, Session};

#[derive(Clone, Copy)]
pub(in crate::advanced) enum NativeRole {
    Signature,
    Cipher,
}
pub(in crate::advanced) enum Prepared<'a> {
    Readers(KeyReaders<2>),
    NativeMessages(native_messages::restoration::Destination<'a>),
    Native {
        destination: Destination<'a>,
        role: NativeRole,
    },
}
/// Destruction-only owners with no borrow of the saved operation being moved.
pub(in crate::advanced) enum Retired {
    Readers {
        _readers: KeyReaders<2>,
    },
    NativeMessages {
        _destination: native_messages::restoration::RetiredDestination,
    },
    Native {
        _destination: crate::advanced::signature::binding::RetiredDestination,
    },
}
pub(in crate::advanced) enum Acquired {
    Consumed,
    Readers([Option<crate::registry::ReadPermit>; 2]),
    NativeMessages(native_messages::Binding),
    Native { binding: Binding, role: NativeRole },
}
impl Acquired {
    /// Preserve acquired permissions and native snapshots until all local
    /// binding checks succeed. Reader reconstruction borrows the permit array.
    pub(in crate::advanced) fn bind(
        &mut self,
        keys: StateRestoreKeys<'_>,
        readers: impl FnOnce(
            &mut [Option<crate::registry::ReadPermit>; 2],
        ) -> Result<crate::advanced::restoration_keys::BoundKeys>,
    ) -> Result<crate::advanced::restoration_keys::BoundKeys> {
        use crate::advanced::restoration_keys::BoundKeys;
        match self {
            Self::Consumed => Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::RestorationBindingAlreadyConsumed,
            ))),
            Self::Readers(permits) => readers(permits),
            Self::NativeMessages(_) => {
                let encoding = keys
                    .authentication
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::MessageDestinationAbsent,
                    )))?
                    .encoding;
                let Self::NativeMessages(binding) = std::mem::replace(self, Self::Consumed) else {
                    unreachable!("validated message restoration binding")
                };
                Ok(BoundKeys::for_native_messages(binding, encoding))
            }
            Self::Native {
                role: NativeRole::Signature,
                ..
            } => {
                let encoding = keys
                    .authentication
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::SignatureDestinationAbsent,
                    )))?
                    .encoding;
                let Self::Native { binding, .. } = std::mem::replace(self, Self::Consumed) else {
                    unreachable!("validated signature restoration binding")
                };
                Ok(BoundKeys::signature(binding, encoding))
            }
            Self::Native {
                binding,
                role: NativeRole::Cipher,
            } => {
                super::KeyLease::check_cipher_binding(binding)?;
                let encoding = keys
                    .encryption
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::CipherDestinationAbsent,
                    )))?
                    .encoding;
                let Self::Native { binding, .. } = std::mem::replace(self, Self::Consumed) else {
                    unreachable!("validated cipher restoration binding")
                };
                let declaration = binding.contract.clone();
                let lease = super::KeyLease::from_checked_cipher_binding(binding);
                let mut bound = BoundKeys::new(Some((lease, encoding)), None);
                bound.extension = Some(declaration);
                Ok(bound)
            }
        }
    }
}
impl<'a> Prepared<'a> {
    pub(in crate::advanced) fn retire(self) -> Retired {
        match self {
            Self::Readers(readers) => Retired::Readers { _readers: readers },
            Self::NativeMessages(destination) => Retired::NativeMessages {
                _destination: destination.retire(),
            },
            Self::Native { destination, .. } => Retired::Native {
                _destination: destination.retire(),
            },
        }
    }

    pub(in crate::advanced) fn initialization_plan(
        &self,
    ) -> Option<native_messages::restoration::InitializationPlan<'a>> {
        match self {
            Self::NativeMessages(destination) => Some(destination.initialization_plan()),
            _ => None,
        }
    }
    pub(in crate::advanced) fn captured(
        session: &Session,
        body: &'a OperationBody,
        keys: StateRestoreKeys<'a>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        if keys.extension.is_some()
            && !matches!(body, OperationBody::Digest(_) | OperationBody::Cipher(_))
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::DigestDeclarationOnAnotherFamily,
            )));
        }
        if let OperationBody::Signature(source) = body {
            return Destination::captured(session, source, keys, progress, authentication).map(
                |destination| Self::Native {
                    destination,
                    role: NativeRole::Signature,
                },
            );
        }
        if let OperationBody::NativeMessages(source) = body {
            if keys.encryption.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::MessageHasNoCipherKeyRole,
                )));
            }
            let Some(crate::StateRestoreKey {
                reference:
                    crate::StateKeyReference::NativeMessages {
                        key,
                        auxiliary,
                        extension,
                        parameters,
                    },
                ..
            }) = keys.authentication
            else {
                return Err(Error::Rejected(crate::RejectionReason::Persistence(
                    crate::PersistenceRejection::NativeMessageDestinationRequired,
                )));
            };
            return native_messages::restoration::Destination::captured(
                session,
                source,
                key,
                auxiliary,
                extension,
                parameters,
                progress,
                authentication,
            )
            .map(Self::NativeMessages);
        }
        if let OperationBody::Cipher(source) = body {
            if source.requires_writer_destination() {
                return Destination::cipher_captured(
                    session,
                    source,
                    keys,
                    progress,
                    authentication,
                )
                .map(|destination| Self::Native {
                    destination,
                    role: NativeRole::Cipher,
                });
            }
        }
        Self::readers(session, keys, authentication, progress)
    }
    pub(in crate::advanced) fn imported(
        session: &Session,
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        keys: StateRestoreKeys<'a>,
        progress: &AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        if keys.extension.is_some()
            && descriptor.family != record::Family::Digest
            && !descriptor.family.is_cipher()
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::DigestDeclarationOnAnotherFamily,
            )));
        }
        if descriptor.family == record::Family::NativeMessages {
            if keys.encryption.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::MessageHasNoCipherKeyRole,
                )));
            }
            let Some(crate::StateRestoreKey {
                reference:
                    crate::StateKeyReference::NativeMessages {
                        key,
                        auxiliary,
                        extension,
                        parameters,
                    },
                ..
            }) = keys.authentication
            else {
                return Err(Error::Rejected(crate::RejectionReason::Persistence(
                    crate::PersistenceRejection::NativeMessageDestinationRequired,
                )));
            };
            let record =
                messages
                    .native()
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::GenericMessageArchiveBodyAbsent,
                    )))?;
            return native_messages::restoration::Destination::imported(
                session,
                record,
                descriptor.profile == 2,
                key,
                auxiliary,
                extension,
                parameters,
                progress,
                authentication,
            )
            .map(Self::NativeMessages);
        }
        if descriptor.family == record::Family::Signature {
            return Destination::imported(
                session,
                descriptor,
                messages,
                keys,
                progress,
                authentication,
            )
            .map(|destination| Self::Native {
                destination,
                role: NativeRole::Signature,
            });
        }
        if descriptor.family.is_cipher()
            && keys.encryption.is_some()
            && messages
                .iter()
                .next()
                .transpose()?
                .and_then(|message| message.params.cipher_extension)
                .is_some_and(|extension| extension.mutates_key)
        {
            return Destination::cipher_imported(
                session,
                descriptor,
                messages,
                keys,
                progress,
                authentication,
            )
            .map(|destination| Self::Native {
                destination,
                role: NativeRole::Cipher,
            });
        }
        Self::readers(session, keys, authentication, progress)
    }
    fn readers(
        session: &Session,
        keys: StateRestoreKeys<'_>,
        authentication: u64,
        progress: &AdmissionProgress,
    ) -> Result<Self> {
        if [keys.encryption, keys.authentication]
            .into_iter()
            .flatten()
            .any(|key| {
                matches!(
                    key.reference,
                    crate::StateKeyReference::NativeSignature { .. }
                        | crate::StateKeyReference::NativeMessages { .. }
                )
            })
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::SignatureReferenceOnAnotherOperationFamily,
            )));
        }
        KeyReaders::prepare_retaining_at_epoch(
            session,
            [
                keys.encryption.map(|key| key.reference.managed()),
                keys.authentication.map(|key| key.reference.managed()),
            ],
            authentication,
            progress,
        )
        .map(Self::Readers)
    }
    pub(in crate::advanced) fn storage_plan(
        &self,
        session: &Session,
        authentication: u64,
    ) -> Result<crate::advanced::key_storage::Plan> {
        match self {
            Self::Readers(_) => Ok(crate::advanced::key_storage::Plan::default()),
            Self::NativeMessages(destination) => destination.storage_plan(session, authentication),
            Self::Native { destination, .. } => destination.storage_plan(session, authentication),
        }
    }
    pub(in crate::advanced) fn attach_storage(
        &mut self,
        storage: crate::advanced::key_storage::Ready,
    ) -> Result<()> {
        match self {
            Self::Native { destination, .. } => destination.attach_storage(storage),
            Self::NativeMessages(destination) => destination.attach_storage(storage),
            Self::Readers(_) => {
                if storage.revocation.is_some()
                    || storage.transfers.iter().any(Option::is_some)
                    || storage.permissions.is_some()
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::NativeDestinationStorageWithoutNativeRole,
                    )));
                }
            }
        }
        Ok(())
    }
    pub(in crate::advanced) fn try_access_with_progress<'s>(
        &mut self,
        session: &'s Session,
        progress: &AdmissionProgress,
    ) -> Result<(SessionAccess<'s>, Acquired)> {
        match self {
            Self::NativeMessages(destination) => destination
                .try_access(session, progress)
                .map(|(access, binding)| (access, Acquired::NativeMessages(binding))),
            Self::Readers(readers) => readers
                .try_access_with_progress(session, progress)
                .map(|(access, readers)| (access, Acquired::Readers(readers))),
            Self::Native { destination, role } => {
                destination
                    .try_access(session, progress)
                    .map(|(access, signature)| {
                        (
                            access,
                            Acquired::Native {
                                binding: signature,
                                role: *role,
                            },
                        )
                    })
            }
        }
    }
    pub(in crate::advanced) fn wait_after_contention(
        &mut self,
        session: &Session,
        progress: &AdmissionProgress,
        authentication: u64,
        error: Error,
    ) -> Result<()> {
        match self {
            Self::NativeMessages(destination) => {
                destination.wait_after_contention(session, progress, authentication, error)
            }
            Self::Readers(readers) => {
                readers.wait_after_contention(session, progress, authentication, error)
            }
            Self::Native {
                destination,
                role: _,
            } => destination.wait_after_contention(session, progress, authentication, error),
        }
    }
    pub(in crate::advanced) fn prepare_with<'s, T>(
        &mut self,
        session: &'s Session,
        progress: &AdmissionProgress,
        authentication: u64,
        mut prepare: impl FnMut(
            crate::advanced::key_storage::Plan,
        ) -> Result<(T, crate::advanced::key_storage::Ready)>,
    ) -> Result<(T, SessionAccess<'s>, Acquired)> {
        match self {
            Self::NativeMessages(destination) => destination
                .prepare_with(session, progress, authentication, prepare)
                .map(|(candidate, access, binding)| {
                    (candidate, access, Acquired::NativeMessages(binding))
                }),
            Self::Readers(readers) => readers
                .prepare_with_at_epoch(session, progress, authentication, || {
                    let (candidate, storage) =
                        prepare(crate::advanced::key_storage::Plan::default())?;
                    if storage.revocation.is_some()
                        || storage.transfers.iter().any(Option::is_some)
                        || storage.permissions.is_some()
                    {
                        return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                            crate::OperationKeysRejection::UnexpectedReaderPreparationStorage,
                        )));
                    }
                    Ok(candidate)
                })
                .map(|(candidate, access, readers)| {
                    (candidate, access, Acquired::Readers(readers))
                }),
            Self::Native { destination, role } => destination
                .prepare_with(session, progress, authentication, prepare)
                .map(|(candidate, access, signature)| {
                    (
                        candidate,
                        access,
                        Acquired::Native {
                            binding: signature,
                            role: *role,
                        },
                    )
                }),
        }
    }
}
