// SPDX-License-Identifier: Apache-2.0
//! Key identity, consumer activity and restoration bindings shared by families.
//!
//! These leases retain an admitted identity and its original Activity, never an
//! Inner/module owner. A source's observations cannot replace caller-selected
//! expectations; native modules decide cryptographic compatibility.
use super::{record, StateKeyEncoding, StateKeyReference, StateRestoreKey};
use crate::advanced::record::profile;

use crate::{
    managed::ManagedIdentity, module::SessionEntry, registry::ReadPermit, Error, Result, Session,
    SymmetricKey,
};
use fe11_sys::{CKM_SHA256_RSA_PKCS_PSS, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};
use std::sync::{atomic::Ordering, Arc};
mod preparation;
pub(super) mod restoration;
pub(super) use preparation::KeyReaders;

// A restored lease cannot omit its cryptographic parameters or combine RSA
// sizing with a symmetric selection. Destination selections remain owned here.
enum KeyLeaseMaterial {
    Symmetric {
        algorithm: crate::SymmetricAlgorithm,
    },
    Rsa {
        bits: usize,
    },
    NativeCipher {
        mechanism: CK_MECHANISM_TYPE,
    },
    Recovery {
        mechanism: CK_MECHANISM_TYPE,
    },
}
impl KeyLeaseMaterial {
    fn duplicate(&self) -> Self {
        match self {
            Self::Symmetric { algorithm } => Self::Symmetric {
                algorithm: *algorithm,
            },
            Self::Rsa { bits } => Self::Rsa { bits: *bits },
            Self::NativeCipher { mechanism } => Self::NativeCipher {
                mechanism: *mechanism,
            },
            Self::Recovery { mechanism } => Self::Recovery {
                mechanism: *mechanism,
            },
        }
    }
    fn same_parameters(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Symmetric { algorithm: a, .. }, Self::Symmetric { algorithm: b, .. }) => a == b,
            (Self::Rsa { bits: a }, Self::Rsa { bits: b }) => a == b,
            (Self::NativeCipher { mechanism: a }, Self::NativeCipher { mechanism: b }) => a == b,
            (Self::Recovery { mechanism: a }, Self::Recovery { mechanism: b }) => a == b,
            _ => false,
        }
    }
}
mod permission;
pub(super) use permission::Revocation as WriterRevocation;

// Contains no Arc<Inner>; the registry must not own its module recursively.
pub(super) struct KeyLease {
    identity: Arc<crate::managed::NativeIdentity>,
    description: Option<Arc<ManagedIdentity>>,
    pub(super) handle: CK_OBJECT_HANDLE,
    stamp: u64,

    material: KeyLeaseMaterial,
    permission: permission::Permission,
}
impl KeyLease {
    pub(super) fn authentication_stamp(&self) -> u64 {
        self.stamp
    }
    /// Inspect writer declaration and revocation state before taking ownership.
    pub(super) fn check_cipher_binding(
        binding: &crate::advanced::signature::binding::Binding,
    ) -> Result<()> {
        if !binding.contract.mutates_key() {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::CipherWriterDeclarationRequired,
            )));
        }
        match (binding.own_revocation, binding.revocation.as_ref()) {
            (true, None) | (false, Some(_)) => Ok(()),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::CipherWriterRevocationState,
            ))),
        }
    }

    /// Transfer a binding immediately after check_cipher_binding, without any
    /// intervening mutation. No fallible step remains after ownership moves.
    pub(super) fn from_checked_cipher_binding(
        binding: crate::advanced::signature::binding::Binding,
    ) -> Self {
        let revocation = match (binding.own_revocation, binding.revocation) {
            (true, None) => WriterRevocation::Armed,
            (false, Some(targets)) => WriterRevocation::Prepared(targets),
            _ => unreachable!("validated cipher writer revocation"),
        };
        Self {
            handle: binding.key.handle,
            identity: binding.key,
            description: None,
            stamp: binding.authentication,
            material: KeyLeaseMaterial::NativeCipher {
                mechanism: binding.contract.native_mechanism(),
            },
            permission: permission::Permission::Write {
                roles: binding.roles,
                revocation,
            },
        }
    }
    /// Bind an already granted writer. Preparation owns all fallible allocation;
    /// this constructor checks identity and transfers only existing resources.
    pub(super) fn from_native_writer(
        session: &Session,
        key: &crate::NativeObjectRef,
        mechanism: CK_MECHANISM_TYPE,
        roles: crate::advanced::key_roles::Roles,
        revocation: &mut Option<crate::managed::RevocationTargets>,
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        if candidate.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::KeyLeaseCandidateAlreadyOccupied,
            )));
        }
        let identity = &key.identity;
        if !Arc::ptr_eq(&session.inner, &key.inner)
            || session.uid != identity.session
            || session.entry.slot != identity.slot
            || session.snapshot.generation != identity.generation
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::ForeignOrStaleNativeWriterKey,
            )));
        }
        let targets =
            revocation
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::NativeWriterRevocationAbsent,
                )))?;
        *candidate = Some(Self {
            identity: identity.clone(),
            description: None,
            handle: identity.handle,
            stamp: session.snapshot.authentication_stamp(),
            material: KeyLeaseMaterial::NativeCipher { mechanism },
            permission: permission::Permission::Write {
                roles,
                revocation: WriterRevocation::Prepared(targets),
            },
        });
        candidate
            .as_ref()
            .expect("prepared writer lease")
            .check(&session.entry)?;
        Ok(candidate.take().expect("checked writer lease"))
    }
    pub(super) fn native_identity(&self) -> &Arc<crate::managed::NativeIdentity> {
        &self.identity
    }
    pub(super) fn writer_roles(&self) -> Option<&crate::advanced::key_roles::Roles> {
        self.permission.writer_roles()
    }
    pub(super) fn owns_revocation(&self) -> bool {
        self.permission.owns_revocation()
    }
    pub(super) fn retain_refused_binding(&mut self, destination: &Self) {
        if Arc::ptr_eq(&self.identity, &destination.identity) && destination.owns_revocation() {
            self.permission.retain_armed();
        }
    }
    pub(super) fn new(
        session: &Session,
        key: &SymmetricKey,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<Self> {
        Self::from_managed(
            session,
            &key.managed,
            KeyLeaseMaterial::Symmetric {
                algorithm: key.algorithm,
            },
            permits,
        )
    }
    /// Cipher admission keeps this slot before access in its local drop order.
    pub(super) fn new_retained(
        session: &Session,
        key: &SymmetricKey,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        Self::from_native_retained(
            session,
            &key.managed,
            Some(key.managed.identity.clone()),
            KeyLeaseMaterial::Symmetric {
                algorithm: key.algorithm,
            },
            permits,
            candidate,
        )
    }

    pub(super) fn for_native_cipher_retained(
        session: &Session,
        key: &crate::NativeObjectRef,
        mechanism: CK_MECHANISM_TYPE,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        Self::from_native_retained(
            session,
            key,
            None,
            KeyLeaseMaterial::NativeCipher { mechanism },
            permits,
            candidate,
        )
    }

    // Shared by normal PSS operation construction, rejoin and its source case.
    // The lease retains identity and operation parameters, not application
    // requirements about historical protection attributes.
    pub(super) fn for_rsa_messages(
        session: &Session,
        managed: &crate::ManagedObjectRef,
        bits: usize,
        _signing: bool,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<Self> {
        Self::from_managed(session, managed, KeyLeaseMaterial::Rsa { bits }, permits)
    }
    pub(super) fn for_recovery(
        session: &Session,
        managed: &crate::NativeObjectRef,
        mechanism: CK_MECHANISM_TYPE,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<Self> {
        Self::from_native(
            session,
            managed,
            None,
            KeyLeaseMaterial::Recovery { mechanism },
            permits,
        )
    }
    pub(super) fn for_native_cipher(
        session: &Session,
        managed: &crate::NativeObjectRef,
        mechanism: CK_MECHANISM_TYPE,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<Self> {
        // The native module decides key/mechanism compatibility. The lease
        // retains only the identity, activity permit and operation parameters.
        Self::from_native(
            session,
            managed,
            None,
            KeyLeaseMaterial::NativeCipher { mechanism },
            permits,
        )
    }
    fn from_managed(
        session: &Session,
        managed: &crate::ManagedObjectRef,
        material: KeyLeaseMaterial,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<Self> {
        Self::from_native(
            session,
            managed,
            Some(managed.identity.clone()),
            material,
            permits,
        )
    }
    fn from_native(
        session: &Session,
        managed: &crate::NativeObjectRef,
        description: Option<Arc<ManagedIdentity>>,

        material: KeyLeaseMaterial,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<Self> {
        Self::from_native_retained(session, managed, description, material, permits, &mut None)
    }

    /// Keep a transferred read permit in the enclosing candidate if the final
    /// identity/context check refuses. Success takes the same complete lease.
    fn from_native_retained(
        session: &Session,
        managed: &crate::NativeObjectRef,
        description: Option<Arc<ManagedIdentity>>,

        material: KeyLeaseMaterial,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        if candidate.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::KeyLeaseCandidateAlreadyOccupied,
            )));
        }
        let identity = &managed.identity;
        if !Arc::ptr_eq(&session.inner, &managed.inner)
            || session.uid != identity.session
            || session.entry.slot != identity.slot
            || session.snapshot.generation != identity.generation
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::ForeignOrStaleMessageKey,
            )));
        }
        let permit = ReadPermit::take_prepared(permits, identity.activity()?, session.uid)?;
        *candidate = Some(Self {
            identity: identity.clone(),
            description,
            handle: identity.handle,
            stamp: session.snapshot.authentication_stamp(),

            material,
            permission: permission::Permission::Read(permit),
        });
        candidate
            .as_ref()
            .expect("prepared reader lease")
            .check(&session.entry)?;
        Ok(candidate.take().expect("checked reader lease"))
    }

    /// Keep a partially validated destination in the caller's slot on refusal.
    /// The caller places that slot before session access in its drop order.
    pub(super) fn for_rejoin_selected_retained(
        session: &Session,
        reference: StateKeyReference<'_>,
        mechanism: CK_MECHANISM_TYPE,
        parameters: Option<crate::RsaPssParameters>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        match reference {
            StateKeyReference::NativeSignature { .. }
            | StateKeyReference::NativeMessages { .. } => {
                Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::SignatureReferenceRequiresItsSignatureOwner,
                )))
            }
            StateKeyReference::NativeSecret(key) => {
                if parameters.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::NativeSecretCipherHasNoPssParameterContract,
                    )));
                }
                Self::for_native_cipher_retained(session, key, mechanism, permits, candidate)
            }
            StateKeyReference::Recovery(key) => {
                if parameters.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::RecoveryReferenceHasNoPssParameterContract,
                    )));
                }
                Self::from_native_retained(
                    session,
                    key,
                    None,
                    KeyLeaseMaterial::Recovery { mechanism },
                    permits,
                    candidate,
                )
            }
            StateKeyReference::Symmetric(key) => {
                if parameters.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::PssRequiresAnRsaReference,
                    )));
                }
                StateRestoreKey {
                    reference,
                    encoding: StateKeyEncoding::Supplied,
                }
                .symmetric(mechanism)?;
                Self::new_retained(session, key, permits, candidate)
            }
            StateKeyReference::Signing(key) => {
                let parameters =
                    parameters.ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::RejoinSigningParameters,
                    )))?;
                if mechanism != parameters.mechanism(crate::HashExecution::Pkcs11Combined)? {
                    return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::RejoinSigningMechanism,
                    )));
                }
                let bits = key.message_pss_bits(parameters)?;
                let managed = key.management_reference();
                Self::from_native_retained(
                    session,
                    managed,
                    Some(managed.identity.clone()),
                    KeyLeaseMaterial::Rsa { bits },
                    permits,
                    candidate,
                )
            }
            StateKeyReference::Verification(key) => {
                let parameters =
                    parameters.ok_or(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::RejoinVerificationParameters,
                    )))?;
                if mechanism != parameters.mechanism(crate::HashExecution::Pkcs11Combined)? {
                    return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                        crate::OperationKeysRejection::RejoinVerificationMechanism,
                    )));
                }
                let bits = key.message_pss_bits(parameters)?;
                let managed = key.management_reference();
                Self::from_native_retained(
                    session,
                    managed,
                    Some(managed.identity.clone()),
                    KeyLeaseMaterial::Rsa { bits },
                    permits,
                    candidate,
                )
            }
        }
    }

    /// Retain the destination even when comparison with the source refuses.
    pub(super) fn rebind_retained(
        &self,
        session: &Session,
        reference: StateKeyReference<'_>,
        mechanism: CK_MECHANISM_TYPE,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        let parameters = (mechanism == CKM_SHA256_RSA_PKCS_PSS).then_some(pss_profile());
        self.rebind_selected_retained(
            session, reference, mechanism, parameters, permits, candidate,
        )
    }
    pub(super) fn rebind_selected_retained(
        &self,
        session: &Session,
        reference: StateKeyReference<'_>,
        mechanism: CK_MECHANISM_TYPE,
        parameters: Option<crate::RsaPssParameters>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        self.check(&session.entry)?;
        // Construct from the explicitly supplied destination key. Its owned
        // selection must survive restoration; source policy is never copied.
        let destination = Self::for_rejoin_selected_retained(
            session, reference, mechanism, parameters, permits, candidate,
        )?;
        *candidate = Some(destination);
        let destination = candidate.as_ref().expect("restored destination lease");
        let old = &self.identity;
        let new = &destination.identity;
        // Observations of PRIVATE/TOKEN and creator knowledge can legitimately
        // differ across admissions. They are not secret-key identity evidence.
        // Each lease independently checks revocation, creator and auth lifetime.
        // A generic content expectation is never retained or inherited on rebind.
        // These metadata/parameter checks alone do not prove key-material equality.
        if old.slot != new.slot
            || old.generation != new.generation
            || !self.material.same_parameters(&destination.material)
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::RestoreKeyIdentityMismatch,
            )));
        }
        Ok(candidate.take().expect("checked destination lease"))
    }
    pub(super) fn duplicate(&self) -> Result<Self> {
        let permission = self.permission.duplicate()?;
        Ok(Self {
            identity: self.identity.clone(),
            description: self.description.clone(),
            handle: self.handle,
            stamp: self.stamp,

            material: self.material.duplicate(),
            permission,
        })
    }
    pub(super) fn check_checkpoint(
        &self,
        expected: record::KeyBinding<'_>,
        profile: u8,
        size: usize,
    ) -> Result<()> {
        let actual = self.checkpoint_key(expected.role)?;
        // Legacy source-policy bits are descriptive, not a destination policy.
        // The supplied destination key owns the caller's explicit selection.
        if self.description.is_some()
            && ((expected.class.is_some() && actual.class != expected.class)
                || (expected.key_type.is_some() && actual.key_type != expected.key_type))
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::CheckpointDestinationKeyBinding,
            )));
        }
        if matches!(profile, profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED) {
            if !matches!(self.material, KeyLeaseMaterial::Rsa { bits } if (bits / 8 + usize::from(bits % 8 != 0)) == size)
            {
                return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::CheckpointRsaKeySize,
                )));
            }
        } else if self.checkpoint_profile()? != profile {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::CheckpointDestinationKeyProfile,
            )));
        }
        Ok(())
    }
    pub(super) fn checkpoint_profile(&self) -> Result<u8> {
        match &self.material {
            KeyLeaseMaterial::Symmetric { algorithm, .. } => {
                record::Descriptor::symmetric_profile(*algorithm)
            }
            KeyLeaseMaterial::Rsa { .. } => {
                Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                    crate::OperationKeysRejection::CheckpointAlgorithmAbsent,
                )))
            }
            KeyLeaseMaterial::Recovery { .. } | KeyLeaseMaterial::NativeCipher { .. } => {
                Ok(profile::NATIVE_KEY_TYPE)
            }
        }
    }
    pub(super) fn checkpoint_key(&self, role: record::KeyRole) -> Result<record::KeyBinding<'_>> {
        let description = self.description.as_deref();
        Ok(record::KeyBinding {
            role,
            class: description.map(|identity| identity.class.raw() as u64),
            key_type: description.and_then(|identity| identity.key_type.map(|value| value as u64)),
            id: description.and_then(|identity| match identity.id_observation() {
                crate::AttributeValue::Available(value) => Some(value.as_slice()),
                _ => None,
            }),
        })
    }

    pub(super) fn arm_for_native_call(&mut self) {
        self.permission.arm();
    }
    pub(super) fn check(&self, entry: &SessionEntry) -> Result<()> {
        if self.identity.revoked.load(Ordering::Acquire) && !self.permission.owns_revocation() {
            return Err(Error::Rejected(crate::RejectionReason::OperationKeys(
                crate::OperationKeysRejection::RevokedMessageKey,
            )));
        }
        crate::managed::check_creator(self.identity.creator())?;
        // The lease protects this identity and its memory, not a cached login.
        // Authentication changes do not transfer or release its permissions.
        entry.snapshot.check()?;
        self.identity.access().check(&entry.snapshot)?;
        Ok(())
    }
}

pub(super) fn pss_profile() -> crate::RsaPssParameters {
    crate::RsaPssParameters {
        hash: crate::HashAlgorithm::Sha256,
        mgf_hash: crate::HashAlgorithm::Sha256,
        salt_length: 32,
    }
}

impl crate::symmetric::memory::RetainedStorage for KeyLease {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.identity.retain_identity_credit(retained)?;
        self.permission.retain_credits(retained)
    }
}
