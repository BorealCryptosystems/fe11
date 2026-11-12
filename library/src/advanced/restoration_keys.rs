// SPDX-License-Identifier: Apache-2.0
//! Explicit destination references and native key-argument convention.
use super::keys::KeyLease;
use super::record;

use crate::{module::SessionEntry, Error, Result, Session};
use fe11_sys::{CKM_AES_CCM, CKM_AES_GCM, CK_INVALID_HANDLE, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE};
/// Native C_SetOperationState key argument; never selected from provider identity.
#[derive(Clone, Copy)]
pub enum StateKeyEncoding {
    /// Pass the admitted destination object's native handle.
    Supplied,
    /// Pass CK_INVALID_HANDLE; the native state must contain the needed key.
    /// The destination reference and its creator lease are still mandatory.
    Embedded,
}
/// Explicitly selected reference in the destination session.
#[derive(Clone, Copy)]
pub enum StateKeyReference<'a> {
    /// Generic message process with its explicit initialization auxiliaries.
    /// Local captures retain their ABI declarations. Imported per-call graphs
    /// require explicit destination ABI assertions before they can reach C;
    /// serialized provenance alone does not establish their native layout.
    NativeMessages {
        /// Primary signature/verification reference in the destination session.
        key: &'a crate::NativeObjectRef,
        /// Initialization auxiliary references, in source first-occurrence order.
        /// Aliases at distinct fields still share one source role index.
        auxiliary: &'a [&'a crate::NativeObjectRef],
        /// Optional destination declaration for the initialization graph.
        /// Required on import for a caller-defined layout. Init is not replayed.
        extension: Option<&'a crate::MechanismExtension>,
        /// Optional per-call declarations in Begin/part order across messages.
        /// An empty slice reuses local captured declarations. Otherwise provide
        /// one slot per retained call graph, including None for null parameters.
        /// On import, every non-null graph requires a matching caller-asserted
        /// declaration. An empty slice is accepted only when all call graphs use
        /// the null-parameter contract; no declaration is inferred from bytes.
        parameters: &'a [Option<&'a crate::MechanismExtension>],
    },
    /// Generic classic signature reference. Imported caller-defined layouts
    /// require a declaration for the destination module; standard typed layouts
    /// and local captures do not require a new unsafe assertion.
    NativeSignature {
        /// Explicit key in the destination session.
        key: &'a crate::NativeObjectRef,
        /// Destination ABI declaration for a caller-defined parameter graph.
        extension: Option<&'a crate::MechanismExtension>,
    },
    /// Typed symmetric cipher or MAC key.
    Symmetric(&'a crate::SymmetricKey),
    /// Generic secret key for the cipher mechanism bound in the record.
    /// No readable class, protection or mechanism-list attributes are required.
    NativeSecret(&'a crate::NativeObjectRef),
    /// Typed private signing reference and its parameter representation.
    Signing(&'a crate::SigningKey),
    /// Typed public verification reference and its parameter representation.
    Verification(&'a crate::VerificationKey),
    /// Admitted key for the exact parameterless recovery mechanism in the record.
    /// The module decides its native recovery usage; no raw handle is accepted.
    Recovery(&'a crate::NativeObjectRef),
}
impl<'a> StateKeyReference<'a> {
    pub(super) fn managed(self) -> &'a crate::NativeObjectRef {
        match self {
            Self::NativeSignature { key, .. } | Self::NativeMessages { key, .. } => key,
            Self::Symmetric(key) => &key.managed,
            Self::NativeSecret(key) | Self::Recovery(key) => key,
            Self::Signing(key) => key.management_reference(),
            Self::Verification(key) => key.management_reference(),
        }
    }
}
/// One operation-key role and its explicit native encoding.
///
/// The caller selects the destination key. Fe11 checks its module/session,
/// lifetime, native role and parameter representation. Observed class/type/ID
/// values do not establish mathematical key correspondence. No source history
/// policy is reconstructed or imposed on the destination; the native module
/// decides whether C_SetOperationState can use the supplied key arguments.
#[derive(Clone, Copy)]
pub struct StateRestoreKey<'a> {
    /// Destination cryptographic reference, never an administrative/raw handle.
    pub reference: StateKeyReference<'a>,
    /// Whether the native handle is supplied or the key is already embedded.
    pub encoding: StateKeyEncoding,
}
/// The two roles defined by C_SetOperationState. Digest-only state uses neither.
#[derive(Clone, Copy, Default)]
pub struct StateRestoreKeys<'a> {
    /// Destination ABI declaration for an imported caller-defined digest or cipher graph.
    /// Local captures retain their declaration; ordinary typed operations use None.
    pub extension: Option<&'a crate::MechanismExtension>,
    /// Encryption/decryption role, if used by the saved plan.
    pub encryption: Option<StateRestoreKey<'a>>,
    /// Signature/verification role, if used by the saved plan.
    pub authentication: Option<StateRestoreKey<'a>>,
}
pub(super) struct BoundKeys {
    pub(super) extension: Option<crate::MechanismExtension>,
    pub(super) signature: Option<SignatureBinding>,
    pub(super) encryption: Option<KeyLease>,
    pub(super) authentication: Option<KeyLease>,
    pub(super) native_encryption: CK_OBJECT_HANDLE,
    pub(super) native_authentication: CK_OBJECT_HANDLE,
}

/// The native authentication role belongs to one signature family. A classic
/// binding and a generic message binding cannot coexist or be silently swapped.
pub(super) enum SignatureBinding {
    Classic(super::signature::binding::Binding),
    Messages(super::native_messages::Binding),
}
impl SignatureBinding {
    fn arm(&mut self) {
        match self {
            Self::Classic(binding) => binding.arm(),
            Self::Messages(binding) => binding.arm(),
        }
    }
    fn check(&self, entry: &SessionEntry) -> Result<()> {
        match self {
            Self::Classic(binding) => binding.check(entry),
            Self::Messages(binding) => binding.check(entry),
        }
    }
    fn duplicate(&self) -> Result<Self> {
        match self {
            Self::Classic(binding) => binding.duplicate().map(Self::Classic),
            Self::Messages(binding) => binding.duplicate().map(Self::Messages),
        }
    }
}
impl BoundKeys {
    pub(super) fn native_messages(&self) -> Option<&super::native_messages::Binding> {
        match &self.signature {
            Some(SignatureBinding::Messages(binding)) => Some(binding),
            _ => None,
        }
    }
    pub(super) fn classic_signature(&self) -> Option<&super::signature::binding::Binding> {
        match &self.signature {
            Some(SignatureBinding::Classic(binding)) => Some(binding),
            _ => None,
        }
    }
    pub(super) fn take_classic_signature(&mut self) -> Option<super::signature::binding::Binding> {
        if !matches!(self.signature, Some(SignatureBinding::Classic(_))) {
            return None;
        }
        match self.signature.take() {
            Some(SignatureBinding::Classic(binding)) => Some(binding),
            _ => unreachable!(),
        }
    }
    pub(super) fn take_native_messages(&mut self) -> Option<super::native_messages::Binding> {
        if !matches!(self.signature, Some(SignatureBinding::Messages(_))) {
            return None;
        }
        match self.signature.take() {
            Some(SignatureBinding::Messages(binding)) => Some(binding),
            _ => unreachable!(),
        }
    }
    pub(super) fn for_native_messages(
        binding: super::native_messages::Binding,
        encoding: StateKeyEncoding,
    ) -> Self {
        let native_authentication = binding.handle(encoding);
        Self {
            extension: None,
            signature: Some(SignatureBinding::Messages(binding)),
            encryption: None,
            authentication: None,
            native_encryption: CK_INVALID_HANDLE,
            native_authentication,
        }
    }

    pub(super) fn signature(
        binding: super::signature::binding::Binding,
        encoding: StateKeyEncoding,
    ) -> Self {
        let native_authentication = binding.handle(encoding);
        Self {
            extension: None,
            signature: Some(SignatureBinding::Classic(binding)),
            encryption: None,
            authentication: None,
            native_encryption: CK_INVALID_HANDLE,
            native_authentication,
        }
    }
    pub(super) fn arm_native_keys(&mut self) {
        if let Some(binding) = &mut self.signature {
            binding.arm();
        }
        for key in [&mut self.encryption, &mut self.authentication]
            .into_iter()
            .flatten()
        {
            key.arm_for_native_call();
        }
    }

    /// Preserve earlier duplicated roles if a later role refuses duplication.
    pub(super) fn duplicate_retained(&self, candidate: &mut Option<Self>) -> Result<Self> {
        if candidate.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::DuplicateKeyCandidateAlreadyOccupied,
            )));
        }
        *candidate = Some(Self {
            extension: self.extension.clone(),
            signature: None,
            encryption: None,
            authentication: None,
            native_encryption: self.native_encryption,
            native_authentication: self.native_authentication,
        });
        let bound = candidate.as_mut().expect("duplicate key candidate");
        bound.signature = self
            .signature
            .as_ref()
            .map(SignatureBinding::duplicate)
            .transpose()?;
        bound.encryption = self
            .encryption
            .as_ref()
            .map(KeyLease::duplicate)
            .transpose()?;
        bound.authentication = self
            .authentication
            .as_ref()
            .map(KeyLease::duplicate)
            .transpose()?;
        Ok(candidate.take().expect("complete duplicate key candidate"))
    }
    pub(super) fn check(&self, entry: &SessionEntry) -> Result<()> {
        if let Some(binding) = &self.signature {
            binding.check(entry)?;
        }
        for key in [&self.encryption, &self.authentication]
            .into_iter()
            .flatten()
        {
            key.check(entry)?;
        }
        Ok(())
    }

    /// Retain both destination readers if either checkpoint or the extension
    /// contract refuses. The caller owns this slot outside session access.
    pub(super) fn from_record_retained(
        session: &Session,
        d: record::Descriptor,
        bindings: &record::KeyBindings<'_>,
        messages: &record::Messages<'_>,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        candidate: &mut Option<Self>,
    ) -> Result<Self> {
        if candidate.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RecordKeyCandidateAlreadyOccupied,
            )));
        }
        fn role(
            session: &Session,
            expected: Option<record::KeyBinding<'_>>,
            key: Option<StateRestoreKey<'_>>,
            mechanism: CK_MECHANISM_TYPE,
            profile: u8,
            size: usize,
            parameters: Option<crate::RsaPssParameters>,
            permits: &mut [Option<crate::registry::ReadPermit>],
            lease_slot: &mut Option<KeyLease>,
        ) -> Result<CK_OBJECT_HANDLE> {
            match (expected, key) {
                (None, None) => Ok(CK_INVALID_HANDLE),
                (Some(expected), Some(key)) => {
                    let lease = KeyLease::for_rejoin_selected_retained(
                        session,
                        key.reference,
                        mechanism,
                        parameters,
                        permits,
                        lease_slot,
                    )?;
                    // The checkpoint may refuse after the reader permit moved.
                    // Keep that lease in the enclosing candidate until access exits.
                    *lease_slot = Some(lease);
                    let lease = lease_slot.as_ref().expect("record destination lease");
                    lease.check_checkpoint(expected, profile, size)?;
                    Ok(match key.encoding {
                        StateKeyEncoding::Supplied => lease.handle,
                        StateKeyEncoding::Embedded => CK_INVALID_HANDLE,
                    })
                }
                _ => Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RecordDestinationKeyRoles,
                ))),
            }
        }
        let parameters = super::messages::pss::record_selection(d, messages)?;
        let dual = super::dual::authentication::record_selection(d, messages)?;
        let mac = dual.and_then(|a| a.mac());
        let mechanism = CK_MECHANISM_TYPE::try_from(d.mechanism).map_err(|_| {
            Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RecordMechanismWidth,
            ))
        })?;
        if d.family.is_cipher() {
            let profile = super::cipher::checkpoint::key_profile(d.profile)?;
            match (profile, keys.encryption.map(|key| key.reference)) {
                (0, None) => {}
                (1, Some(StateKeyReference::NativeSecret(_))) => {}
                (2..=4, Some(StateKeyReference::Symmetric(_))) => {}
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::BlockCipherDestinationReferenceProfile,
                    )))
                }
            }
        }
        *candidate = Some(Self::new(None, None));
        let bound = candidate.as_mut().expect("record key candidate");
        bound.native_encryption = role(
            session,
            bindings.cipher,
            keys.encryption,
            mechanism,
            super::dual::authentication::cipher_profile(d)?,
            0,
            None,
            permits,
            &mut bound.encryption,
        )?;
        bound.native_authentication = role(
            session,
            bindings.authentication,
            keys.authentication,
            mac.map_or(mechanism, |a| a.mechanism()),
            if d.family.is_recover() {
                1
            } else {
                mac.map_or(d.profile, |a| a.profile())
            },
            d.size,
            parameters,
            permits,
            &mut bound.authentication,
        )?;
        bound.extension = if d.family.is_cipher() {
            super::cipher::extension_binding::import_contract(session, d, messages, keys.extension)?
        } else {
            super::digest::extension::import_contract(session, d, messages, keys.extension)?
        };
        Ok(candidate.take().expect("complete record key candidate"))
    }
    pub(super) fn new(
        encryption: Option<(KeyLease, StateKeyEncoding)>,
        authentication: Option<(KeyLease, StateKeyEncoding)>,
    ) -> Self {
        fn handle(key: &Option<(KeyLease, StateKeyEncoding)>) -> CK_OBJECT_HANDLE {
            match key {
                Some((key, StateKeyEncoding::Supplied)) => key.handle,
                _ => CK_INVALID_HANDLE,
            }
        }
        let native_encryption = handle(&encryption);
        let native_authentication = handle(&authentication);
        Self {
            extension: None,
            signature: None,
            encryption: encryption.map(|x| x.0),
            authentication: authentication.map(|x| x.0),
            native_encryption,
            native_authentication,
        }
    }
}
impl<'a> StateRestoreKey<'a> {
    pub(super) fn symmetric(self, kind: CK_MECHANISM_TYPE) -> Result<&'a crate::ManagedObjectRef> {
        let StateKeyReference::Symmetric(key) = self.reference else {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestoreSymmetricReferenceRequired,
            )));
        };
        let algorithm = key.algorithm;
        let compatible = if matches!(kind, CKM_AES_GCM | CKM_AES_CCM)
            || crate::advanced::dual::cipher::non_aead(kind as u64)
        {
            matches!(
                algorithm,
                crate::SymmetricAlgorithm::Aes128
                    | crate::SymmetricAlgorithm::Aes192
                    | crate::SymmetricAlgorithm::Aes256
            )
        } else {
            algorithm.mechanism() == kind && algorithm.mac()
        };
        if !compatible {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestoreKeyMechanismPolicy,
            )));
        }
        Ok(&key.managed)
    }
}


