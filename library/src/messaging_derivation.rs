// SPDX-License-Identifier: Apache-2.0
//! Typed X3DH/ratchet layouts with explicit implicit-length safety assertions.
use crate::NativeObjectRef;
/// X3DH initiation operands from the peer prekey bundle.
pub struct X3dhInitiator<'a> {
    /// Exact CKD_* KDF identifier.
    pub kdf: u64,
    /// Peer identity key.
    pub peer_identity: &'a NativeObjectRef,
    /// Peer prekey.
    pub peer_prekey: &'a NativeObjectRef,
    /// XEdDSA signature. Its native pointer has no accompanying length field.
    pub prekey_signature: &'a [u8],
    /// Optional peer one-time public key; None is a NULL pointer.
    pub onetime_key: Option<&'a [u8]>,
    /// Local identity key.
    pub own_identity: &'a NativeObjectRef,
    /// Local ephemeral key.
    pub own_ephemeral: &'a NativeObjectRef,
}
/// X3DH response operands. The ABI omits lengths for all byte pointers.
pub struct X3dhResponder<'a> {
    /// Exact CKD_* KDF identifier.
    pub kdf: u64,
    /// Peer identity identifier, in the module's expected representation.
    pub identity_id: &'a [u8],
    /// Peer prekey identifier.
    pub prekey_id: &'a [u8],
    /// Optional one-time identifier; absence remains NULL.
    pub onetime_id: Option<&'a [u8]>,
    /// Initiator identity key.
    pub initiator_identity: &'a NativeObjectRef,
    /// Initiator ephemeral key bytes.
    pub initiator_ephemeral: &'a [u8],
}
/// Double Ratchet common scalars and shared secret; sk has no ABI length field.
pub struct RatchetParameters<'a> {
    /// Exact shared-secret bytes, without local KDF or implicit export.
    pub shared_secret: &'a [u8],
    /// Native encrypted-header flag.
    pub encrypted_header: bool,
    /// Exact native eCurve value, without local strength policy.
    pub curve: u64,
    /// Exact CKM_* AEAD mechanism.
    pub aead: u64,
    /// Exact CKD_* KDF identifier.
    pub kdf: u64,
}
pub(crate) enum MessagingRequest<'a> {
    X3dhInitiate(X3dhInitiator<'a>),
    X3dhRespond(X3dhResponder<'a>),
    RatchetInitialize {
        parameters: RatchetParameters<'a>,
        peer_prekey: &'a NativeObjectRef,
        peer_identity: &'a NativeObjectRef,
        own_identity: &'a NativeObjectRef,
    },
    RatchetRespond {
        parameters: RatchetParameters<'a>,
        own_prekey: &'a NativeObjectRef,
        initiator_identity: &'a NativeObjectRef,
        own_identity: &'a NativeObjectRef,
    },
}
/// A typed native derivation whose implicit byte extents were asserted by the
/// integrator. The PKCS#11 structures define the layout but do not carry byte
/// lengths. Fe11 copies the supplied buffers; it cannot infer missing lengths
/// from a module name, key label or guessed protocol profile.
pub struct MessagingKeyDerivation<'a>(pub(crate) MessagingRequest<'a>);
impl<'a> MessagingKeyDerivation<'a> {
    /// Construct CK_X3DH_INITIATE_PARAMS without adding a protocol profile.
    ///
    /// # Safety
    /// For the module and keys used at dispatch, each supplied byte slice must
    /// have the representation and full extent the module reads through that
    /// pointer. Optional NULL pointers must be supported in the selected case.
    /// No byte pointer may be interpreted as a nested pointer or external object.
    pub unsafe fn x3dh_initiate(request: X3dhInitiator<'a>) -> Self {
        Self(MessagingRequest::X3dhInitiate(request))
    }
    /// Construct CK_X3DH_RESPOND_PARAMS.
    ///
    /// # Safety
    /// Every identifier and ephemeral-key buffer must satisfy the module's
    /// implicit extent/representation for the selected keys, including any
    /// terminator it reads. Optional NULL must be valid. Buffers contain bytes,
    /// not nested native pointers; Fe11 cannot recover omitted ABI lengths.
    pub unsafe fn x3dh_respond(request: X3dhResponder<'a>) -> Self {
        Self(MessagingRequest::X3dhRespond(request))
    }
    /// Construct CK_X2RATCHET_INITIALIZE_PARAMS.
    ///
    /// # Safety
    /// shared_secret must contain the entire byte extent read by the selected
    /// module for this curve/KDF and these keys. It must not encode native pointers.
    pub unsafe fn ratchet_initialize(
        parameters: RatchetParameters<'a>,
        peer_prekey: &'a NativeObjectRef,
        peer_identity: &'a NativeObjectRef,
        own_identity: &'a NativeObjectRef,
    ) -> Self {
        Self(MessagingRequest::RatchetInitialize {
            parameters,
            peer_prekey,
            peer_identity,
            own_identity,
        })
    }
    /// Construct CK_X2RATCHET_RESPOND_PARAMS.
    ///
    /// # Safety
    /// shared_secret must contain the entire byte extent read by the selected
    /// module for this curve/KDF and these keys. It must not encode native pointers.
    pub unsafe fn ratchet_respond(
        parameters: RatchetParameters<'a>,
        own_prekey: &'a NativeObjectRef,
        initiator_identity: &'a NativeObjectRef,
        own_identity: &'a NativeObjectRef,
    ) -> Self {
        Self(MessagingRequest::RatchetRespond {
            parameters,
            own_prekey,
            initiator_identity,
            own_identity,
        })
    }
    pub(crate) fn native(&self) -> fe11_sys::CK_MECHANISM_TYPE {
        use fe11_sys::*;
        match self.0 {
            MessagingRequest::X3dhInitiate(_) => CKM_X3DH_INITIALIZE,
            MessagingRequest::X3dhRespond(_) => CKM_X3DH_RESPOND,
            MessagingRequest::RatchetInitialize { .. } => CKM_X2RATCHET_INITIALIZE,
            MessagingRequest::RatchetRespond { .. } => CKM_X2RATCHET_RESPOND,
        }
    }
    pub(crate) fn keys(&self) -> [Option<&'a NativeObjectRef>; 4] {
        match &self.0 {
            MessagingRequest::X3dhInitiate(v) => [
                Some(v.peer_identity),
                Some(v.peer_prekey),
                Some(v.own_identity),
                Some(v.own_ephemeral),
            ],
            MessagingRequest::X3dhRespond(v) => [Some(v.initiator_identity), None, None, None],
            MessagingRequest::RatchetInitialize {
                peer_prekey,
                peer_identity,
                own_identity,
                ..
            } => [
                Some(*peer_prekey),
                Some(*peer_identity),
                Some(*own_identity),
                None,
            ],
            MessagingRequest::RatchetRespond {
                own_prekey,
                initiator_identity,
                own_identity,
                ..
            } => [
                Some(*own_prekey),
                Some(*initiator_identity),
                Some(*own_identity),
                None,
            ],
        }
    }
}
