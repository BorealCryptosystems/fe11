// SPDX-License-Identifier: Apache-2.0
//! Four published messaging derivation layouts; all implicit-length buffers owned.
use super::*;
use crate::messaging_derivation::{MessagingKeyDerivation, MessagingRequest};
#[derive(Clone, Copy)]
enum Layout {
    Initiate,
    Respond,
    RatchetInitialize,
    RatchetRespond,
}
enum Raw {
    Initiate(CK_X3DH_INITIATE_PARAMS),
    Respond(CK_X3DH_RESPOND_PARAMS),
    RatchetInitialize(CK_X2RATCHET_INITIALIZE_PARAMS),
    RatchetRespond(CK_X2RATCHET_RESPOND_PARAMS),
}
struct Scalars {
    kdf: CK_ULONG,
    curve: CK_ULONG,
    aead: CK_MECHANISM_TYPE,
    encrypted: CK_BBOOL,
}
pub(super) struct Messaging {
    raw: Raw,
    scalars: Scalars,
    keys: [CK_OBJECT_HANDLE; 4],
    bytes: [Option<InputBytes>; 4],
}
fn pieces<'a>(input: &MessagingKeyDerivation<'a>) -> [Option<&'a [u8]>; 4] {
    match &input.0 {
        MessagingRequest::X3dhInitiate(v) => [Some(v.prekey_signature), v.onetime_key, None, None],
        MessagingRequest::X3dhRespond(v) => [
            Some(v.identity_id),
            Some(v.prekey_id),
            v.onetime_id,
            Some(v.initiator_ephemeral),
        ],
        MessagingRequest::RatchetInitialize { parameters, .. }
        | MessagingRequest::RatchetRespond { parameters, .. } => {
            [Some(parameters.shared_secret), None, None, None]
        }
    }
}
fn fields(input: &MessagingKeyDerivation<'_>) -> Result<(Layout, Scalars)> {
    let (layout, kdf, curve, aead, encrypted) = match &input.0 {
        MessagingRequest::X3dhInitiate(v) => (Layout::Initiate, v.kdf, 0, 0, false),
        MessagingRequest::X3dhRespond(v) => (Layout::Respond, v.kdf, 0, 0, false),
        MessagingRequest::RatchetInitialize { parameters: v, .. } => (
            Layout::RatchetInitialize,
            v.kdf,
            v.curve,
            v.aead,
            v.encrypted_header,
        ),
        MessagingRequest::RatchetRespond { parameters: v, .. } => (
            Layout::RatchetRespond,
            v.kdf,
            v.curve,
            v.aead,
            v.encrypted_header,
        ),
    };
    Ok((
        layout,
        Scalars {
            kdf: native_ulong(kdf)?,
            curve: native_ulong(curve)?,
            aead: native_ulong(aead)?,
            encrypted: CK_BBOOL::from(encrypted),
        },
    ))
}
pub(super) struct MessagingStorage<'a> {
    layout: Layout,
    scalars: Scalars,
    keys: [CK_OBJECT_HANDLE; 4],
    bytes: [Option<(&'a [u8], InputBytesStorage)>; 4],
}
impl<'a> MessagingStorage<'a> {
    pub(super) fn allocate(input: &MessagingKeyDerivation<'a>) -> Result<Self> {
        Messaging::payload_bytes(input)?;
        let (layout, scalars) = fields(input)?;
        let keys = input
            .keys()
            .map(|key| key.map_or(CK_INVALID_HANDLE, |key| key.identity.handle));
        let mut bytes = std::array::from_fn(|_| None);
        for (slot, piece) in bytes.iter_mut().zip(pieces(input)) {
            *slot = piece
                .map(|input| Ok::<_, Error>((input, InputBytesStorage::allocate(input.len())?)))
                .transpose()?;
        }
        Ok(Self {
            layout,
            scalars,
            keys,
            bytes,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.bytes
            .iter()
            .flatten()
            .try_fold(0usize, |n, (_, storage)| {
                n.checked_add(storage.allocated_bytes()?)
                    .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::MessagingParameterAccounting,
                    )))
            })
    }
    pub(super) fn bind(self, credit: &mut Credit) -> Result<Messaging> {
        let mut bytes = std::array::from_fn(|_| None);
        for (target, source) in bytes.iter_mut().zip(self.bytes) {
            *target = source
                .map(|(input, storage)| storage.bind(input, credit))
                .transpose()?;
        }
        Messaging::from_owned_parts(self.layout, self.scalars, self.keys, bytes)
    }
}
impl Messaging {
    pub(super) fn payload_bytes(input: &MessagingKeyDerivation<'_>) -> Result<usize> {
        fields(input)?;
        pieces(input)
            .into_iter()
            .flatten()
            .try_fold(0usize, |sum, bytes| {
                bounds::ck_length(bytes.len())?;
                bytes
                    .len()
                    .checked_mul(2)
                    .and_then(|n| sum.checked_add(n))
                    .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::MessagingParameterAccounting,
                    )))
            })
    }

    fn from_owned_parts(
        layout: Layout,
        scalars: Scalars,
        keys: [CK_OBJECT_HANDLE; 4],
        bytes: [Option<InputBytes>; 4],
    ) -> Result<Self> {
        // SAFETY: only integers and nullable pointers. projection fills each
        // input of the selected C layout before any native dispatch.
        let raw = unsafe {
            match layout {
                Layout::Initiate => Raw::Initiate(std::mem::zeroed()),
                Layout::Respond => Raw::Respond(std::mem::zeroed()),
                Layout::RatchetInitialize => Raw::RatchetInitialize(std::mem::zeroed()),
                Layout::RatchetRespond => Raw::RatchetRespond(std::mem::zeroed()),
            }
        };
        Ok(Self {
            raw,
            scalars,
            keys,
            bytes,
        })
    }
    pub(super) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        let pointers = self.bytes.each_mut().map(optional_pointer);
        let k = &self.keys;
        let s = &self.scalars;
        match &mut self.raw {
            Raw::Initiate(raw) => {
                raw.kdf = s.kdf;
                raw.pPeer_identity = k[0];
                raw.pPeer_prekey = k[1];
                raw.pPrekey_signature = pointers[0];
                raw.pOnetime_key = pointers[1];
                raw.pOwn_identity = k[2];
                raw.pOwn_ephemeral = k[3];
                (
                    (raw as *mut CK_X3DH_INITIATE_PARAMS).cast(),
                    size_of::<CK_X3DH_INITIATE_PARAMS>() as CK_ULONG,
                )
            }
            Raw::Respond(raw) => {
                raw.kdf = s.kdf;
                raw.pIdentity_id = pointers[0];
                raw.pPrekey_id = pointers[1];
                raw.pOnetime_id = pointers[2];
                raw.pInitiator_identity = k[0];
                raw.pInitiator_ephemeral = pointers[3];
                (
                    (raw as *mut CK_X3DH_RESPOND_PARAMS).cast(),
                    size_of::<CK_X3DH_RESPOND_PARAMS>() as CK_ULONG,
                )
            }
            Raw::RatchetInitialize(raw) => {
                raw.sk = pointers[0];
                raw.peer_public_prekey = k[0];
                raw.peer_public_identity = k[1];
                raw.own_public_identity = k[2];
                raw.bEncryptedHeader = s.encrypted;
                raw.eCurve = s.curve;
                raw.aeadMechanism = s.aead;
                raw.kdfMechanism = s.kdf;
                (
                    (raw as *mut CK_X2RATCHET_INITIALIZE_PARAMS).cast(),
                    size_of::<CK_X2RATCHET_INITIALIZE_PARAMS>() as CK_ULONG,
                )
            }
            Raw::RatchetRespond(raw) => {
                raw.sk = pointers[0];
                raw.own_prekey = k[0];
                raw.initiator_identity = k[1];
                raw.own_public_identity = k[2];
                raw.bEncryptedHeader = s.encrypted;
                raw.eCurve = s.curve;
                raw.aeadMechanism = s.aead;
                raw.kdfMechanism = s.kdf;
                (
                    (raw as *mut CK_X2RATCHET_RESPOND_PARAMS).cast(),
                    size_of::<CK_X2RATCHET_RESPOND_PARAMS>() as CK_ULONG,
                )
            }
        }
    }
    pub(super) fn unchanged(&self) -> bool {
        let pointers = self.bytes.each_ref().map(optional_expected_pointer);
        let k = &self.keys;
        let s = &self.scalars;
        let fields = match &self.raw {
            Raw::Initiate(raw) => {
                raw.kdf == s.kdf
                    && raw.pPeer_identity == k[0]
                    && raw.pPeer_prekey == k[1]
                    && raw.pPrekey_signature == pointers[0]
                    && raw.pOnetime_key == pointers[1]
                    && raw.pOwn_identity == k[2]
                    && raw.pOwn_ephemeral == k[3]
            }
            Raw::Respond(raw) => {
                raw.kdf == s.kdf
                    && raw.pIdentity_id == pointers[0]
                    && raw.pPrekey_id == pointers[1]
                    && raw.pOnetime_id == pointers[2]
                    && raw.pInitiator_identity == k[0]
                    && raw.pInitiator_ephemeral == pointers[3]
            }
            Raw::RatchetInitialize(raw) => {
                raw.sk == pointers[0]
                    && raw.peer_public_prekey == k[0]
                    && raw.peer_public_identity == k[1]
                    && raw.own_public_identity == k[2]
                    && raw.bEncryptedHeader == s.encrypted
                    && raw.eCurve == s.curve
                    && raw.aeadMechanism == s.aead
                    && raw.kdfMechanism == s.kdf
            }
            Raw::RatchetRespond(raw) => {
                raw.sk == pointers[0]
                    && raw.own_prekey == k[0]
                    && raw.initiator_identity == k[1]
                    && raw.own_public_identity == k[2]
                    && raw.bEncryptedHeader == s.encrypted
                    && raw.eCurve == s.curve
                    && raw.aeadMechanism == s.aead
                    && raw.kdfMechanism == s.kdf
            }
        };
        fields && self.bytes.iter().all(optional_unchanged)
    }
}
