// SPDX-License-Identifier: Apache-2.0
//! Cross-section coherence, before construction or any native restoration.
use super::options::OptionsTag;

use super::{
    Context, Function, KeyBindings, Kind, Limits, Message, MessageState, Messages, NonceOrigin,
    Reader, ValidationRecord, Writer,
};
use crate::advanced::record::profile;
use crate::advanced::record::Family;
use crate::advanced::MessageRoute;
use crate::symmetric::stream::StreamCounter;
use crate::symmetric::structured::CipherOptions;
use crate::{bounds, Error, Result};
use fe11_sys::{
    CKF_DECRYPT, CKF_DIGEST, CKF_ENCRYPT, CKF_SIGN, CKF_VERIFY, CKG_NO_GENERATE, CKK_AES,
    CKK_GENERIC_SECRET, CKK_RSA, CKK_SHA256_HMAC, CKK_SHA384_HMAC, CKK_SHA512_HMAC, CKM_AES_CCM,
    CKM_AES_CTR, CKM_AES_ECB, CKM_AES_GCM, CKM_SHA256_HMAC, CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_HMAC, CKM_SHA512_HMAC, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, CK_ULONG,
};
/// Local validation phases, distinct from both function identifiers and wire tags.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PhaseKind {
    SingleOrBegin,
    Update,
    Final,
    CipherInit,
    CipherFinal,
    Residual,
    AuthenticationFinal,
    Initial,
}

/// Structurally decoded archive fields, before cross-section validation.
/// `profile` is still an encoded, family-dependent byte here. Family adapters
/// decode it into DigestSelection, cipher/recovery profiles or authentication
/// selections before constructing an operation. Keeping that conversion at
/// its validation frontier preserves family-first error precedence for records
/// with multiple defects; a Descriptor alone never authorizes native use.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Descriptor {
    pub input: crate::advanced::input::InputState,
    pub family: Family,
    pub profile: u8,
    pub phase: Function,
    pub mechanism: u64,
    pub size: usize,
    pub active_flags: u64,
    pub validation_requested: bool,
    pub carried_messages: usize,
    pub cipher_options: Option<CipherOptions>,
    pub digest_bits: Option<u64>,
}

/// Borrowed internal record; no authentication, raw export or native dispatch API.
pub(in crate::advanced) struct SavedRecord<'a> {
    pub context: Context,
    pub descriptor: Descriptor,
    pub keys: KeyBindings<'a>,
    pub messages: Messages<'a>,
    pub validation: Option<ValidationRecord<'a>>,
    pub native: &'a [u8],
}
impl<'a> SavedRecord<'a> {
    pub(in crate::advanced) fn read(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        Self::read_with(bytes, limits, None)
    }
    pub(in crate::advanced) fn read_with(
        bytes: &'a [u8],
        limits: Limits,
        observer: super::GraphObserver<'a>,
    ) -> Result<Self> {
        let (kind, mut r) = super::decode_with(bytes, limits, observer)?;
        if kind != Kind::Saved {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::SavedRecordKind,
            )));
        }
        let context = Context::read(&mut r)?;
        let descriptor = Descriptor::read(&mut r)?;
        let keys = KeyBindings::read(&mut r)?;
        let messages = Messages::read(&mut r, limits)?;
        let validation = ValidationRecord::read(&mut r, limits)?;
        let native = r.bytes(limits.bytes)?;
        r.finish()?;
        descriptor.validate(&keys, &messages, validation.as_ref(), limits)?;
        Ok(Self {
            context,
            descriptor,
            keys,
            messages,
            validation,
            native,
        })
    }
}

mod descriptor;
mod encoding;
mod keys;
mod validation;
