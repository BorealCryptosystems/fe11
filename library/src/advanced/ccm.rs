// SPDX-License-Identifier: Apache-2.0
//! CCM public message contracts backed by the shared owned AEAD sequence.
use super::{
    complete_single_message, AdvancedSession, CipherKind, GcmRejection, MessageInitLayout,
    MessageKey, MessageRoute, OperationTicket, Outputs, Request, Requests, Selection, SymmetricKey,
};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, Result, Session};

/// One CCM plaintext message with explicit nonce selection and MAC length.
pub struct CcmEncryptMessage<'a> {
    /// Original nonce bytes and native generation fields.
    pub nonce: crate::CcmNonce,
    /// Authenticated, unencrypted data.
    pub aad: &'a [u8],
    /// Ordered plaintext fragments; an empty list means an empty message.
    pub parts: &'a [&'a [u8]],
    /// MAC length in bytes: 4, 6, 8, 10, 12, 14 or 16.
    pub mac_length: u64,
}
/// One CCM ciphertext message with its separate MAC.
pub struct CcmDecryptMessage<'a> {
    /// Exact encryption nonce. Generator and fixed-bit fields are ignored by
    /// native MessageDecrypt and passed unchanged, subject to ABI conversion.
    pub nonce: crate::CcmNonce,
    /// Exact authenticated context.
    pub aad: &'a [u8],
    /// Ciphertext fragments only, excluding the separate MAC.
    pub parts: &'a [&'a [u8]],
    /// Expected MAC bytes; their length selects ulMACLen.
    pub mac: &'a [u8],
}
/// Borrowed associated ciphertext, MAC and actual nonce of one completed message.
pub struct CcmMessageCiphertext<'a> {
    /// Ciphertext only, excluding the MAC.
    pub ciphertext: &'a [u8],
    /// Nonce returned by the completed encryption request.
    pub nonce: &'a [u8],
    /// Complete separate authentication code.
    pub mac: &'a [u8],
}
/// A complete CCM batch; no result is published before the process Final.
pub struct CcmCiphertexts(pub(super) Outputs);
impl CcmCiphertexts {
    /// Refusal at this submission index, without any output from that message.
    /// None means either a successful entry or an index outside this result.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.0
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// Number of submitted messages, including individually refused entries.
    pub fn len(&self) -> usize {
        self.0.entries.len()
    }
    /// Whether the completed batch contains no entries.
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }
    /// Local representation supplied to native Init, not a capability claim.
    pub fn message_init(&self) -> crate::CallerSelectedInitLayout {
        crate::CallerSelectedInitLayout::ccm(self.0.init)
    }
    /// Borrow one associated result in input order.
    /// Returns None for a refused message; inspect rejection at the same index.
    pub fn get(&self, index: usize) -> Option<CcmMessageCiphertext<'_>> {
        self.0
            .entries
            .get(index)
            .filter(|o| o.disposition.candidate())
            .map(|o| CcmMessageCiphertext {
                ciphertext: o.bytes.as_slice(),
                nonce: o.nonce.as_slice(),
                mac: o.tag.as_slice(),
            })
    }
}
/// Successful plaintexts and individual refusals after parent Final succeeds.
/// Refused entries have no plaintext; successful entries retain their selected MAC.
/// Consumer-made plaintext copies cannot be erased by this owner.
pub struct CcmPlaintexts(pub(super) Outputs);
impl CcmPlaintexts {
    /// Refusal at this submission index, without any output from that message.
    /// None means either a successful entry or an index outside this result.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.0
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// Number of submitted messages, including individually refused entries.
    pub fn len(&self) -> usize {
        self.0.entries.len()
    }
    /// Whether this batch contains no entries.
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }
    /// Local representation supplied to native Init.
    pub fn message_init(&self) -> crate::CallerSelectedInitLayout {
        crate::CallerSelectedInitLayout::ccm(self.0.init)
    }
    /// Borrow completed plaintext; caller-made copies are outside this owner.
    /// Returns None for a refused message; inspect rejection at the same index.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.0
            .entries
            .get(index)
            .filter(|o| o.disposition.candidate())
            .map(|o| o.bytes.as_slice())
    }
    /// Number of MAC bytes selected for this completed message.
    pub fn mac_length(&self, index: usize) -> Option<usize> {
        self.0.entries.get(index).map(|o| o.tag.capacity())
    }
}
/// Exact native CCM authentication rejection and process cleanup observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CcmRejection {
    /// Native Message function that rejected the ciphertext.
    pub function: &'static str,
    /// Original CK_RV, without conversion into a fabricated success.
    pub code: u64,
    /// Exact MessageDecryptFinal result, including already-inactive cleanup.
    pub cleanup_code: u64,
}
impl From<GcmRejection> for CcmRejection {
    fn from(value: GcmRejection) -> Self {
        Self {
            function: value.function,
            code: value.code,
            cleanup_code: value.cleanup_code,
        }
    }
}
impl AdvancedSession {
    /// Encrypt one native CCM sequence with explicit route and Init layout.
    /// Owned Init permits per-message data lengths; fixed scalar changes are
    /// rejected before installing the sequence or consuming a nonce.
    pub fn encrypt_ccm_messages(
        &self,
        key: &SymmetricKey,
        messages: &[CcmEncryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
        init: MessageInitLayout,
    ) -> Result<OperationTicket> {
        self.start_aead_messages(
            MessageKey::Aes(key),
            Requests::CcmEncrypt(messages),
            route,
            limits,
            init,
        )
    }
    /// Decrypt one native CCM sequence. A refused message releases no plaintext
    /// from any message in the batch; there is no native business replay.
    pub fn decrypt_ccm_messages(
        &self,
        key: &SymmetricKey,
        messages: &[CcmDecryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
        init: MessageInitLayout,
    ) -> Result<OperationTicket> {
        self.start_aead_messages(
            MessageKey::Aes(key),
            Requests::CcmDecrypt(messages),
            route,
            limits,
            init,
        )
    }
}

impl Session {
    pub(crate) fn ccm_message_buffers(
        &self,
        key: &SymmetricKey,
        parameters: &crate::CcmParameters<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
        route: MessageRoute,
        init: MessageInitLayout,
        mac: Option<&[u8]>,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<(Buffer, Buffer, Credit)> {
        let metadata = std::mem::size_of::<crate::CcmNonce>()
            .checked_add(parameters.nonce.bytes.len())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::CcmRetainedSelectionAccounting,
            )))?;
        complete_single_message(
            self,
            MessageKey::Aes(key),
            Request {
                nonce: Selection::Ccm {
                    nonce: parameters.nonce.clone(),
                    mac_length: parameters.mac_length,
                },
                aad: parameters.aad,
                parts,
                tag: mac,
            },
            CipherKind::Ccm,
            mac.is_some(),
            route,
            limits,
            init,
            metadata,
            message_diagnostics,
        )
    }
}
