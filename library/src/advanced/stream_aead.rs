// SPDX-License-Identifier: Apache-2.0
//! ChaCha/Salsa-Poly1305 messages backed by the shared AEAD owner.
use super::{
    AdvancedSession, CipherKind, GcmRejection, MessageInitLayout, MessageKey, MessageRoute,
    OperationTicket, Outputs, Requests,
};
use crate::{Error, Result};

/// Plaintext message with an explicit native nonce variant and AAD.
pub struct StreamAeadEncryptMessage<'a> {
    /// Exact nonce; uniqueness under the key belongs to the caller.
    pub nonce: crate::StreamAeadNonce,
    /// Authenticated, unencrypted context.
    pub aad: &'a [u8],
    /// Ordered plaintext fragments; an empty list is an empty message.
    pub parts: &'a [&'a [u8]],
}
/// Ciphertext message with the separate, complete Poly1305 tag.
pub struct StreamAeadDecryptMessage<'a> {
    /// Exact variant and nonce used for encryption.
    pub nonce: crate::StreamAeadNonce,
    /// Exact authenticated context.
    pub aad: &'a [u8],
    /// Ciphertext fragments only, excluding the tag.
    pub parts: &'a [&'a [u8]],
    /// Exactly sixteen bytes; no truncation or padding is implicit.
    pub tag: &'a [u8; 16],
}
/// Associated output of one completed native message.
pub struct StreamAeadCiphertext<'a> {
    /// Ciphertext only, excluding the tag.
    pub ciphertext: &'a [u8],
    /// Nonce bytes, preserving the selected variant.
    pub nonce: &'a [u8],
    /// Sixteen-byte authentication tag returned by the module.
    pub tag: &'a [u8],
}
/// Entire completed batch; no partial ciphertext batch is published.
pub struct StreamAeadCiphertexts(pub(super) Outputs, pub(super) crate::StreamAeadAlgorithm);
impl StreamAeadCiphertexts {
    /// Refusal at this submission index, without any output from that message.
    /// None means either a successful entry or an index outside this result.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.0
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// Native family used for every message in the batch.
    pub fn algorithm(&self) -> crate::StreamAeadAlgorithm {
        self.1
    }
    /// Number of submitted messages, including individually refused entries.
    pub fn len(&self) -> usize {
        self.0.entries.len()
    }
    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }
    /// Borrow the associated ciphertext, nonce and tag in input order.
    /// Returns None for a refused message; inspect rejection at the same index.
    pub fn get(&self, index: usize) -> Option<StreamAeadCiphertext<'_>> {
        self.0
            .entries
            .get(index)
            .filter(|output| output.disposition.candidate())
            .map(|output| StreamAeadCiphertext {
                ciphertext: output.bytes.as_slice(),
                nonce: output.nonce.as_slice(),
                tag: output.tag.as_slice(),
            })
    }
}
/// Successful plaintexts and individual refusals after parent Final succeeds.
/// Refused entries never expose plaintext.
/// Caller-made copies are outside this owner's erasure guarantees.
pub struct StreamAeadPlaintexts(pub(super) Outputs, pub(super) crate::StreamAeadAlgorithm);
impl StreamAeadPlaintexts {
    /// Refusal at this submission index, without any output from that message.
    /// None means either a successful entry or an index outside this result.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.0
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// Native family used for the complete batch.
    pub fn algorithm(&self) -> crate::StreamAeadAlgorithm {
        self.1
    }
    /// Number of submitted messages, including individually refused entries.
    pub fn len(&self) -> usize {
        self.0.entries.len()
    }
    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }
    /// Borrow authenticated plaintext; nothing is exposed before batch completion.
    /// Returns None for a refused message; inspect rejection at the same index.
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.0
            .entries
            .get(index)
            .filter(|output| output.disposition.candidate())
            .map(|output| output.bytes.as_slice())
    }
}
/// Exact native authentication rejection and process-cleanup observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamAeadRejection {
    /// Native message function that rejected the ciphertext.
    pub function: &'static str,
    /// Original native rejection code.
    pub code: u64,
    /// Exact MessageDecryptFinal cleanup result; not a decryption success.
    pub cleanup_code: u64,
}
impl From<GcmRejection> for StreamAeadRejection {
    fn from(value: GcmRejection) -> Self {
        Self {
            function: value.function,
            code: value.code,
            cleanup_code: value.cleanup_code,
        }
    }
}
impl AdvancedSession {
    /// Encrypt a native ChaCha/Salsa-Poly1305 message sequence. Every nonce must
    /// select the same family; nonce variants may differ between messages.
    /// Init has no parameter as specified by PKCS#11 3.2 §6.61.2. There is no
    /// automatic retry, nonce generation or selection of another mechanism.
    pub fn encrypt_stream_aead_messages(
        &self,
        key: &crate::ManagedObjectRef,
        messages: &[StreamAeadEncryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let first =
            messages
                .first()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::EmptyStreamAeadSequence,
                )))?;
        let kind = CipherKind::from_stream(first.nonce.algorithm());
        self.start_aead_messages(
            MessageKey::Native(key),
            Requests::StreamEncrypt { kind, messages },
            route,
            limits,
            MessageInitLayout::InitWithoutParameters,
        )
    }
    /// Decrypt a complete batch with separate sixteen-byte tags. A refused
    /// message releases no plaintext from any message in this batch.
    pub fn decrypt_stream_aead_messages(
        &self,
        key: &crate::ManagedObjectRef,
        messages: &[StreamAeadDecryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let first =
            messages
                .first()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::EmptyStreamAeadSequence,
                )))?;
        let kind = CipherKind::from_stream(first.nonce.algorithm());
        self.start_aead_messages(
            MessageKey::Native(key),
            Requests::StreamDecrypt { kind, messages },
            route,
            limits,
            MessageInitLayout::InitWithoutParameters,
        )
    }
}
