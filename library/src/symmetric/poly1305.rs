// SPDX-License-Identifier: Apache-2.0
//! Exact native stream-AEAD nonce tuples; no software cipher or counter policy.
use crate::{Error, Result};
use fe11_sys::*;

/// Native Poly1305 AEAD family, independent of the selected nonce variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamAeadAlgorithm {
    /// CKM_CHACHA20_POLY1305.
    ChaCha20,
    /// CKM_SALSA20_POLY1305.
    Salsa20,
}
impl StreamAeadAlgorithm {
    /// Exact native identifier; no module capability is inferred.
    pub fn mechanism_number(self) -> u64 {
        match self {
            Self::ChaCha20 => CKM_CHACHA20_POLY1305 as u64,
            Self::Salsa20 => CKM_SALSA20_POLY1305 as u64,
        }
    }
}

/// Caller-selected ChaCha20/Salsa20-Poly1305 variant and nonce.
///
/// Never reuse a nonce with the same key. Fe11 preserves these bytes and does
/// not claim to establish their uniqueness across calls, sessions or processes.
/// PKCS#11 3.2 §6.61 expresses the native nonce length in bits, not bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamAeadNonce {
    /// Original ChaCha20-Poly1305, 64-bit nonce.
    ChaCha20([u8; 8]),
    /// IETF ChaCha20-Poly1305, 96-bit nonce.
    ChaCha20Ietf([u8; 12]),
    /// XChaCha20-Poly1305, 192-bit nonce.
    XChaCha20([u8; 24]),
    /// Original Salsa20-Poly1305, 64-bit nonce.
    Salsa20([u8; 8]),
    /// XSalsa20-Poly1305, 192-bit nonce.
    XSalsa20([u8; 24]),
}
impl StreamAeadNonce {
    /// Borrow the exact nonce bytes supplied by the caller.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::ChaCha20(bytes) | Self::Salsa20(bytes) => bytes,
            Self::ChaCha20Ietf(bytes) => bytes,
            Self::XChaCha20(bytes) | Self::XSalsa20(bytes) => bytes,
        }
    }
    /// Native family selected by this tuple; not evidence of module support.
    pub fn algorithm(self) -> StreamAeadAlgorithm {
        if self.is_chacha() {
            StreamAeadAlgorithm::ChaCha20
        } else {
            StreamAeadAlgorithm::Salsa20
        }
    }
    /// Exact native mechanism, without a capability claim.
    pub fn mechanism_number(self) -> u64 {
        if self.is_chacha() {
            CKM_CHACHA20_POLY1305 as u64
        } else {
            CKM_SALSA20_POLY1305 as u64
        }
    }
    pub(crate) fn is_chacha(self) -> bool {
        matches!(
            self,
            Self::ChaCha20(_) | Self::ChaCha20Ietf(_) | Self::XChaCha20(_)
        )
    }
    pub(crate) fn native_bits(self) -> CK_ULONG {
        match self {
            Self::ChaCha20(_) | Self::Salsa20(_) => 64,
            Self::ChaCha20Ietf(_) => 96,
            Self::XChaCha20(_) | Self::XSalsa20(_) => 192,
        }
    }
    pub(crate) fn from_record(mechanism: u64, bytes: &[u8]) -> Result<Self> {
        match (mechanism, bytes.len()) {
            (kind, 8) if kind == CKM_CHACHA20_POLY1305 as u64 => {
                Ok(Self::ChaCha20(bytes.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::ChachaNonceWidth,
                    ))
                })?))
            }
            (kind, 12) if kind == CKM_CHACHA20_POLY1305 as u64 => {
                Ok(Self::ChaCha20Ietf(bytes.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::ChachaNonceWidth,
                    ))
                })?))
            }
            (kind, 24) if kind == CKM_CHACHA20_POLY1305 as u64 => {
                Ok(Self::XChaCha20(bytes.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::ChachaNonceWidth,
                    ))
                })?))
            }
            (kind, 8) if kind == CKM_SALSA20_POLY1305 as u64 => {
                Ok(Self::Salsa20(bytes.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::SalsaNonceWidth,
                    ))
                })?))
            }
            (kind, 24) if kind == CKM_SALSA20_POLY1305 as u64 => {
                Ok(Self::XSalsa20(bytes.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::SalsaNonceWidth,
                    ))
                })?))
            }
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::StreamAeadMechanismNonceTuple,
                ),
            )),
        }
    }
}
pub(crate) fn is_stream_aead(mechanism: u64) -> bool {
    mechanism == CKM_CHACHA20_POLY1305 as u64 || mechanism == CKM_SALSA20_POLY1305 as u64
}

/// Parameters for classic Encrypt/Decrypt, distinct from Message descriptors.
/// Nonce lengths are encoded in bits; AAD length is encoded in bytes.
pub struct StreamAeadParameters<'a> {
    /// Exact variant and nonce; never reuse under the same key.
    pub nonce: StreamAeadNonce,
    /// Authenticated, unencrypted context.
    pub aad: &'a [u8],
}
/// Completed classic ciphertext with its full sixteen-byte tag appended.
/// The library-owned buffers remain budgeted and are erased when dropped.
pub struct StreamAeadEncrypted {
    pub(super) bytes: super::Buffer,
    pub(super) nonce: StreamAeadNonce,
    pub(super) _parameters: super::memory::Credit,
}
impl StreamAeadEncrypted {
    /// Ciphertext followed by the complete native Poly1305 tag.
    /// Copies made by the caller are outside this owner's erasure guarantees.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Exact variant and nonce retained from the request.
    pub fn nonce(&self) -> StreamAeadNonce {
        self.nonce
    }
    pub(super) fn into_plaintext(self) -> super::AeadPlaintext {
        super::AeadPlaintext {
            classic: None,
            bytes: self.bytes,
            tag_bits: 128,
            message_init: None,
        }
    }
}
impl crate::Session {
    /// Encrypt with classic C_Encrypt or Update/Final, as selected by `route`.
    /// Fragments are concatenated for Single and preserved for Multipart.
    /// The native module decides key compatibility. There is no retry, nonce
    /// generation, alternative mechanism or byte-length compatibility encoding.
    pub fn encrypt_stream_aead(
        &self,
        key: &crate::ManagedObjectRef,
        parameters: StreamAeadParameters<'_>,
        parts: &[&[u8]],
        route: crate::MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<StreamAeadEncrypted> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.stream_aead(
            key,
            parameters,
            parts,
            route,
            limits,
            false,
            &mut retirement,
            &mut message_diagnostics,
        )
    }
    /// Decrypt ciphertext with its complete sixteen-byte tag appended.
    /// Fragments form one message. Intermediate native output remains private
    /// until C_Decrypt or C_DecryptFinal succeeds; rejection returns no plaintext.
    pub fn decrypt_stream_aead(
        &self,
        key: &crate::ManagedObjectRef,
        parameters: StreamAeadParameters<'_>,
        parts: &[&[u8]],
        route: crate::MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<super::AeadPlaintext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.stream_aead(
            key,
            parameters,
            parts,
            route,
            limits,
            true,
            &mut retirement,
            &mut message_diagnostics,
        )
        .map(StreamAeadEncrypted::into_plaintext)
    }
}
