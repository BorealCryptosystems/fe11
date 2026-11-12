// SPDX-License-Identifier: Apache-2.0
//! Standalone AES calls with the same owned parameters as combined operations.
use super::cipher::DualCipher;
use super::memory::Buffer;
use crate::{InputLimits, MessageRoute, Result, Session, SymmetricKey};

/// Explicit parameters for classic AES modes without authentication.
///
/// The caller owns IV unpredictability and counter/nonce uniqueness under a key.
/// These selections never request a digest, MAC, nonce generation or fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesCipherParameters {
    /// ECB has no native parameters. Repeated plaintext blocks remain visible.
    Ecb,
    /// CBC without padding; total input must be a multiple of 16 bytes.
    Cbc {
        /// Exact IV; it must be unpredictable when encrypting.
        iv: [u8; 16],
    },
    /// CBC with native PKCS#7 padding. Padding validity is not authentication.
    CbcPad {
        /// Exact IV; it must be unpredictable when encrypting.
        iv: [u8; 16],
    },
    /// CTR with the complete initial block and 1..=128 low-order counter bits.
    /// The module increments the counter and refuses overflow; Fe11 never resets it.
    Ctr {
        /// Number of low-order counter bits, from 1 through 128.
        counter_bits: u64,
        /// Complete initial counter block, including its high nonce bits.
        counter_block: [u8; 16],
    },
    /// OFB with an IV that must not repeat under the same key.
    Ofb {
        /// Exact initial block supplied by the caller.
        iv: [u8; 16],
    },
    /// CFB with an eight-bit segment and caller-selected unpredictable IV.
    Cfb8 {
        /// Exact initial block supplied by the caller.
        iv: [u8; 16],
    },
    /// CFB with a 64-bit segment and caller-selected unpredictable IV.
    Cfb64 {
        /// Exact initial block supplied by the caller.
        iv: [u8; 16],
    },
    /// CFB with a 128-bit segment and caller-selected unpredictable IV.
    Cfb128 {
        /// Exact initial block supplied by the caller.
        iv: [u8; 16],
    },
}
impl AesCipherParameters {
    /// Exact CKM identifier of this selection, without querying a module.
    pub fn mechanism_number(self) -> u64 {
        super::cipher::mechanism(&self.owned_selection()) as u64
    }

    pub(crate) fn iv_bytes(&self) -> &[u8] {
        match self {
            Self::Ecb => &[],
            Self::Ctr { counter_block, .. } => counter_block,
            Self::Cbc { iv }
            | Self::CbcPad { iv }
            | Self::Ofb { iv }
            | Self::Cfb8 { iv }
            | Self::Cfb64 { iv }
            | Self::Cfb128 { iv } => iv,
        }
    }
    pub(crate) fn from_selection(selection: DualCipher<'_>) -> Result<Self> {
        Ok(match selection {
            DualCipher::Ecb => Self::Ecb,
            DualCipher::Cbc { iv } => Self::Cbc { iv },
            DualCipher::CbcPad { iv } => Self::CbcPad { iv },
            DualCipher::Ctr {
                counter_bits,
                counter_block,
            } => Self::Ctr {
                counter_bits,
                counter_block,
            },
            DualCipher::Ofb { iv } => Self::Ofb { iv },
            DualCipher::Cfb8 { iv } => Self::Cfb8 { iv },
            DualCipher::Cfb64 { iv } => Self::Cfb64 { iv },
            DualCipher::Cfb128 { iv } => Self::Cfb128 { iv },
            DualCipher::Gcm { .. } => return Err(crate::Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AeadRequiresItsAuthenticatedOutputOwner,
                ),
            )),
        })
    }
    pub(crate) fn owned_selection(self) -> DualCipher<'static> {
        match self {
            Self::Ecb => DualCipher::Ecb,
            Self::Cbc { iv } => DualCipher::Cbc { iv },
            Self::CbcPad { iv } => DualCipher::CbcPad { iv },
            Self::Ctr {
                counter_bits,
                counter_block,
            } => DualCipher::Ctr {
                counter_bits,
                counter_block,
            },
            Self::Ofb { iv } => DualCipher::Ofb { iv },
            Self::Cfb8 { iv } => DualCipher::Cfb8 { iv },
            Self::Cfb64 { iv } => DualCipher::Cfb64 { iv },
            Self::Cfb128 { iv } => DualCipher::Cfb128 { iv },
        }
    }
}

/// Complete ciphertext from the selected native cipher, without a MAC.
pub struct Ciphertext {
    bytes: Buffer,
    generated_iv: Option<[u8; 24]>,
}
impl Ciphertext {
    pub(crate) fn from_parts(bytes: Buffer, generated_iv: Option<[u8; 24]>) -> Self {
        Self {
            bytes,
            generated_iv,
        }
    }
    /// Native IV for TokenIv::Generate. Preserve it with the ciphertext for
    /// decryption. Other mechanisms return None; no IV is inferred or generated.
    pub fn generated_iv(&self) -> Option<&[u8; 24]> {
        self.generated_iv.as_ref()
    }
    /// Borrow ciphertext. Copies made by the caller have their own lifetime.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
/// Plaintext returned by a mode that provides no authentication.
///
/// Successful decryption, including valid CBC padding, establishes no sender
/// identity or integrity. The owned allocation is erased on drop; caller copies
/// are outside this guarantee. No Debug or Clone implementation exposes copies.
pub struct UnauthenticatedCipherPlaintext(Buffer);
impl UnauthenticatedCipherPlaintext {
    pub(crate) fn from_buffer(bytes: Buffer) -> Self {
        Self(bytes)
    }
    /// Borrow unauthenticated plaintext; authenticate it at the protocol layer.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Session {
    /// Complete a native AES encrypt operation with the registered shared owner.
    /// Uses the single route without a size probe, retry or auxiliary MAC.
    /// Decrypted output remains unauthenticated; native refusals are preserved.
    /// Error::CipherBufferRequired leaves work active. Retrieve the continuation
    /// with take_cipher_ticket, select storage and poll, or explicitly close.
    pub fn encrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<Ciphertext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::advanced::cipher::api::encrypt_synchronous(
            self,
            key,
            parameters,
            MessageRoute::Single,
            parts,
            limits,
            &mut retirement,
        )
    }
    /// Complete a native AES encrypt operation with the registered shared owner.
    /// Uses the multipart route without a size probe, retry or auxiliary MAC.
    /// Decrypted output remains unauthenticated; native refusals are preserved.
    /// Error::CipherBufferRequired leaves work active. Retrieve the continuation
    /// with take_cipher_ticket, select storage and poll, or explicitly close.
    pub fn encrypt_aes_multipart(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<Ciphertext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::advanced::cipher::api::encrypt_synchronous(
            self,
            key,
            parameters,
            MessageRoute::Multipart,
            parts,
            limits,
            &mut retirement,
        )
    }
    /// Complete a native AES decrypt operation with the registered shared owner.
    /// Uses the single route without a size probe, retry or auxiliary MAC.
    /// Decrypted output remains unauthenticated; native refusals are preserved.
    /// Error::CipherBufferRequired leaves work active. Retrieve the continuation
    /// with take_cipher_ticket, select storage and poll, or explicitly close.
    pub fn decrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<UnauthenticatedCipherPlaintext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::advanced::cipher::api::decrypt_synchronous(
            self,
            key,
            parameters,
            MessageRoute::Single,
            parts,
            limits,
            &mut retirement,
        )
    }
    /// Complete a native AES decrypt operation with the registered shared owner.
    /// Uses the multipart route without a size probe, retry or auxiliary MAC.
    /// Decrypted output remains unauthenticated; native refusals are preserved.
    /// Error::CipherBufferRequired leaves work active. Retrieve the continuation
    /// with take_cipher_ticket, select storage and poll, or explicitly close.
    pub fn decrypt_aes_multipart(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<UnauthenticatedCipherPlaintext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::advanced::cipher::api::decrypt_synchronous(
            self,
            key,
            parameters,
            MessageRoute::Multipart,
            parts,
            limits,
            &mut retirement,
        )
    }
}

impl crate::AdvancedSession {
    /// Synchronous standalone AES encryption through the Session owner.
    /// Does not create a ticket or change pacing; an occupied session is refused.
    pub fn encrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<Ciphertext> {
        self.session.encrypt_aes(key, parameters, parts, limits)
    }
    /// Synchronous multipart AES encryption; no cooperative or native asynchronous mode claim.
    pub fn encrypt_aes_multipart(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<Ciphertext> {
        self.session
            .encrypt_aes_multipart(key, parameters, parts, limits)
    }
    /// Synchronous standalone AES decryption; returns unauthenticated plaintext.
    pub fn decrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<UnauthenticatedCipherPlaintext> {
        self.session.decrypt_aes(key, parameters, parts, limits)
    }
    /// Synchronous multipart AES decryption through the same retained owner.
    pub fn decrypt_aes_multipart(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<UnauthenticatedCipherPlaintext> {
        self.session
            .decrypt_aes_multipart(key, parameters, parts, limits)
    }
}

/// Compatibility spelling for the AES convenience methods.
pub type AesCiphertext = Ciphertext;
/// Compatibility spelling; this output never establishes authenticity.
pub type UnauthenticatedAesPlaintext = UnauthenticatedCipherPlaintext;
