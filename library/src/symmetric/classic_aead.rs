// SPDX-License-Identifier: Apache-2.0
//! Caller-selected parameters for the classic Encrypt/Decrypt function families.

use super::memory::{Buffer, Credit};
use crate::{bounds, Error, Result, StreamAeadNonce};
use fe11_sys::*;

/// Classic AEAD parameters, copied before native initialization. Nonce uniqueness
/// belongs to the caller. These routes neither generate a nonce nor select a
/// security profile. Native support, including multipart support, is not inferred.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClassicAeadParameters<'a> {
    /// AES-GCM; the tag is appended to ciphertext. Zero bits provides no authentication.
    Gcm {
        /// Exact caller-provided IV bytes.
        iv: &'a [u8],
        /// Additional authenticated data.
        aad: &'a [u8],
        /// Native tag length in bits, from zero through 128.
        tag_bits: u64,
    },
    /// Explicit historical C layout without ulIvBits. Select only for a module
    /// implementing that layout; Fe11 neither probes nor retries another ABI.
    /// Continuations and records preserve this application-selected contract.
    GcmWithoutIvBits {
        /// Exact caller-provided IV bytes.
        iv: &'a [u8],
        /// Additional authenticated data.
        aad: &'a [u8],
        /// Appended authentication tag length in bits.
        tag_bits: u64,
    },
    /// AES-CCM; the native descriptor receives the complete plaintext length.
    Ccm {
        /// Caller-provided nonce, seven through thirteen bytes.
        nonce: &'a [u8],
        /// Additional authenticated data.
        aad: &'a [u8],
        /// Appended MAC length in bytes: 4, 6, 8, 10, 12, 14 or 16.
        mac_length: u64,
    },
    /// One of the five standard stream AEAD tuples, with a 128-bit appended tag.
    Stream {
        /// Exact mechanism/nonce tuple; native nonce lengths are expressed in bits.
        nonce: StreamAeadNonce,
        /// Additional authenticated data.
        aad: &'a [u8],
    },
    /// Explicit legacy IETF encoding: write 12 into ulNonceLen, not 96.
    /// This is an application-selected compatibility contract, never a fallback.
    ChaCha20IetfBytes {
        /// Exact 96-bit nonce, retained in storage large enough for either interpretation.
        nonce: [u8; 12],
        /// Additional authenticated data.
        aad: &'a [u8],
    },
}
impl ClassicAeadParameters<'_> {
    /// Exact native mechanism number; availability is decided by the module.
    pub fn mechanism_number(self) -> u64 {
        match self {
            Self::Gcm { .. } | Self::GcmWithoutIvBits { .. } => CKM_AES_GCM as u64,
            Self::Ccm { .. } => CKM_AES_CCM as u64,
            Self::Stream { nonce, .. } => nonce.mechanism_number(),
            Self::ChaCha20IetfBytes { .. } => CKM_CHACHA20_POLY1305 as u64,
        }
    }
    pub(crate) fn nonce(&self) -> &[u8] {
        match self {
            Self::Gcm { iv, .. } | Self::GcmWithoutIvBits { iv, .. } => iv,
            Self::Ccm { nonce, .. } => nonce,
            Self::Stream { nonce, .. } => nonce.as_bytes(),
            Self::ChaCha20IetfBytes { nonce, .. } => nonce,
        }
    }
    pub(crate) fn aad(&self) -> &[u8] {
        match self {
            Self::Gcm { aad, .. }
            | Self::GcmWithoutIvBits { aad, .. }
            | Self::Ccm { aad, .. }
            | Self::Stream { aad, .. }
            | Self::ChaCha20IetfBytes { aad, .. } => aad,
        }
    }
    pub(crate) fn tag_bits(self) -> Result<u64> {
        match self {
            Self::Gcm { tag_bits, .. } | Self::GcmWithoutIvBits { tag_bits, .. }
                if tag_bits <= 128 =>
            {
                Ok(tag_bits)
            }
            Self::Ccm { mac_length: n, .. } if matches!(n, 4 | 6 | 8 | 10 | 12 | 14 | 16) => {
                Ok(n * 8)
            }
            Self::Stream { .. } | Self::ChaCha20IetfBytes { .. } => Ok(128),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::ClassicAeadTagLength,
                ),
            )),
        }
    }
    pub(crate) fn output_bounds(self, input: usize, decrypt: bool) -> Result<(usize, usize)> {
        let tag = self.tag_bits()?.div_ceil(8) as usize;
        let output = if decrypt {
            input.checked_sub(tag).ok_or(Error::InvalidCiphertext)?
        } else {
            input.checked_add(tag).ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AeadOutputLengthOverflow,
                ),
            ))?
        };
        bounds::ck_length(input)?;
        bounds::ck_length(output)?;
        self.validate_stream_parameters(Some(if decrypt { output } else { input }), decrypt)?;
        Ok((output, output))
    }
    pub(crate) fn validate_stream_parameters(
        self,
        ccm_data_length: Option<usize>,
        decrypt: bool,
    ) -> Result<()> {
        self.tag_bits()?;
        bounds::ck_length(self.nonce().len())?;
        bounds::ck_length(self.aad().len())?;
        match self {
            Self::Gcm { iv, aad, .. } | Self::GcmWithoutIvBits { iv, aad, .. } => {
                if iv.is_empty()
                    || iv.len() as u128 > u32::MAX as u128
                    || aad.len() as u128 > u32::MAX as u128
                {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::GcmNormativeParameterBounds,
                        ),
                    ));
                }
            }
            Self::Ccm {
                nonce,
                aad,
                mac_length,
            } => {
                super::ccm::validate_ccm_fields(
                    super::AeadParameterLayout::Classic,
                    nonce.len(),
                    0,
                    0,
                    aad.len(),
                    mac_length,
                    ccm_data_length.ok_or(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::CcmRequiresDeclaredPlaintextLength,
                        ),
                    ))?,
                    decrypt,
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Completed classic AEAD ciphertext and its exact nonce. Owned bytes are erased
/// on drop; copies made by the application are outside that guarantee.
pub struct ClassicAeadCiphertext {
    pub(crate) bytes: Buffer,
    pub(crate) nonce: Buffer,
    pub(crate) mechanism: u64,
    pub(crate) tag_bits: u64,
    pub(crate) retention: Credit,
}
impl ClassicAeadCiphertext {
    /// Ciphertext followed by the native authentication tag.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Exact nonce supplied to native initialization.
    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_slice()
    }
    /// Selected mechanism, without a claim of global module conformance.
    pub fn mechanism_number(&self) -> u64 {
        self.mechanism
    }
    /// Selected native tag length in bits; zero provides no authentication.
    pub fn tag_bits(&self) -> u64 {
        self.tag_bits
    }
}
