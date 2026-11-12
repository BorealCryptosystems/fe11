// SPDX-License-Identifier: Apache-2.0
//! Historical RC parameters with owned native descriptors and explicit units.
use super::block::{FixedContract, LengthRule};
use crate::{bounds, Error, Result};
use fe11_sys::*;

/// Explicit RC2/RC5 selections. Parameter presence is not native support.
/// The IV is copied into the registered operation before any native call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcCipherParameters<'a> {
    /// RC2 electronic codebook, with no IV.
    Rc2Ecb {
        /// Effective search-space bits, passed without a key-size policy.
        effective_bits: u64,
    },
    /// RC2 CBC without padding.
    Rc2Cbc {
        /// Effective search-space bits.
        effective_bits: u64,
        /// Caller-supplied unpredictable IV.
        iv: [u8; 8],
    },
    /// RC2 CBC with native PKCS#7 padding, which is not authentication.
    Rc2CbcPad {
        /// Effective search-space bits.
        effective_bits: u64,
        /// Caller-supplied unpredictable IV.
        iv: [u8; 8],
    },
    /// RC5 electronic codebook, with no IV.
    Rc5Ecb {
        /// Word size in bytes; the block is twice this size.
        word_bytes: u64,
        /// Exact number of rounds; the module decides support.
        rounds: u64,
    },
    /// RC5 CBC without padding.
    Rc5Cbc {
        /// Word size in bytes; the block is twice this size.
        word_bytes: u64,
        /// Exact number of rounds; the module decides support.
        rounds: u64,
        /// Exactly one block, copied before native initialization.
        iv: &'a [u8],
    },
    /// RC5 CBC with native PKCS#7 padding, which is not authentication.
    Rc5CbcPad {
        /// Word size in bytes; the block is twice this size.
        word_bytes: u64,
        /// Exact number of rounds; the module decides support.
        rounds: u64,
        /// Exactly one block, copied before native initialization.
        iv: &'a [u8],
    },
}
/// Wire metadata is independent of native integer width and pointer layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CipherOptions {
    /// Exact ulDataLen retained by classic CCM, independent of queued input.
    CcmDataLength {
        bytes: u64,
    },
    /// Explicit historical GCM structure without ulIvBits.
    GcmWithoutIvBits,
    /// Explicit legacy ulNonceLen=12 for IETF ChaCha20-Poly1305.
    ChaChaIetfBytes,
    TokenIv {
        generated: bool,
    },
    Stream {
        counter: super::stream::StreamCounter,
    },
    Rc2 {
        effective_bits: u64,
    },
    Rc5 {
        word_bytes: u64,
        rounds: u64,
    },
}
impl<'a> RcCipherParameters<'a> {
    pub(crate) fn kind(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Rc2Ecb { .. } => CKM_RC2_ECB,
            Self::Rc2Cbc { .. } => CKM_RC2_CBC,
            Self::Rc2CbcPad { .. } => CKM_RC2_CBC_PAD,
            Self::Rc5Ecb { .. } => CKM_RC5_ECB,
            Self::Rc5Cbc { .. } => CKM_RC5_CBC,
            Self::Rc5CbcPad { .. } => CKM_RC5_CBC_PAD,
        }
    }
    pub(crate) fn options(self) -> CipherOptions {
        match self {
            Self::Rc2Ecb { effective_bits }
            | Self::Rc2Cbc { effective_bits, .. }
            | Self::Rc2CbcPad { effective_bits, .. } => CipherOptions::Rc2 { effective_bits },
            Self::Rc5Ecb { word_bytes, rounds }
            | Self::Rc5Cbc {
                word_bytes, rounds, ..
            }
            | Self::Rc5CbcPad {
                word_bytes, rounds, ..
            } => CipherOptions::Rc5 { word_bytes, rounds },
        }
    }
    pub(crate) fn iv_bytes(&self) -> &[u8] {
        match self {
            Self::Rc2Ecb { .. } | Self::Rc5Ecb { .. } => &[],
            Self::Rc2Cbc { iv, .. } | Self::Rc2CbcPad { iv, .. } => iv,
            Self::Rc5Cbc { iv, .. } | Self::Rc5CbcPad { iv, .. } => iv,
        }
    }
    fn block_size(self) -> Result<usize> {
        match self.options() {
            CipherOptions::CcmDataLength { .. }
            | CipherOptions::Stream { .. }
            | CipherOptions::GcmWithoutIvBits
            | CipherOptions::TokenIv { .. }
            | CipherOptions::ChaChaIetfBytes => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::NonRcOptionsOnRcParameters,
                ),
            )),
            CipherOptions::Rc2 { effective_bits } => {
                scalar(effective_bits)?;
                Ok(8)
            }
            CipherOptions::Rc5 { word_bytes, rounds } => {
                scalar(word_bytes)?;
                scalar(rounds)?;
                usize::try_from(word_bytes)
                    .ok()
                    .and_then(|n| n.checked_mul(2))
                    .filter(|n| *n > 0)
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::Rc5BlockSize,
                        ),
                    ))
            }
        }
    }
    pub(crate) fn validate(self) -> Result<()> {
        let block = self.block_size()?;
        bounds::ck_length(block)?;
        let expected = if matches!(self, Self::Rc2Ecb { .. } | Self::Rc5Ecb { .. }) {
            0
        } else {
            block
        };
        if self.iv_bytes().len() != expected {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::RcCipherIvLength,
                ),
            ));
        }
        Ok(())
    }
    pub(crate) fn terminal_lengths(self, input: u128, output: u128, decrypt: bool) -> bool {
        let Ok(block) = self.block_size() else {
            return false;
        };
        FixedContract {
            kind: self.kind(),
            block,
            iv: self.iv_bytes().len(),
            length: if matches!(self, Self::Rc2CbcPad { .. } | Self::Rc5CbcPad { .. }) {
                LengthRule::Padded
            } else {
                LengthRule::Aligned
            },
        }
        .terminal_lengths(input, output, decrypt)
    }

    pub(crate) fn output_bounds(self, input: usize, decrypt: bool) -> Result<(usize, usize)> {
        self.validate()?;
        FixedContract {
            kind: self.kind(),
            block: self.block_size()?,
            iv: self.iv_bytes().len(),
            length: if matches!(self, Self::Rc2CbcPad { .. } | Self::Rc5CbcPad { .. }) {
                LengthRule::Padded
            } else {
                LengthRule::Aligned
            },
        }
        .output_bounds(input, decrypt)
    }
    pub(crate) fn from_record(
        kind: CK_MECHANISM_TYPE,
        options: CipherOptions,
        iv: &'a [u8],
    ) -> Result<Self> {
        let value = match (kind, options) {
            (CKM_RC2_ECB, CipherOptions::Rc2 { effective_bits }) if iv.is_empty() => {
                Self::Rc2Ecb { effective_bits }
            }
            (CKM_RC2_CBC, CipherOptions::Rc2 { effective_bits }) => Self::Rc2Cbc {
                effective_bits,
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::Rc2IvWidth,
                    ))
                })?,
            },
            (CKM_RC2_CBC_PAD, CipherOptions::Rc2 { effective_bits }) => Self::Rc2CbcPad {
                effective_bits,
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::Rc2IvWidth,
                    ))
                })?,
            },
            (CKM_RC5_ECB, CipherOptions::Rc5 { word_bytes, rounds }) if iv.is_empty() => {
                Self::Rc5Ecb { word_bytes, rounds }
            }
            (CKM_RC5_CBC, CipherOptions::Rc5 { word_bytes, rounds }) => Self::Rc5Cbc {
                word_bytes,
                rounds,
                iv,
            },
            (CKM_RC5_CBC_PAD, CipherOptions::Rc5 { word_bytes, rounds }) => Self::Rc5CbcPad {
                word_bytes,
                rounds,
                iv,
            },
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::RcRecordMechanismOptionsMismatch,
                    ),
                ))
            }
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn native_bytes(self) -> usize {
        match self {
            Self::Rc2Ecb { .. } => std::mem::size_of::<CK_RC2_PARAMS>(),
            Self::Rc2Cbc { .. } | Self::Rc2CbcPad { .. } => {
                std::mem::size_of::<CK_RC2_CBC_PARAMS>()
            }
            Self::Rc5Ecb { .. } => std::mem::size_of::<CK_RC5_PARAMS>(),
            Self::Rc5Cbc { .. } | Self::Rc5CbcPad { .. } => {
                std::mem::size_of::<CK_RC5_CBC_PARAMS>()
            }
        }
    }
}
pub(crate) fn recognized(kind: CK_MECHANISM_TYPE) -> bool {
    matches!(
        kind,
        CKM_RC2_ECB | CKM_RC2_CBC | CKM_RC2_CBC_PAD | CKM_RC5_ECB | CKM_RC5_CBC | CKM_RC5_CBC_PAD
    )
}
fn scalar(value: u64) -> Result<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SymmetricParameters(
            crate::SymmetricParametersRejection::RcParameterNativeWidth,
        ))
    })
}
pub(crate) enum RcNative {
    Rc2Ecb(Box<CK_RC2_PARAMS>),
    Rc2Cbc(Box<CK_RC2_CBC_PARAMS>),
    Rc5Ecb(Box<CK_RC5_PARAMS>),
    Rc5Cbc(Box<CK_RC5_CBC_PARAMS>),
}
impl RcNative {
    /// Complete an unpublished snapshot. RC2 embeds its IV; RC5 already points
    /// at the destination frame's stable IV buffer and needs no pointer change.
    pub(crate) fn fill_snapshot_iv(&mut self, iv: &[u8]) -> Result<()> {
        if let Self::Rc2Cbc(parameters) = self {
            parameters.iv = iv.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::Rc2IvWidth,
                ))
            })?;
        }
        Ok(())
    }
    // IV points into the enclosing CipherFrame buffer, retained with this owner.
    pub(crate) fn new(selection: RcCipherParameters<'_>, iv: *mut u8) -> Result<Self> {
        selection.validate()?;
        Ok(match selection {
            RcCipherParameters::Rc2Ecb { effective_bits } => {
                Self::Rc2Ecb(Box::new(scalar(effective_bits)?))
            }
            RcCipherParameters::Rc2Cbc { effective_bits, iv }
            | RcCipherParameters::Rc2CbcPad { effective_bits, iv } => {
                Self::Rc2Cbc(Box::new(CK_RC2_CBC_PARAMS {
                    ulEffectiveBits: scalar(effective_bits)?,
                    iv,
                }))
            }
            RcCipherParameters::Rc5Ecb { word_bytes, rounds } => {
                Self::Rc5Ecb(Box::new(CK_RC5_PARAMS {
                    ulWordsize: scalar(word_bytes)?,
                    ulRounds: scalar(rounds)?,
                }))
            }
            RcCipherParameters::Rc5Cbc {
                word_bytes,
                rounds,
                iv: source,
            }
            | RcCipherParameters::Rc5CbcPad {
                word_bytes,
                rounds,
                iv: source,
            } => Self::Rc5Cbc(Box::new(CK_RC5_CBC_PARAMS {
                ulWordsize: scalar(word_bytes)?,
                ulRounds: scalar(rounds)?,
                pIv: iv,
                ulIvLen: bounds::ck_length(source.len())?,
            })),
        })
    }
    pub(crate) fn descriptor(&mut self) -> (*mut std::ffi::c_void, CK_ULONG) {
        match self {
            Self::Rc2Ecb(p) => (
                (&mut **p as *mut CK_RC2_PARAMS).cast(),
                std::mem::size_of::<CK_RC2_PARAMS>() as CK_ULONG,
            ),
            Self::Rc2Cbc(p) => (
                (&mut **p as *mut CK_RC2_CBC_PARAMS).cast(),
                std::mem::size_of::<CK_RC2_CBC_PARAMS>() as CK_ULONG,
            ),
            Self::Rc5Ecb(p) => (
                (&mut **p as *mut CK_RC5_PARAMS).cast(),
                std::mem::size_of::<CK_RC5_PARAMS>() as CK_ULONG,
            ),
            Self::Rc5Cbc(p) => (
                (&mut **p as *mut CK_RC5_CBC_PARAMS).cast(),
                std::mem::size_of::<CK_RC5_CBC_PARAMS>() as CK_ULONG,
            ),
        }
    }
    pub(crate) fn unchanged(
        &self,
        options: CipherOptions,
        expected_iv: &[u8],
        iv: *mut u8,
    ) -> bool {
        // Read scalars by value: Windows descriptors are packed. Never form an
        // aligned reference to a native scalar or follow a rewritten pointer.
        match (self, options) {
            (Self::Rc2Ecb(p), CipherOptions::Rc2 { effective_bits }) => {
                **p as u64 == effective_bits && expected_iv.is_empty()
            }
            (Self::Rc2Cbc(p), CipherOptions::Rc2 { effective_bits }) => {
                p.ulEffectiveBits as u64 == effective_bits && p.iv.as_slice() == expected_iv
            }
            (Self::Rc5Ecb(p), CipherOptions::Rc5 { word_bytes, rounds }) => {
                p.ulWordsize as u64 == word_bytes
                    && p.ulRounds as u64 == rounds
                    && expected_iv.is_empty()
            }
            (Self::Rc5Cbc(p), CipherOptions::Rc5 { word_bytes, rounds }) => {
                p.ulWordsize as u64 == word_bytes
                    && p.ulRounds as u64 == rounds
                    && p.pIv == iv
                    && p.ulIvLen as usize == expected_iv.len()
            }
            _ => false,
        }
    }
}
