// SPDX-License-Identifier: Apache-2.0
//! Native cipher selections and fixed-width contracts, without provider selection.
use crate::{AesCipherParameters, Error, Result};
use fe11_sys::*;

/// Explicit native cipher parameters. IV unpredictability/uniqueness and protocol
/// authentication belong to the caller. Native key-wrap integrity checks do not
/// establish the origin or protocol context of the decrypted data.
/// Token-IV mechanisms explicitly request native IV generation on encryption.
/// A mechanism identifier is not evidence of native support or key permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherParameters<'a> {
    /// CKM_AES_CFB1, retaining the caller's complete AES-block initialization vector.
    AesCfb1 {
        /// Exact sixteen-byte IV; native calls express data lengths in bytes.
        iv: [u8; 16],
    },
    /// Historical CKM_AES_KEY_WRAP_PAD, retaining its own native identifier.
    /// PKCS#11 3.0 §2.16 mentions PKCS7 without fixing its padding block size;
    /// 3.2 deprecates this mechanism. The native module determines the result
    /// length. A local storage estimate is not a result-length requirement.
    AesKeyWrapPad {
        /// None selects the native default; Some passes these exact eight bytes.
        iv: Option<[u8; 8]>,
    },
    /// CKM_AES_KEY_WRAP on data, using C_Encrypt/C_Decrypt in one part.
    AesKeyWrap {
        /// None selects the normative default; Some passes these exact eight bytes.
        iv: Option<[u8; 8]>,
    },
    /// CKM_AES_KEY_WRAP_KWP on data, with RFC5649 padding performed by the module.
    AesKeyWrapKwp {
        /// None selects the normative default; Some passes these exact four bytes.
        iv: Option<[u8; 4]>,
    },
    /// CKM_AES_KEY_WRAP_PKCS7 on data, with native PKCS7 semiblock padding.
    AesKeyWrapPkcs7 {
        /// None selects the normative default; Some passes these exact eight bytes.
        iv: Option<[u8; 8]>,
    },
    /// CKM_GOST28147_ECB: no parameter, whole eight-byte blocks.
    Gost28147Ecb,
    /// CKM_GOST28147: the key's CKA_GOST28147_PARAMS selects the mode.
    Gost28147 {
        /// None explicitly requests the normative omitted-parameter zero IV.
        /// Some preserves the eight supplied bytes, including an all-zero IV.
        iv: Option<[u8; 8]>,
    },
    /// Historical native modes with an output IV on encryption.
    TokenIv {
        /// Exact mechanism; no implicit replacement or capability assumption.
        cipher: super::token_iv::TokenIvCipher,
        /// Generate for encryption, Provided for decryption.
        iv: super::token_iv::TokenIv,
    },
    /// CKM_NULL: native pass-through, providing no confidentiality or authenticity.
    Null,
    /// ChaCha20/Salsa20 native tuples, with no implicit authentication.
    Stream(super::stream::StreamCipherParameters),
    /// CKM_CAST_ECB: no native parameters.
    CastEcb,
    /// CKM_CAST_CBC: exact eight-byte IV.
    CastCbc {
        /// Exact caller-supplied IV, copied before initialization.
        iv: [u8; 8],
    },
    /// CKM_CAST_CBC_PAD: exact eight-byte IV.
    CastCbcPad {
        /// Exact caller-supplied IV, copied before initialization.
        iv: [u8; 8],
    },
    /// CKM_CAST3_ECB: no native parameters.
    Cast3Ecb,
    /// CKM_CAST3_CBC: exact eight-byte IV.
    Cast3Cbc {
        /// Exact caller-supplied IV, copied before initialization.
        iv: [u8; 8],
    },
    /// CKM_CAST3_CBC_PAD: exact eight-byte IV.
    Cast3CbcPad {
        /// Exact caller-supplied IV, copied before initialization.
        iv: [u8; 8],
    },
    /// CKM_CAST5_ECB (CKM_CAST128_ECB): no native parameters.
    Cast5Ecb,
    /// CKM_CAST5_CBC (CKM_CAST128_CBC): exact eight-byte IV.
    Cast5Cbc {
        /// Exact caller-supplied IV, copied before initialization.
        iv: [u8; 8],
    },
    /// CKM_CAST5_CBC_PAD (CKM_CAST128_CBC_PAD): exact eight-byte IV.
    Cast5CbcPad {
        /// Exact caller-supplied IV, copied before initialization.
        iv: [u8; 8],
    },
    /// CKM_RC4: no native parameters.
    Rc4,

    /// RC2/RC5 scalar and owned-at-call parameter contracts.
    Rc(super::structured::RcCipherParameters<'a>),
    /// Camellia CTR, retaining the complete initial counter block.
    CamelliaCtr {
        /// Number of low-order counter bits, from 1 through 128.
        counter_bits: u64,
        /// Complete caller-selected initial counter block.
        counter_block: [u8; 16],
    },
    /// Existing AES modes, including their structured CTR counter selection.
    Aes(AesCipherParameters),
    /// CKM_DES_ECB: no parameters.
    DesEcb,
    /// CKM_DES_CBC: exact 8-byte initialization vector.
    DesCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_DES_CBC_PAD: exact 8-byte initialization vector.
    DesCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_DES3_ECB: no parameters.
    Des3Ecb,
    /// CKM_DES3_CBC: exact 8-byte initialization vector.
    Des3Cbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_DES3_CBC_PAD: exact 8-byte initialization vector.
    Des3CbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_CDMF_ECB: no parameters.
    CdmfEcb,
    /// CKM_CDMF_CBC: exact 8-byte initialization vector.
    CdmfCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_CDMF_CBC_PAD: exact 8-byte initialization vector.
    CdmfCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_IDEA_ECB: no parameters.
    IdeaEcb,
    /// CKM_IDEA_CBC: exact 8-byte initialization vector.
    IdeaCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_IDEA_CBC_PAD: exact 8-byte initialization vector.
    IdeaCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_CAMELLIA_ECB: no parameters.
    CamelliaEcb,
    /// CKM_CAMELLIA_CBC: exact 16-byte initialization vector.
    CamelliaCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_CAMELLIA_CBC_PAD: exact 16-byte initialization vector.
    CamelliaCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_ARIA_ECB: no parameters.
    AriaEcb,
    /// CKM_ARIA_CBC: exact 16-byte initialization vector.
    AriaCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_ARIA_CBC_PAD: exact 16-byte initialization vector.
    AriaCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_SEED_ECB: no parameters.
    SeedEcb,
    /// CKM_SEED_CBC: exact 16-byte initialization vector.
    SeedCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_SEED_CBC_PAD: exact 16-byte initialization vector.
    SeedCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_DES_OFB64: exact 8-byte initialization vector.
    DesOfb64 {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_DES_OFB8: exact 8-byte initialization vector.
    DesOfb8 {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_DES_CFB64: exact 8-byte initialization vector.
    DesCfb64 {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_DES_CFB8: exact 8-byte initialization vector.
    DesCfb8 {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_BLOWFISH_CBC: exact 8-byte initialization vector.
    BlowfishCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_BLOWFISH_CBC_PAD: exact 8-byte initialization vector.
    BlowfishCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 8],
    },
    /// CKM_TWOFISH_CBC: exact 16-byte initialization vector.
    TwofishCbc {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_TWOFISH_CBC_PAD: exact 16-byte initialization vector.
    TwofishCbcPad {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_AES_CTS: exact 16-byte initialization vector.
    AesCts {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
    /// CKM_AES_XTS: exact 16-byte data-unit sequence number.
    AesXts {
        /// Exact bytes supplied by the caller; no implicit generation.
        iv: [u8; 16],
    },
}
impl From<AesCipherParameters> for CipherParameters<'_> {
    fn from(value: AesCipherParameters) -> Self {
        Self::Aes(value)
    }
}
impl<'a> CipherParameters<'a> {
    pub(crate) fn validate_route(self, route: crate::MessageRoute) -> Result<()> {
        // PKCS#11 3.2 §6.16.3 defines only single-part data and key wrapping.
        // Reject an unrepresentable route before any native initialization.
        if matches!(
            self,
            Self::AesKeyWrap { .. }
                | Self::AesKeyWrapPad { .. }
                | Self::AesKeyWrapKwp { .. }
                | Self::AesKeyWrapPkcs7 { .. }
        ) && route != crate::MessageRoute::Single
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AesKeyWrapRequiresASinglePartOperation,
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn additional_buffer_bytes(self) -> usize {
        match self {
            Self::Stream(value) => value.counter().bytes().len(),
            _ => 0,
        }
    }
    /// PAD has no unambiguous historical result-length contract. Only the
    /// actual supplied buffer bounds its native output; other contracts retain
    /// their normative length checks.
    pub(crate) fn validates_output_interval(self) -> bool {
        !matches!(self, Self::AesKeyWrapPad { .. })
    }
    pub(crate) fn output_bounds(self, input: usize, decrypt: bool) -> Result<(usize, usize)> {
        match self {
            Self::Gost28147 { .. } => Ok((
                input,
                rounded_gost_length(input).ok_or(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::GostOutputLengthOverflow,
                    ),
                ))?,
            )),
            Self::TokenIv { cipher, iv } => {
                iv.validate_direction(decrypt)?;
                cipher.output_bounds(input)
            }
            Self::Stream(value) => value.output_bounds(input),
            Self::Rc(value) => value.output_bounds(input, decrypt),
            Self::CamelliaCtr { counter_bits, .. } => {
                super::cipher::counter_width(counter_bits)?;
                Ok((input, input))
            }
            _ => super::cipher::output_bounds(input, decrypt, self.mechanism_number(), 0),
        }
    }

    /// Exact CKM selection, without querying a module or asserting support.
    pub fn mechanism_number(self) -> u64 {
        match self {
            Self::AesCfb1 { .. } => CKM_AES_CFB1 as u64,
            Self::AesKeyWrapPad { .. } => CKM_AES_KEY_WRAP_PAD as u64,
            Self::AesKeyWrap { .. } => CKM_AES_KEY_WRAP as u64,
            Self::AesKeyWrapKwp { .. } => CKM_AES_KEY_WRAP_KWP as u64,
            Self::AesKeyWrapPkcs7 { .. } => CKM_AES_KEY_WRAP_PKCS7 as u64,
            Self::TokenIv { cipher, .. } => cipher.mechanism_number(),
            Self::Gost28147Ecb => CKM_GOST28147_ECB as u64,
            Self::Gost28147 { .. } => CKM_GOST28147 as u64,
            Self::Null => CKM_NULL as u64,
            Self::CastEcb => CKM_CAST_ECB as u64,
            Self::CastCbc { .. } => CKM_CAST_CBC as u64,
            Self::CastCbcPad { .. } => CKM_CAST_CBC_PAD as u64,
            Self::Cast3Ecb => CKM_CAST3_ECB as u64,
            Self::Cast3Cbc { .. } => CKM_CAST3_CBC as u64,
            Self::Cast3CbcPad { .. } => CKM_CAST3_CBC_PAD as u64,
            Self::Cast5Ecb => CKM_CAST5_ECB as u64,
            Self::Cast5Cbc { .. } => CKM_CAST5_CBC as u64,
            Self::Cast5CbcPad { .. } => CKM_CAST5_CBC_PAD as u64,
            Self::Rc4 => CKM_RC4 as u64,
            Self::Stream(value) => value.mechanism_number(),
            Self::Rc(value) => value.kind() as u64,
            Self::CamelliaCtr { .. } => CKM_CAMELLIA_CTR as u64,
            Self::Aes(value) => value.mechanism_number(),
            Self::DesEcb => CKM_DES_ECB as u64,
            Self::DesCbc { .. } => CKM_DES_CBC as u64,
            Self::DesCbcPad { .. } => CKM_DES_CBC_PAD as u64,
            Self::Des3Ecb => CKM_DES3_ECB as u64,
            Self::Des3Cbc { .. } => CKM_DES3_CBC as u64,
            Self::Des3CbcPad { .. } => CKM_DES3_CBC_PAD as u64,
            Self::CdmfEcb => CKM_CDMF_ECB as u64,
            Self::CdmfCbc { .. } => CKM_CDMF_CBC as u64,
            Self::CdmfCbcPad { .. } => CKM_CDMF_CBC_PAD as u64,
            Self::IdeaEcb => CKM_IDEA_ECB as u64,
            Self::IdeaCbc { .. } => CKM_IDEA_CBC as u64,
            Self::IdeaCbcPad { .. } => CKM_IDEA_CBC_PAD as u64,
            Self::CamelliaEcb => CKM_CAMELLIA_ECB as u64,
            Self::CamelliaCbc { .. } => CKM_CAMELLIA_CBC as u64,
            Self::CamelliaCbcPad { .. } => CKM_CAMELLIA_CBC_PAD as u64,
            Self::AriaEcb => CKM_ARIA_ECB as u64,
            Self::AriaCbc { .. } => CKM_ARIA_CBC as u64,
            Self::AriaCbcPad { .. } => CKM_ARIA_CBC_PAD as u64,
            Self::SeedEcb => CKM_SEED_ECB as u64,
            Self::SeedCbc { .. } => CKM_SEED_CBC as u64,
            Self::SeedCbcPad { .. } => CKM_SEED_CBC_PAD as u64,
            Self::DesOfb64 { .. } => CKM_DES_OFB64 as u64,
            Self::DesOfb8 { .. } => CKM_DES_OFB8 as u64,
            Self::DesCfb64 { .. } => CKM_DES_CFB64 as u64,
            Self::DesCfb8 { .. } => CKM_DES_CFB8 as u64,
            Self::BlowfishCbc { .. } => CKM_BLOWFISH_CBC as u64,
            Self::BlowfishCbcPad { .. } => CKM_BLOWFISH_CBC_PAD as u64,
            Self::TwofishCbc { .. } => CKM_TWOFISH_CBC as u64,
            Self::TwofishCbcPad { .. } => CKM_TWOFISH_CBC_PAD as u64,
            Self::AesCts { .. } => CKM_AES_CTS as u64,
            Self::AesXts { .. } => CKM_AES_XTS as u64,
        }
    }
    pub(crate) fn iv_bytes(&self) -> &[u8] {
        match self {
            Self::AesCfb1 { iv } => iv,
            Self::AesKeyWrap { iv: None }
            | Self::AesKeyWrapPad { iv: None }
            | Self::AesKeyWrapKwp { iv: None }
            | Self::AesKeyWrapPkcs7 { iv: None } => &[],
            Self::AesKeyWrap { iv: Some(iv) }
            | Self::AesKeyWrapPad { iv: Some(iv) }
            | Self::AesKeyWrapPkcs7 { iv: Some(iv) } => iv,
            Self::AesKeyWrapKwp { iv: Some(iv) } => iv,
            Self::TokenIv { iv, .. } => iv.bytes(),
            Self::Gost28147Ecb | Self::Gost28147 { iv: None } => &[],
            Self::Gost28147 { iv: Some(iv) } => iv,
            Self::Null => &[],
            Self::CastEcb => &[],
            Self::CastCbc { iv } => iv,
            Self::CastCbcPad { iv } => iv,
            Self::Cast3Ecb => &[],
            Self::Cast3Cbc { iv } => iv,
            Self::Cast3CbcPad { iv } => iv,
            Self::Cast5Ecb => &[],
            Self::Cast5Cbc { iv } => iv,
            Self::Cast5CbcPad { iv } => iv,
            Self::Rc4 => &[],
            Self::Stream(value) => value.nonce(),
            Self::Rc(value) => value.iv_bytes(),
            Self::CamelliaCtr { counter_block, .. } => counter_block,
            Self::Aes(value) => value.iv_bytes(),
            Self::DesEcb => &[],
            Self::DesCbc { iv } => iv,
            Self::DesCbcPad { iv } => iv,
            Self::Des3Ecb => &[],
            Self::Des3Cbc { iv } => iv,
            Self::Des3CbcPad { iv } => iv,
            Self::CdmfEcb => &[],
            Self::CdmfCbc { iv } => iv,
            Self::CdmfCbcPad { iv } => iv,
            Self::IdeaEcb => &[],
            Self::IdeaCbc { iv } => iv,
            Self::IdeaCbcPad { iv } => iv,
            Self::CamelliaEcb => &[],
            Self::CamelliaCbc { iv } => iv,
            Self::CamelliaCbcPad { iv } => iv,
            Self::AriaEcb => &[],
            Self::AriaCbc { iv } => iv,
            Self::AriaCbcPad { iv } => iv,
            Self::SeedEcb => &[],
            Self::SeedCbc { iv } => iv,
            Self::SeedCbcPad { iv } => iv,
            Self::DesOfb64 { iv } => iv,
            Self::DesOfb8 { iv } => iv,
            Self::DesCfb64 { iv } => iv,
            Self::DesCfb8 { iv } => iv,
            Self::BlowfishCbc { iv } => iv,
            Self::BlowfishCbcPad { iv } => iv,
            Self::TwofishCbc { iv } => iv,
            Self::TwofishCbcPad { iv } => iv,
            Self::AesCts { iv } => iv,
            Self::AesXts { iv } => iv,
        }
    }
    pub(crate) fn from_fixed(kind: u64, iv: &[u8]) -> Result<Self> {
        let kind = CK_MECHANISM_TYPE::try_from(kind).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::BlockCipherMechanismWidth,
            ))
        })?;
        match kind {
            CKM_AES_CFB1 => Ok(Self::AesCfb1 {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::AesCfb1IvWidth,
                    ))
                })?,
            }),
            CKM_AES_KEY_WRAP | CKM_AES_KEY_WRAP_PAD | CKM_AES_KEY_WRAP_PKCS7 => {
                let iv = if iv.is_empty() {
                    None
                } else {
                    Some(iv.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::AesKeyWrapIvWidth,
                        ))
                    })?)
                };
                Ok(if kind == CKM_AES_KEY_WRAP {
                    Self::AesKeyWrap { iv }
                } else if kind == CKM_AES_KEY_WRAP_PAD {
                    Self::AesKeyWrapPad { iv }
                } else {
                    Self::AesKeyWrapPkcs7 { iv }
                })
            }
            CKM_AES_KEY_WRAP_KWP => {
                let iv = if iv.is_empty() {
                    None
                } else {
                    Some(iv.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::AesKwpIvWidth,
                        ))
                    })?)
                };
                Ok(Self::AesKeyWrapKwp { iv })
            }
            CKM_GOST28147_ECB => {
                if iv.is_empty() {
                    Ok(Self::Gost28147Ecb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::GostEcbHasNoParameter,
                        ),
                    ))
                }
            }
            CKM_NULL => {
                if iv.is_empty() {
                    Ok(Self::Null)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::CkmNullHasNoParameters,
                        ),
                    ))
                }
            }
            CKM_CAST_ECB => {
                if iv.is_empty() {
                    Ok(Self::CastEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::ParameterlessCipherHasNoIv,
                        ),
                    ))
                }
            }
            CKM_CAST_CBC => Ok(Self::CastCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAST_CBC_PAD => Ok(Self::CastCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAST3_ECB => {
                if iv.is_empty() {
                    Ok(Self::Cast3Ecb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::ParameterlessCipherHasNoIv,
                        ),
                    ))
                }
            }
            CKM_CAST3_CBC => Ok(Self::Cast3Cbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAST3_CBC_PAD => Ok(Self::Cast3CbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAST5_ECB => {
                if iv.is_empty() {
                    Ok(Self::Cast5Ecb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::ParameterlessCipherHasNoIv,
                        ),
                    ))
                }
            }
            CKM_CAST5_CBC => Ok(Self::Cast5Cbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAST5_CBC_PAD => Ok(Self::Cast5CbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_RC4 => {
                if iv.is_empty() {
                    Ok(Self::Rc4)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::ParameterlessCipherHasNoIv,
                        ),
                    ))
                }
            }
            CKM_DES_ECB => {
                if iv.is_empty() {
                    Ok(Self::DesEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_DES_CBC => Ok(Self::DesCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES_CBC_PAD => Ok(Self::DesCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES3_ECB => {
                if iv.is_empty() {
                    Ok(Self::Des3Ecb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_DES3_CBC => Ok(Self::Des3Cbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES3_CBC_PAD => Ok(Self::Des3CbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CDMF_ECB => {
                if iv.is_empty() {
                    Ok(Self::CdmfEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_CDMF_CBC => Ok(Self::CdmfCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CDMF_CBC_PAD => Ok(Self::CdmfCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_IDEA_ECB => {
                if iv.is_empty() {
                    Ok(Self::IdeaEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_IDEA_CBC => Ok(Self::IdeaCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_IDEA_CBC_PAD => Ok(Self::IdeaCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAMELLIA_ECB => {
                if iv.is_empty() {
                    Ok(Self::CamelliaEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_CAMELLIA_CBC => Ok(Self::CamelliaCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_CAMELLIA_CBC_PAD => Ok(Self::CamelliaCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_ARIA_ECB => {
                if iv.is_empty() {
                    Ok(Self::AriaEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_ARIA_CBC => Ok(Self::AriaCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_ARIA_CBC_PAD => Ok(Self::AriaCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_SEED_ECB => {
                if iv.is_empty() {
                    Ok(Self::SeedEcb)
                } else {
                    Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::EcbHasNoIv,
                        ),
                    ))
                }
            }
            CKM_SEED_CBC => Ok(Self::SeedCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_SEED_CBC_PAD => Ok(Self::SeedCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES_OFB64 => Ok(Self::DesOfb64 {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES_OFB8 => Ok(Self::DesOfb8 {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES_CFB64 => Ok(Self::DesCfb64 {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_DES_CFB8 => Ok(Self::DesCfb8 {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_BLOWFISH_CBC => Ok(Self::BlowfishCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_BLOWFISH_CBC_PAD => Ok(Self::BlowfishCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_TWOFISH_CBC => Ok(Self::TwofishCbc {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_TWOFISH_CBC_PAD => Ok(Self::TwofishCbcPad {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_AES_CTS => Ok(Self::AesCts {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            CKM_AES_XTS => Ok(Self::AesXts {
                iv: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::BlockCipherIvWidth,
                    ))
                })?,
            }),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::FixedBlockCipherContractAbsent,
                ),
            )),
        }
    }
}

mod terminal;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LengthRule {
    KeyWrap,
    Aligned,
    Padded,
    Stream,
    Stealing,
}
#[derive(Clone, Copy)]
pub(crate) struct FixedContract {
    pub kind: CK_MECHANISM_TYPE,
    pub block: usize,
    pub iv: usize,
    pub length: LengthRule,
}
impl FixedContract {
    pub(crate) fn from_native(kind: CK_MECHANISM_TYPE) -> Option<Self> {
        let (block, iv, length) = match kind {
            CKM_AES_KEY_WRAP
            | CKM_AES_KEY_WRAP_PAD
            | CKM_AES_KEY_WRAP_KWP
            | CKM_AES_KEY_WRAP_PKCS7 => (8, 0, LengthRule::KeyWrap),
            CKM_AES_CFB1 => (16, 16, LengthRule::Stream),
            CKM_GOST28147_ECB | CKM_CAST_ECB | CKM_CAST3_ECB | CKM_CAST5_ECB | CKM_DES_ECB
            | CKM_DES3_ECB | CKM_CDMF_ECB | CKM_IDEA_ECB => (8, 0, LengthRule::Aligned),
            CKM_NULL | CKM_RC4 => (1, 0, LengthRule::Stream),
            CKM_CAST_CBC | CKM_CAST3_CBC | CKM_CAST5_CBC | CKM_DES_CBC | CKM_DES3_CBC
            | CKM_CDMF_CBC | CKM_IDEA_CBC | CKM_BLOWFISH_CBC => (8, 8, LengthRule::Aligned),
            CKM_CAST_CBC_PAD | CKM_CAST3_CBC_PAD | CKM_CAST5_CBC_PAD | CKM_DES_CBC_PAD
            | CKM_DES3_CBC_PAD | CKM_CDMF_CBC_PAD | CKM_IDEA_CBC_PAD | CKM_BLOWFISH_CBC_PAD => {
                (8, 8, LengthRule::Padded)
            }
            CKM_CAMELLIA_ECB | CKM_ARIA_ECB | CKM_SEED_ECB => (16, 0, LengthRule::Aligned),
            CKM_CAMELLIA_CBC | CKM_ARIA_CBC | CKM_SEED_CBC | CKM_TWOFISH_CBC => {
                (16, 16, LengthRule::Aligned)
            }
            CKM_CAMELLIA_CBC_PAD | CKM_ARIA_CBC_PAD | CKM_SEED_CBC_PAD | CKM_TWOFISH_CBC_PAD => {
                (16, 16, LengthRule::Padded)
            }
            CKM_DES_OFB64 | CKM_DES_OFB8 | CKM_DES_CFB64 | CKM_DES_CFB8 => {
                (8, 8, LengthRule::Stream)
            }
            CKM_AES_CTS | CKM_AES_XTS => (16, 16, LengthRule::Stealing),
            _ => return None,
        };
        Some(Self {
            kind,
            block,
            iv,
            length,
        })
    }
    pub(crate) fn output_bounds(self, input: usize, decrypt: bool) -> Result<(usize, usize)> {
        let invalid = || {
            if decrypt {
                Error::InvalidCiphertext
            } else {
                Error::Rejected(crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::BlockCipherInputLength,
                ))
            }
        };
        match self.length {
            LengthRule::KeyWrap => key_wrap_bounds(self.kind, input, decrypt),
            LengthRule::Aligned if input % self.block != 0 => Err(invalid()),
            LengthRule::Stealing if input < self.block => Err(invalid()),
            LengthRule::Aligned | LengthRule::Stream | LengthRule::Stealing => Ok((input, input)),
            LengthRule::Padded if decrypt => {
                if input == 0 || input % self.block != 0 {
                    return Err(invalid());
                }
                Ok((input - self.block, input - 1))
            }
            LengthRule::Padded => {
                let padded = (input / self.block)
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(self.block))
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::BlockCipherPaddingLengthOverflow,
                        ),
                    ))?;
                Ok((padded, padded))
            }
        }
    }
}

// PKCS#11 3.2 table240: no extra block for an already aligned message.
fn rounded_gost_length(input: usize) -> Option<usize> {
    input.checked_add((8 - input % 8) % 8)
}

// These bounds reserve memory; they do not pre-judge native data-length errors.
// §6.16.3: KW adds one semiblock; KWP rounds up; PKCS7 adds a padding block
// even when aligned. Decryption removes the IV semiblock and any native padding.
fn key_wrap_bounds(kind: CK_MECHANISM_TYPE, input: usize, decrypt: bool) -> Result<(usize, usize)> {
    if decrypt {
        return Ok((0, input.saturating_sub(8)));
    }
    let padded = match kind {
        CKM_AES_KEY_WRAP => Some(input),
        CKM_AES_KEY_WRAP_KWP => input.checked_add((8 - input % 8) % 8).map(|n| n.max(8)),
        // Reserve for PKCS7 padding on a full AES block. This is an allocation
        // estimate only: PAD output is bounded by the supplied buffer, and a
        // larger native size request remains available to the caller.
        CKM_AES_KEY_WRAP_PAD => input.checked_add(16 - input % 16),
        CKM_AES_KEY_WRAP_PKCS7 => input.checked_add(8 - input % 8),
        _ => {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AesKeyWrapMechanism,
                ),
            ))
        }
    };
    let length = padded
        .and_then(|n| n.checked_add(8))
        .ok_or(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::AesKeyWrapOutputLengthOverflow,
            ),
        ))?;
    Ok((length, length))
}
