// SPDX-License-Identifier: Apache-2.0
//! Stable block-cipher parameters; combined operations retain their AES contract.
use super::block::{CipherParameters, FixedContract};

use super::memory::{Buffer, Credit};
use super::stream::{StreamCipherParameters, StreamFrame};
use super::structured::{self, CipherOptions, RcNative};
use super::token_iv::{TokenIv, TokenIvCipher};
use crate::{bounds, Error, Result};
use fe11_sys::*;

pub(crate) mod snapshot;

pub(crate) fn counter_width(bits: u64) -> Result<CK_ULONG> {
    // PKCS#11 3.2 §6.11.2 defines the meaningful low-order bit count.
    if !(1..=128).contains(&bits) {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::AesCtrCounterWidth,
            ),
        ));
    }
    CK_ULONG::try_from(bits).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SymmetricParameters(
            crate::SymmetricParametersRejection::AesCtrCounterAbiWidth,
        ))
    })
}

/// Explicit cipher profile. Nonce/IV generation and lifetime uniqueness belong
/// to the caller; these classic dual functions do not generate an IV implicitly.
pub enum DualCipher<'a> {
    /// AES-GCM with explicit IV, appended tag length and exact AAD.
    Gcm {
        /// Caller-supplied nonce, unique for each encryption under this key.
        nonce: crate::AeadNonce,
        /// Exact additional authenticated data, retained until completion.
        aad: &'a [u8],
    },
    /// AES-CBC-PAD with a 128-bit IV. The selected digest or MAC is processed
    /// through the corresponding native dual operation.
    /// A digest does not authenticate this ciphertext or its recovered bytes.
    CbcPad {
        /// Caller-supplied unpredictable initialization vector for encryption.
        iv: [u8; 16],
    },
    /// AES counter mode, without padding or authentication. The native module
    /// reports CKR_DATA_LEN_RANGE if processing would overflow the counter bits.
    Ctr {
        /// Number of low-order counter bits, from 1 through 128.
        counter_bits: u64,
        /// Entire initial big-endian counter block, including nonce/high bits.
        /// All bits are supplied by the caller; no initial value is invented.
        counter_block: [u8; 16],
    },
    /// AES-ECB without padding or parameters; does not authenticate or hide
    /// repeated blocks. The complete input must be a multiple of 16 bytes.
    Ecb,
    /// AES-CBC without padding. The complete input must be block-aligned.
    Cbc {
        /// Exact 128-bit IV; unpredictable for encryption.
        iv: [u8; 16],
    },
    /// AES-OFB; arbitrary byte length, no padding or authentication.
    Ofb {
        /// Exact 128-bit IV; never reuse under the same encryption key.
        iv: [u8; 16],
    },
    /// AES-CFB with an 8-bit feedback segment; no authentication.
    Cfb8 {
        /// Exact 128-bit IV; unpredictable for encryption.
        iv: [u8; 16],
    },
    /// AES-CFB with a 64-bit feedback segment; no authentication.
    Cfb64 {
        /// Exact 128-bit IV; unpredictable for encryption.
        iv: [u8; 16],
    },
    /// AES-CFB with a 128-bit feedback segment; no authentication.
    Cfb128 {
        /// Exact 128-bit IV; unpredictable for encryption.
        iv: [u8; 16],
    },
}

pub(crate) fn output_bounds(
    input: usize,
    decrypt: bool,
    mechanism: u64,
    tag_bytes: usize,
) -> Result<(usize, usize)> {
    let kind = CK_MECHANISM_TYPE::try_from(mechanism).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SymmetricParameters(
            crate::SymmetricParametersRejection::AesCipherMechanismWidth,
        ))
    })?;
    if let Some(contract) = FixedContract::from_native(kind) {
        return contract.output_bounds(input, decrypt);
    }
    if matches!(kind, CKM_AES_ECB | CKM_AES_CBC) {
        if input % 16 != 0 {
            return Err(if decrypt {
                Error::InvalidCiphertext
            } else {
                Error::Rejected(crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AesInputIsNotBlockAligned,
                ))
            });
        }
        return Ok((input, input));
    }
    if matches!(
        kind,
        CKM_AES_CTR | CKM_AES_OFB | CKM_AES_CFB8 | CKM_AES_CFB64 | CKM_AES_CFB128
    ) {
        return Ok((input, input));
    }
    let gcm = match kind {
        CKM_AES_GCM => true,
        CKM_AES_CBC_PAD => false,
        _ => {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AesCipherMechanism,
                ),
            ))
        }
    };
    let overhead = if gcm { tag_bytes } else { 16 };
    if decrypt {
        if input < overhead || (!gcm && input % 16 != 0) {
            return Err(Error::InvalidCiphertext);
        }
        Ok((
            input - overhead,
            if gcm { input - overhead } else { input - 1 },
        ))
    } else {
        let n = if gcm {
            input.checked_add(tag_bytes)
        } else {
            (input / 16).checked_add(1).and_then(|n| n.checked_mul(16))
        }
        .ok_or(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::AesOutputOverflow,
            ),
        ))?;
        Ok((n, n))
    }
}

#[derive(Clone, Copy)]
enum ClassicMode {
    Ecb,
    Cbc,
    CbcPad,
    Ofb,
    Cfb8,
    Cfb64,
    Cfb128,
}
impl ClassicMode {
    fn from_native(kind: CK_MECHANISM_TYPE) -> Result<Self> {
        match kind {
            CKM_AES_ECB => Ok(Self::Ecb),
            CKM_AES_CBC => Ok(Self::Cbc),
            CKM_AES_CBC_PAD => Ok(Self::CbcPad),
            CKM_AES_OFB => Ok(Self::Ofb),
            CKM_AES_CFB8 => Ok(Self::Cfb8),
            CKM_AES_CFB64 => Ok(Self::Cfb64),
            CKM_AES_CFB128 => Ok(Self::Cfb128),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::ClassicAesMechanism,
                ),
            )),
        }
    }
    fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Ecb => CKM_AES_ECB,
            Self::Cbc => CKM_AES_CBC,
            Self::CbcPad => CKM_AES_CBC_PAD,
            Self::Ofb => CKM_AES_OFB,
            Self::Cfb8 => CKM_AES_CFB8,
            Self::Cfb64 => CKM_AES_CFB64,
            Self::Cfb128 => CKM_AES_CFB128,
        }
    }
}

pub(crate) fn non_aead(mechanism: u64) -> bool {
    if mechanism == CKM_AES_CTR as u64 {
        return true;
    }
    CK_MECHANISM_TYPE::try_from(mechanism)
        .ok()
        .and_then(|kind| ClassicMode::from_native(kind).ok())
        .is_some()
}

pub(crate) fn block_cipher(mechanism: u64) -> bool {
    if mechanism == CKM_GOST28147 as u64
        || mechanism == CKM_CHACHA20 as u64
        || mechanism == CKM_SALSA20 as u64
        || mechanism == CKM_CAMELLIA_CTR as u64
        || CK_MECHANISM_TYPE::try_from(mechanism)
            .ok()
            .is_some_and(structured::recognized)
    {
        return true;
    }
    CK_MECHANISM_TYPE::try_from(mechanism)
        .ok()
        .and_then(TokenIvCipher::from_native)
        .is_some()
        || non_aead(mechanism)
        || CK_MECHANISM_TYPE::try_from(mechanism)
            .ok()
            .and_then(FixedContract::from_native)
            .is_some()
}

pub(crate) fn mechanism(parameters: &DualCipher<'_>) -> CK_MECHANISM_TYPE {
    match parameters {
        DualCipher::Gcm { .. } => CKM_AES_GCM,
        DualCipher::Ctr { .. } => CKM_AES_CTR,
        DualCipher::Ecb => CKM_AES_ECB,
        DualCipher::Cbc { .. } => CKM_AES_CBC,
        DualCipher::CbcPad { .. } => CKM_AES_CBC_PAD,
        DualCipher::Ofb { .. } => CKM_AES_OFB,
        DualCipher::Cfb8 { .. } => CKM_AES_CFB8,
        DualCipher::Cfb64 { .. } => CKM_AES_CFB64,
        DualCipher::Cfb128 { .. } => CKM_AES_CFB128,
    }
}

// The native GCM descriptor and its immutable selection exist together.
// Classic AES needs only its exact mechanism and the common owned IV (empty for ECB).
enum Parameters {
    Gcm {
        native: Box<CK_GCM_PARAMS>,
        selection: crate::AeadNonce,
    },
    Classic(ClassicMode),
    Fixed(FixedContract),
    Gost28147,
    TokenIv {
        cipher: TokenIvCipher,
        generated: bool,
    },
    Stream(StreamFrame),
    Rc {
        kind: CK_MECHANISM_TYPE,
        native: RcNative,
        options: CipherOptions,
    },
    CamelliaCtr {
        native: Box<CK_CAMELLIA_CTR_PARAMS>,
        counter_bits: u64,
    },
    Ctr {
        native: Box<CK_AES_CTR_PARAMS>,
        counter_bits: u64,
    },
}

pub(crate) struct CipherFrame {
    pub(crate) mechanism: Box<CK_MECHANISM>,
    parameters: Parameters,
    pub(crate) iv: Buffer,
    pub(crate) expected_iv: Buffer,
    pub(crate) aad: Buffer,
    expected_aad: Buffer,
    _selection_credit: Credit,
}

impl CipherFrame {
    pub(crate) fn native_parameter_bytes(parameters: &DualCipher<'_>) -> usize {
        if matches!(parameters, DualCipher::Gcm { .. }) {
            std::mem::size_of::<CK_GCM_PARAMS>()
        } else if matches!(parameters, DualCipher::Ctr { .. }) {
            std::mem::size_of::<CK_AES_CTR_PARAMS>()
        } else {
            0
        }
    }

    /// Buffer/selection credit only; the parent accounts native descriptors.
    pub(crate) fn allocation_bytes(parameters: &DualCipher<'_>) -> Result<usize> {
        let (iv, aad, selection) = match parameters {
            DualCipher::Gcm { nonce, aad } => {
                nonce.validate_gcm(aad.len())?;
                if nonce.generated() || nonce.fixed_bits() != 0 {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::ClassicGcmDoesNotGenerateAnIv,
                        ),
                    ));
                }
                bounds::ck_length(nonce.iv().len())?;
                CK_ULONG::try_from(nonce.tag_bits()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::GcmTagAbiWidth,
                    ))
                })?;
                (nonce.iv().len(), aad.len(), nonce.retained_bytes())
            }
            DualCipher::Ctr { counter_bits, .. } => {
                counter_width(*counter_bits)?;
                (16, 0, 0)
            }
            DualCipher::Ecb => (0, 0, 0),
            DualCipher::Cbc { .. }
            | DualCipher::CbcPad { .. }
            | DualCipher::Ofb { .. }
            | DualCipher::Cfb8 { .. }
            | DualCipher::Cfb64 { .. }
            | DualCipher::Cfb128 { .. } => (16, 0, 0),
        };
        bounds::ck_length(iv)?;
        bounds::ck_length(aad)?;
        iv.checked_mul(2)
            .and_then(|n| aad.checked_mul(2).and_then(|aad| n.checked_add(aad)))
            .and_then(|n| n.checked_add(selection))
            .ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::DualCipherStorageSize,
                ),
            ))
    }

    pub(crate) fn block_parameter_bytes(selection: CipherParameters<'_>) -> usize {
        match selection {
            CipherParameters::Stream(value) => value.native_bytes(),
            CipherParameters::Rc(value) => value.native_bytes(),
            CipherParameters::CamelliaCtr { .. } => std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>(),
            CipherParameters::Aes(crate::AesCipherParameters::Ctr { .. }) => {
                std::mem::size_of::<CK_AES_CTR_PARAMS>()
            }
            _ => 0,
        }
    }

    pub(crate) fn block_record_request_with_options<'a>(
        kind: u64,
        iv: &'a [u8],
        counter_bits: Option<u64>,
        options: Option<CipherOptions>,
    ) -> Result<CipherParameters<'a>> {
        let native_kind = CK_MECHANISM_TYPE::try_from(kind).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::BlockCipherMechanismWidth,
            ))
        })?;
        if let Some(options) = options {
            if counter_bits.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CtrBitsOnStructuredCipherParameters,
                    ),
                ));
            }
            return match options {
                CipherOptions::TokenIv { generated } => {
                    let cipher = TokenIvCipher::from_native(native_kind).ok_or(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::TokenIvRecordMechanism,
                        ),
                    ))?;
                    let observed: [u8; 24] = iv.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::TokenIvRecordWidth,
                        ))
                    })?;
                    Ok(CipherParameters::TokenIv {
                        cipher,
                        iv: if generated {
                            TokenIv::Generate
                        } else {
                            TokenIv::Provided(observed)
                        },
                    })
                }
                CipherOptions::Stream { counter } => {
                    StreamCipherParameters::from_record(native_kind, counter, iv)
                        .map(CipherParameters::Stream)
                }
                _ => structured::RcCipherParameters::from_record(native_kind, options, iv)
                    .map(CipherParameters::Rc),
            };
        }
        if native_kind == CKM_GOST28147 {
            if counter_bits.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CounterWidthOnGostParameters,
                    ),
                ));
            }
            return Ok(CipherParameters::Gost28147 {
                iv: if iv.is_empty() {
                    None
                } else {
                    Some(iv.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::GostIvWidth,
                        ))
                    })?)
                },
            });
        }
        if native_kind == CKM_CAMELLIA_CTR {
            let bits = counter_bits.ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CamelliaCtrWidthAbsent,
                ),
            ))?;
            counter_width(bits)?;
            return Ok(CipherParameters::CamelliaCtr {
                counter_bits: bits,
                counter_block: iv.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CamelliaCounterBlockWidth,
                    ))
                })?,
            });
        }
        if FixedContract::from_native(native_kind).is_some() {
            if counter_bits.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CounterWidthOnFixedBlockCipher,
                    ),
                ));
            }
            CipherParameters::from_fixed(kind, iv)
        } else {
            crate::AesCipherParameters::from_selection(Self::record_request(
                kind,
                iv,
                counter_bits,
            )?)
            .map(CipherParameters::Aes)
        }
    }
    pub(crate) fn options(&self) -> Option<CipherOptions> {
        match &self.parameters {
            Parameters::TokenIv { generated, .. } => Some(CipherOptions::TokenIv {
                generated: *generated,
            }),
            Parameters::Rc { options, .. } => Some(*options),
            Parameters::Stream(frame) => Some(CipherOptions::Stream {
                counter: frame.counter(),
            }),
            _ => None,
        }
    }
    pub(crate) fn block_request(&self) -> Result<CipherParameters<'_>> {
        Self::block_record_request_with_options(
            self.kind() as u64,
            self.expected_iv.as_slice(),
            self.counter_bits(),
            self.options(),
        )
    }
    pub(crate) fn kind(&self) -> CK_MECHANISM_TYPE {
        match &self.parameters {
            Parameters::Gcm { .. } => CKM_AES_GCM,
            Parameters::Ctr { .. } => CKM_AES_CTR,
            Parameters::Classic(mode) => mode.mechanism(),
            Parameters::TokenIv { cipher, .. } => cipher.kind(),
            Parameters::Gost28147 => CKM_GOST28147,
            Parameters::Fixed(contract) => contract.kind,
            Parameters::Stream(frame) => frame.kind(),
            Parameters::Rc { kind, .. } => *kind,
            Parameters::CamelliaCtr { .. } => CKM_CAMELLIA_CTR,
        }
    }
    pub(crate) fn gcm(&self) -> bool {
        matches!(&self.parameters, Parameters::Gcm { .. })
    }
    pub(crate) fn selection(&self) -> Option<&crate::AeadNonce> {
        match &self.parameters {
            Parameters::Gcm { selection, .. } => Some(selection),
            Parameters::Classic(_)
            | Parameters::Ctr { .. }
            | Parameters::Fixed(_)
            | Parameters::Rc { .. }
            | Parameters::CamelliaCtr { .. }
            | Parameters::Stream(_)
            | Parameters::TokenIv { .. }
            | Parameters::Gost28147 => None,
        }
    }

    pub(crate) fn tag_bytes(&self) -> usize {
        self.selection()
            .map_or(0, |nonce| nonce.tag_bytes().expect("validated GCM tag"))
    }
    pub(crate) fn counter_bits(&self) -> Option<u64> {
        match &self.parameters {
            Parameters::Ctr { counter_bits, .. } | Parameters::CamelliaCtr { counter_bits, .. } => {
                Some(*counter_bits)
            }
            _ => None,
        }
    }

    pub(crate) fn record_request(
        kind: u64,
        block: &[u8],
        counter_bits: Option<u64>,
    ) -> Result<DualCipher<'static>> {
        if kind == CKM_AES_CTR as u64 {
            let counter_bits = counter_bits.ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CtrCounterWidthAbsent,
                ),
            ))?;
            counter_width(counter_bits)?;
            Ok(DualCipher::Ctr {
                counter_bits,
                counter_block: block.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CtrCounterBlockWidth,
                    ))
                })?,
            })
        } else {
            if counter_bits.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CounterWidthOnNonCtrCipher,
                    ),
                ));
            }
            Self::classic_request(kind, block)
        }
    }
    pub(crate) fn classic_request(kind: u64, iv: &[u8]) -> Result<DualCipher<'static>> {
        if kind == CKM_AES_ECB as u64 {
            return if iv.is_empty() {
                Ok(DualCipher::Ecb)
            } else {
                Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::EcbDoesNotHaveIvParameters,
                    ),
                ))
            };
        }
        let iv = iv.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::ClassicAesIvWidth,
            ))
        })?;
        let kind = CK_MECHANISM_TYPE::try_from(kind).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::AesMechanismWidth,
            ))
        })?;
        match kind {
            CKM_AES_CBC => Ok(DualCipher::Cbc { iv }),
            CKM_AES_CBC_PAD => Ok(DualCipher::CbcPad { iv }),
            CKM_AES_OFB => Ok(DualCipher::Ofb { iv }),
            CKM_AES_CFB8 => Ok(DualCipher::Cfb8 { iv }),
            CKM_AES_CFB64 => Ok(DualCipher::Cfb64 { iv }),
            CKM_AES_CFB128 => Ok(DualCipher::Cfb128 { iv }),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::ClassicAesMechanism,
                ),
            )),
        }
    }
    /// Reattach already-observed output IV bytes when copying/restoring an owner.
    /// This changes owned storage only: it never initializes a native operation.
    pub(crate) fn restore_generated_iv(&mut self, observed: &[u8]) -> Result<()> {
        if matches!(
            self.parameters,
            Parameters::TokenIv {
                generated: true,
                ..
            }
        ) {
            if observed.len() != 24 || self.iv.capacity() != 24 || self.expected_iv.capacity() != 24
            {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::RestoredTokenIvWidth,
                    ),
                ));
            }
            self.iv.as_mut().copy_from_slice(observed);
            self.expected_iv.as_mut().copy_from_slice(observed);
        }
        self.validate()
    }

    pub(crate) fn generated_iv(&self) -> Result<Option<[u8; 24]>> {
        if matches!(
            self.parameters,
            Parameters::TokenIv {
                generated: true,
                ..
            }
        ) {
            Ok(Some(self.expected_iv.as_slice().try_into().map_err(
                |_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CompletedTokenIvWidth,
                    ))
                },
            )?))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn validate(&mut self) -> Result<()> {
        self.validate_parameters(false)
    }

    /// Only a definite native return can contribute an output IV. Descriptor
    /// identity remains mandatory, and no substituted native pointer is followed.
    pub(crate) fn validate_after_call(&mut self) -> Result<()> {
        self.validate_parameters(true)
    }

    fn validate_parameters(&mut self, accept_output_iv: bool) -> Result<()> {
        let valid = match &mut self.parameters {
            Parameters::Gcm {
                native: p,
                selection,
            } => {
                self.mechanism.mechanism == CKM_AES_GCM
                    && self.mechanism.pParameter == (&mut **p as *mut CK_GCM_PARAMS).cast()
                    && self.mechanism.ulParameterLen
                        == std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG
                    && p.pIv == self.iv.as_mut().as_mut_ptr()
                    && p.ulIvLen as u128 == self.iv.capacity() as u128
                    && p.ulIvBits == bounds::gcm_iv_bits(bounds::ck_length(self.iv.capacity())?)
                    && p.pAAD == self.aad.as_mut().as_mut_ptr()
                    && p.ulAADLen as u128 == self.aad.capacity() as u128
                    && p.ulTagBits == selection.tag_bits() as CK_ULONG
            }
            Parameters::Ctr {
                native,
                counter_bits,
            } => {
                self.mechanism.mechanism == CKM_AES_CTR
                    && self.mechanism.pParameter == (&mut **native as *mut CK_AES_CTR_PARAMS).cast()
                    && self.mechanism.ulParameterLen
                        == std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG
                    && native.ulCounterBits == counter_width(*counter_bits)?
                    && native.cb.as_slice() == self.expected_iv.as_slice()
            }
            Parameters::Stream(frame) => {
                let (pointer, length) = frame.descriptor();
                self.mechanism.mechanism == frame.kind()
                    && self.mechanism.pParameter == pointer
                    && self.mechanism.ulParameterLen == length
                    && frame.unchanged(self.iv.as_mut().as_mut_ptr())
            }
            Parameters::Rc {
                kind,
                native,
                options,
            } => {
                let (pointer, length) = native.descriptor();
                self.mechanism.mechanism == *kind
                    && self.mechanism.pParameter == pointer
                    && self.mechanism.ulParameterLen == length
                    && native.unchanged(
                        *options,
                        self.expected_iv.as_slice(),
                        self.iv.as_mut().as_mut_ptr(),
                    )
            }
            Parameters::CamelliaCtr {
                native,
                counter_bits,
            } => {
                self.mechanism.mechanism == CKM_CAMELLIA_CTR
                    && self.mechanism.pParameter
                        == (&mut **native as *mut CK_CAMELLIA_CTR_PARAMS).cast()
                    && self.mechanism.ulParameterLen
                        == std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() as CK_ULONG
                    && native.ulCounterBits == counter_width(*counter_bits)?
                    && native.cb.as_slice() == self.expected_iv.as_slice()
            }
            Parameters::TokenIv { cipher, .. } => {
                self.mechanism.mechanism == cipher.kind()
                    && self.iv.capacity() == 24
                    && self.expected_iv.capacity() == 24
                    && self.mechanism.ulParameterLen == 24
                    && self.mechanism.pParameter == self.iv.as_mut().as_mut_ptr().cast()
            }
            Parameters::Gost28147 => {
                self.mechanism.mechanism == CKM_GOST28147
                    && self.iv.capacity() == self.expected_iv.capacity()
                    && match self.iv.capacity() {
                        0 => {
                            self.mechanism.pParameter.is_null()
                                && self.mechanism.ulParameterLen == 0
                        }
                        8 => {
                            self.mechanism.pParameter == self.iv.as_mut().as_mut_ptr().cast()
                                && self.mechanism.ulParameterLen == 8
                        }
                        _ => false,
                    }
            }
            Parameters::Fixed(contract) => {
                self.mechanism.mechanism == contract.kind
                    && self.iv.capacity() == contract.iv
                    && self.mechanism.ulParameterLen as usize == contract.iv
                    && if contract.iv == 0 {
                        self.mechanism.pParameter.is_null()
                    } else {
                        self.mechanism.pParameter == self.iv.as_mut().as_mut_ptr().cast()
                    }
            }
            Parameters::Classic(mode) => {
                self.mechanism.mechanism == mode.mechanism()
                    && if matches!(mode, ClassicMode::Ecb) {
                        self.mechanism.pParameter.is_null() && self.mechanism.ulParameterLen == 0
                    } else {
                        self.mechanism.pParameter == self.iv.as_mut().as_mut_ptr().cast()
                            && self.mechanism.ulParameterLen == 16
                    }
            }
        };
        let output_iv = accept_output_iv
            && matches!(
                self.parameters,
                Parameters::TokenIv {
                    generated: true,
                    ..
                }
            );
        if !valid
            || !output_iv && self.iv.as_slice() != self.expected_iv.as_slice()
            || self.aad.as_slice() != self.expected_aad.as_slice()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CipherParameterIdentity,
                ),
            ));
        }
        if output_iv {
            self.expected_iv
                .as_mut()
                .copy_from_slice(self.iv.as_slice());
        }
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for CipherFrame {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.iv.retain_credits(retained)?;
        self.expected_iv.retain_credits(retained)?;
        self.aad.retain_credits(retained)?;
        self.expected_aad.retain_credits(retained)?;
        self._selection_credit.retain_credits(retained)?;
        if let Parameters::Stream(frame) = &self.parameters {
            frame.retain_credits(retained)?;
        }
        Ok(())
    }
}
