// SPDX-License-Identifier: Apache-2.0
//! Parameter ownership shared by classic cipher and AEAD continuations.
use super::{record, MessageRoute, OperationProgress};

use crate::symmetric::gcm_legacy::GcmWithoutIvBits;

use crate::symmetric::memory::{Buffer, Credit};
use crate::symmetric::{cipher::CipherFrame as PlainFrame, structured::CipherOptions};
use crate::ClassicAeadParameters as Aead;
use crate::{bounds, Error, Result};
use fe11_sys::{
    CKM_AES_CCM, CKM_AES_GCM, CKM_CHACHA20_POLY1305, CK_CCM_PARAMS, CK_GCM_PARAMS, CK_MECHANISM,
    CK_MECHANISM_TYPE, CK_SALSA20_CHACHA20_POLY1305_PARAMS, CK_ULONG, CK_VOID_PTR,
};

pub(in crate::advanced) mod snapshot;

/// Input framing belongs to the mechanism, not the retained input buffers.
#[derive(Clone, Copy)]
pub(super) enum ParameterInput {
    Complete(usize),
    Incremental { ccm_data_length: Option<u64> },
}

#[derive(Clone, Copy)]
pub(super) enum Selection<'a> {
    Extension(super::extension::Source<'a>),
    Plain(crate::CipherParameters<'a>),
    Aead(Aead<'a>, usize),
}
impl<'a> From<crate::CipherParameters<'a>> for Selection<'a> {
    fn from(value: crate::CipherParameters<'a>) -> Self {
        Self::Plain(value)
    }
}
impl<'a> From<Aead<'a>> for Selection<'a> {
    fn from(value: Aead<'a>) -> Self {
        Self::Aead(value, 0)
    }
}
impl<'a> Selection<'a> {
    pub(super) fn record_route(self, route: MessageRoute) -> Result<Self> {
        match self {
            Self::Extension(source) => source.record_route(route).map(Self::Extension),
            selection => Ok(selection),
        }
    }
    pub(super) fn mechanism_number(self) -> u64 {
        match self {
            Self::Extension(source) => source.metadata().mechanism as u64,
            Self::Plain(p) => p.mechanism_number(),
            Self::Aead(p, _) => p.mechanism_number(),
        }
    }
    pub(super) fn validate_route(self, route: MessageRoute) -> Result<()> {
        match self {
            Self::Extension(source) => source.check_route(route),
            Self::Plain(p) => p.validate_route(route),
            Self::Aead(_, _) => Ok(()),
        }
    }
    pub(super) fn output_bounds(self, input: usize, decrypt: bool) -> Result<(usize, usize)> {
        match self {
            Self::Extension(_) => Ok((0, 0)),
            Self::Plain(p) => p.output_bounds(input, decrypt),
            Self::Aead(p, _) => p.output_bounds(input, decrypt),
        }
    }
    pub(super) fn validates_output_interval(self) -> bool {
        match self {
            Self::Extension(_) => false,
            Self::Plain(p) => p.validates_output_interval(),
            Self::Aead(_, _) => true,
        }
    }
    /// Check the full stream, including output already delivered to the caller.
    /// The classic AEAD tag is concatenated, unlike a message AEAD tag.
    pub(super) fn terminal_lengths(
        self,
        input: u128,
        output: u128,
        decrypt: bool,
        options: Option<CipherOptions>,
    ) -> Result<bool> {
        Ok(match self {
            Self::Extension(_) => true,
            Self::Plain(p) => p.terminal_lengths(input, output, decrypt),
            Self::Aead(p, _) => {
                let tag = u128::from(p.tag_bits()?).div_ceil(8);
                let text = if decrypt {
                    input.checked_sub(tag)
                } else {
                    Some(input)
                };
                let expected = if decrypt {
                    text
                } else {
                    input.checked_add(tag)
                };
                expected == Some(output)
                    && match options {
                        Some(CipherOptions::CcmDataLength { bytes }) => text == Some(bytes as u128),
                        _ => true,
                    }
            }
        })
    }
    pub(super) fn iv_bytes(&self) -> &[u8] {
        match self {
            Self::Extension(_) => &[],
            Self::Plain(p) => p.iv_bytes(),
            Self::Aead(p, _) => p.nonce(),
        }
    }
    pub(super) fn parameter_bytes(self) -> usize {
        match self {
            Self::Extension(_) => 0,
            Self::Plain(p) => PlainFrame::block_parameter_bytes(p),
            Self::Aead(Aead::Gcm { .. }, _) => std::mem::size_of::<CK_GCM_PARAMS>(),
            Self::Aead(Aead::GcmWithoutIvBits { .. }, _) => std::mem::size_of::<GcmWithoutIvBits>(),
            Self::Aead(Aead::Ccm { .. }, _) => std::mem::size_of::<CK_CCM_PARAMS>(),
            Self::Aead(_, _) => std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>(),
        }
    }
    pub(super) fn additional_buffer_bytes(self) -> Result<usize> {
        match self {
            Self::Extension(source) => source.allocation_bytes(),
            Self::Plain(p) => Ok(p.additional_buffer_bytes()),
            Self::Aead(p, retained) => p
                .aad()
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(retained))
                .and_then(|n| n.checked_add(if padded_ietf(p) { 84 } else { 0 }))
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::AeadParameterAccountingOverflow,
                ))),
        }
    }
    pub(super) fn from_record(d: record::Descriptor, p: &record::Parameters<'a>) -> Result<Self> {
        if let Some(extension) = p.cipher_extension {
            return super::extension::Source::from_record(d, extension).map(Self::Extension);
        }
        let nonce = p
            .nonce
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherRecordIvAbsent,
            )))?;
        if !is_aead(d.mechanism) {
            if p.aad.is_some() || p.tag_bits != 0 {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::NonAeadRecordAuthenticationFields,
                )));
            }
            return PlainFrame::block_record_request_with_options(
                d.mechanism,
                nonce,
                p.counter_bits,
                d.cipher_options,
            )
            .map(Self::Plain);
        }
        if p.counter_bits.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::AeadRecordCounterField,
            )));
        }
        let aad = p
            .aad
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::AeadRecordAadAbsent,
            )))?;
        let value = match (d.mechanism, d.cipher_options) {
            (kind, Some(CipherOptions::GcmWithoutIvBits)) if kind == CKM_AES_GCM as u64 => {
                Aead::GcmWithoutIvBits {
                    iv: nonce,
                    aad,
                    tag_bits: u64::from(p.tag_bits),
                }
            }
            (kind, None) if kind == CKM_AES_GCM as u64 => Aead::Gcm {
                iv: nonce,
                aad,
                tag_bits: u64::from(p.tag_bits),
            },
            (kind, Some(CipherOptions::CcmDataLength { .. }))
                if kind == CKM_AES_CCM as u64 && p.tag_bits % 8 == 0 =>
            {
                Aead::Ccm {
                    nonce,
                    aad,
                    mac_length: u64::from(p.tag_bits / 8),
                }
            }
            (kind, Some(CipherOptions::ChaChaIetfBytes))
                if kind == CKM_CHACHA20_POLY1305 as u64 && p.tag_bits == 128 =>
            {
                Aead::ChaCha20IetfBytes {
                    nonce: nonce.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::CipherContinuation(
                            crate::CipherContinuationRejection::LegacyAeadNonceWidth,
                        ))
                    })?,
                    aad,
                }
            }
            (kind, None)
                if crate::symmetric::poly1305::is_stream_aead(kind) && p.tag_bits == 128 =>
            {
                Aead::Stream {
                    nonce: crate::StreamAeadNonce::from_record(kind, nonce)?,
                    aad,
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::AeadRecordParameterCombination,
                )))
            }
        };
        value.tag_bits()?;
        Ok(Self::Aead(value, 0))
    }
}
pub(crate) fn is_aead(kind: u64) -> bool {
    kind == CKM_AES_GCM as u64
        || kind == CKM_AES_CCM as u64
        || crate::symmetric::poly1305::is_stream_aead(kind)
}

// Preserve the legacy IETF allocation for both explicit native-unit contracts.
// Extra zeroed storage is not nonce data and is included in the prepaid graph.
fn padded_ietf(p: Aead<'_>) -> bool {
    matches!(
        p,
        Aead::ChaCha20IetfBytes { .. }
            | Aead::Stream {
                nonce: crate::StreamAeadNonce::ChaCha20Ietf(_),
                ..
            }
    )
}

enum Native {
    Gcm(Box<CK_GCM_PARAMS>),
    GcmWithoutIvBits(Box<GcmWithoutIvBits>),
    Ccm(Box<CK_CCM_PARAMS>),
    Stream(Box<CK_SALSA20_CHACHA20_POLY1305_PARAMS>),
}
impl Native {
    fn descriptor(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        match self {
            Self::GcmWithoutIvBits(p) => (
                (&mut **p as *mut GcmWithoutIvBits).cast(),
                std::mem::size_of::<GcmWithoutIvBits>() as CK_ULONG,
            ),
            Self::Gcm(p) => (
                (&mut **p as *mut CK_GCM_PARAMS).cast(),
                std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
            ),
            Self::Ccm(p) => (
                (&mut **p as *mut CK_CCM_PARAMS).cast(),
                std::mem::size_of::<CK_CCM_PARAMS>() as CK_ULONG,
            ),
            Self::Stream(p) => (
                (&mut **p as *mut CK_SALSA20_CHACHA20_POLY1305_PARAMS).cast(),
                std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>() as CK_ULONG,
            ),
        }
    }
}
pub(super) struct AeadFrame {
    mechanism: Box<CK_MECHANISM>,
    native: Native,
    iv: Buffer,
    expected_iv: Buffer,
    aad: Buffer,
    expected_aad: Buffer,
    kind: CK_MECHANISM_TYPE,
    tag_bits: u64,
    data_length: CK_ULONG,
    nonce_length: CK_ULONG,
    bytes_encoding: bool,
    retained: usize,
    retention: Credit,
}
pub(super) enum Frame {
    Extension(super::extension::Frame),
    Plain(PlainFrame),
    Aead(AeadFrame),
}
impl Frame {
    pub(super) fn kind(&self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Extension(frame) => frame.metadata.mechanism,
            Self::Plain(p) => p.kind(),
            Self::Aead(p) => p.kind,
        }
    }

    pub(super) fn mechanism_mut(&mut self) -> &mut CK_MECHANISM {
        match self {
            Self::Extension(frame) => &mut frame.mechanism,
            Self::Plain(p) => &mut p.mechanism,
            Self::Aead(p) => &mut p.mechanism,
        }
    }

    pub(super) fn expected_iv_bytes(&self) -> &[u8] {
        match self {
            Self::Extension(_) => &[],
            Self::Plain(frame) => frame.expected_iv.as_slice(),
            Self::Aead(frame) => frame.expected_iv.as_slice(),
        }
    }
    pub(super) fn aad(&self) -> Option<&[u8]> {
        match self {
            Self::Extension(_) => None,
            Self::Plain(_) => None,
            Self::Aead(p) => Some(p.expected_aad.as_slice()),
        }
    }
    pub(super) fn tag_bits(&self) -> u64 {
        match self {
            Self::Extension(_) => 0,
            Self::Plain(_) => 0,
            Self::Aead(p) => p.tag_bits,
        }
    }
    pub(super) fn counter_bits(&self) -> Option<u64> {
        match self {
            Self::Extension(_) => None,
            Self::Plain(p) => p.counter_bits(),
            Self::Aead(_) => None,
        }
    }
    pub(super) fn options(&self) -> Option<CipherOptions> {
        match self {
            Self::Extension(_) => None,
            Self::Plain(p) => p.options(),
            Self::Aead(p) if matches!(&p.native, Native::GcmWithoutIvBits(_)) => {
                Some(CipherOptions::GcmWithoutIvBits)
            }
            Self::Aead(p) if matches!(&p.native, Native::Ccm(_)) => {
                Some(CipherOptions::CcmDataLength {
                    bytes: p.data_length as u64,
                })
            }
            Self::Aead(p) if p.bytes_encoding => Some(CipherOptions::ChaChaIetfBytes),
            Self::Aead(_) => None,
        }
    }
    pub(super) fn generated_iv(&self) -> Result<Option<[u8; 24]>> {
        match self {
            Self::Extension(_) => Ok(None),
            Self::Plain(p) => p.generated_iv(),
            Self::Aead(_) => Ok(None),
        }
    }
    pub(super) fn restore_generated_iv(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Extension(_) if bytes.is_empty() => Ok(()),
            Self::Extension(_) => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ExtensionGraphHasNoSeparateNonceField,
            ))),
            Self::Plain(p) => p.restore_generated_iv(bytes),
            Self::Aead(p) if bytes == p.expected_iv.as_slice() => Ok(()),
            Self::Aead(_) => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::AeadRestoredNonceMismatch,
            ))),
        }
    }
    pub(super) fn selection(&self) -> Result<Selection<'_>> {
        match self {
            Self::Extension(frame) => frame.source().map(Selection::Extension),
            Self::Plain(p) => p.block_request().map(Selection::Plain),
            Self::Aead(p) => {
                let nonce = p.expected_iv.as_slice();
                let aad = p.expected_aad.as_slice();
                let request = match &p.native {
                    Native::GcmWithoutIvBits(_) => Aead::GcmWithoutIvBits {
                        iv: nonce,
                        aad,
                        tag_bits: u64::from(p.tag_bits),
                    },
                    Native::Gcm(_) => Aead::Gcm {
                        iv: nonce,
                        aad,
                        tag_bits: u64::from(p.tag_bits),
                    },
                    Native::Ccm(_) => Aead::Ccm {
                        nonce,
                        aad,
                        mac_length: u64::from(p.tag_bits / 8),
                    },
                    Native::Stream(_) if p.bytes_encoding => Aead::ChaCha20IetfBytes {
                        nonce: nonce.try_into().map_err(|_| {
                            Error::Rejected(crate::RejectionReason::CipherContinuation(
                                crate::CipherContinuationRejection::AeadRetainedNonceWidth,
                            ))
                        })?,
                        aad,
                    },
                    Native::Stream(_) => Aead::Stream {
                        nonce: crate::StreamAeadNonce::from_record(p.kind as u64, nonce)?,
                        aad,
                    },
                };
                Ok(Selection::Aead(request, p.retained))
            }
        }
    }

    pub(super) fn validate(&mut self) -> Result<()> {
        match self {
            Self::Extension(frame) => frame.validate_for_call(),
            Self::Plain(p) => p.validate(),
            Self::Aead(p) => p.validate(),
        }
    }
    pub(super) fn validate_after_call(&mut self) -> Result<()> {
        match self {
            Self::Extension(frame) => frame.validate(),
            Self::Plain(p) => p.validate_after_call(),
            Self::Aead(p) => p.validate(),
        }
    }
    pub(super) fn finish_parameters(&mut self) -> Result<()> {
        match self {
            Self::Extension(frame) => frame.finish(),
            Self::Plain(_) | Self::Aead(_) => Ok(()),
        }
    }
    pub(super) fn publish(&mut self, output: Buffer, decrypt: bool) -> Result<OperationProgress> {
        match self {
            Self::Extension(frame) if decrypt => frame
                .publish(output)
                .map(OperationProgress::ExtensionDecrypted),
            Self::Extension(frame) => frame
                .publish(output)
                .map(OperationProgress::ExtensionEncrypted),
            Self::Plain(p) if !decrypt => Ok(OperationProgress::CipherEncrypted(
                crate::Ciphertext::from_parts(output, p.generated_iv()?),
            )),
            Self::Plain(_) => Ok(OperationProgress::CipherDecrypted(
                crate::UnauthenticatedCipherPlaintext::from_buffer(output),
            )),
            Self::Aead(p) if decrypt => Ok(OperationProgress::ClassicAeadDecrypted(
                crate::AeadPlaintext::from_classic(
                    output,
                    p.tag_bits,
                    p.expected_iv.take(),
                    p.retention.split(p.retained)?,
                ),
            )),
            Self::Aead(p) => {
                // All native calls have terminated. Transfer the nonce allocation
                // and its credit rather than allocating under the session guard.
                Ok(OperationProgress::ClassicAeadEncrypted(
                    crate::ClassicAeadCiphertext {
                        bytes: output,
                        nonce: p.expected_iv.take(),
                        mechanism: p.kind as u64,
                        tag_bits: u64::from(p.tag_bits),
                        retention: p.retention.split(p.retained)?,
                    },
                ))
            }
        }
    }
}
impl AeadFrame {
    fn validate(&mut self) -> Result<()> {
        let (pointer, length) = self.native.descriptor();
        let iv = self.iv.as_mut().as_mut_ptr();
        let aad = if self.aad.as_slice().is_empty() {
            std::ptr::null_mut()
        } else {
            self.aad.as_mut().as_mut_ptr()
        };
        let aad_len = bounds::ck_length(self.expected_aad.as_slice().len())?;
        let fields = match &self.native {
            Native::GcmWithoutIvBits(p) => {
                p.pIv == iv
                    && p.ulIvLen == self.nonce_length
                    && p.pAAD == aad
                    && p.ulAADLen == aad_len
                    && p.ulTagBits == self.tag_bits as CK_ULONG
            }
            Native::Gcm(p) => {
                p.pIv == iv
                    && p.ulIvLen == self.nonce_length
                    && p.ulIvBits == bounds::gcm_iv_bits(self.nonce_length)
                    && p.pAAD == aad
                    && p.ulAADLen == aad_len
                    && p.ulTagBits == self.tag_bits as CK_ULONG
            }
            Native::Ccm(p) => {
                p.pNonce == iv
                    && p.ulNonceLen == self.nonce_length
                    && p.ulDataLen == self.data_length
                    && p.pAAD == aad
                    && p.ulAADLen == aad_len
                    && p.ulMACLen == (self.tag_bits / 8) as CK_ULONG
            }
            Native::Stream(p) => {
                p.pNonce == iv
                    && p.ulNonceLen == self.nonce_length
                    && p.pAAD == aad
                    && p.ulAADLen == aad_len
            }
        };
        let nonce = self.expected_iv.as_slice();
        if !fields
            || self.mechanism.mechanism != self.kind
            || self.mechanism.pParameter != pointer
            || self.mechanism.ulParameterLen != length
            || self.iv.as_slice().get(..nonce.len()) != Some(nonce)
            || self.iv.as_slice()[nonce.len()..].iter().any(|b| *b != 0)
            || self.aad.as_slice() != self.expected_aad.as_slice()
        {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ClassicAeadParameterMutation,
            )));
        }
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for AeadFrame {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.iv.retain_credits(retained)?;
        self.expected_iv.retain_credits(retained)?;
        self.aad.retain_credits(retained)?;
        self.expected_aad.retain_credits(retained)?;
        self.retention.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for Frame {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::Extension(frame) => frame.retain_credits(retained),
            Self::Plain(frame) => frame.retain_credits(retained),
            Self::Aead(frame) => frame.retain_credits(retained),
        }
    }
}
