// SPDX-License-Identifier: Apache-2.0
//! Typed selections and native descriptors for the owned AEAD message sequence.
use super::record;
use crate::{bounds, Error, Result};
use crate::{AeadNonce, CcmNonce, MessageInitField};
use fe11_sys::{
    CKG_NO_GENERATE, CKM_AES_CCM, CKM_AES_GCM, CKM_CHACHA20_POLY1305, CKM_SALSA20_POLY1305,
    CK_BYTE_PTR, CK_CCM_MESSAGE_PARAMS, CK_GCM_MESSAGE_PARAMS, CK_GENERATOR_FUNCTION,
    CK_MECHANISM_TYPE, CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS, CK_ULONG, CK_VOID_PTR,
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CipherKind {
    Gcm,
    Ccm,
    ChaChaPoly1305,
    SalsaPoly1305,
}
impl CipherKind {
    pub(super) fn stream(self) -> bool {
        matches!(self, Self::ChaChaPoly1305 | Self::SalsaPoly1305)
    }
    pub(super) fn from_stream(algorithm: crate::StreamAeadAlgorithm) -> Self {
        match algorithm {
            crate::StreamAeadAlgorithm::ChaCha20 => Self::ChaChaPoly1305,
            crate::StreamAeadAlgorithm::Salsa20 => Self::SalsaPoly1305,
        }
    }
    pub(super) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Gcm => CKM_AES_GCM,
            Self::Ccm => CKM_AES_CCM,
            Self::ChaChaPoly1305 => CKM_CHACHA20_POLY1305,
            Self::SalsaPoly1305 => CKM_SALSA20_POLY1305,
        }
    }
    pub(super) fn from_mechanism(mechanism: u64) -> Result<Self> {
        if mechanism == CKM_AES_GCM as u64 {
            Ok(Self::Gcm)
        } else if mechanism == CKM_AES_CCM as u64 {
            Ok(Self::Ccm)
        } else if mechanism == CKM_CHACHA20_POLY1305 as u64 {
            Ok(Self::ChaChaPoly1305)
        } else if mechanism == CKM_SALSA20_POLY1305 as u64 {
            Ok(Self::SalsaPoly1305)
        } else {
            Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageMechanism,
            )))
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Selection {
    Stream(crate::StreamAeadNonce),
    Gcm(AeadNonce),
    Ccm { nonce: CcmNonce, mac_length: u64 },
}
impl Selection {
    pub(super) fn kind(&self) -> CipherKind {
        match self {
            Self::Stream(nonce) => CipherKind::from_stream(nonce.algorithm()),
            Self::Gcm(_) => CipherKind::Gcm,
            Self::Ccm { .. } => CipherKind::Ccm,
        }
    }
    pub(super) fn iv(&self) -> &[u8] {
        match self {
            Self::Stream(nonce) => nonce.as_bytes(),
            Self::Gcm(n) => n.iv(),
            Self::Ccm { nonce, .. } => &nonce.bytes,
        }
    }
    pub(super) fn generator(&self) -> Result<CK_GENERATOR_FUNCTION> {
        match self {
            Self::Stream(_) => Ok(CKG_NO_GENERATE),
            Self::Gcm(n) => n.generator(),
            Self::Ccm { nonce, .. } => {
                CK_GENERATOR_FUNCTION::try_from(nonce.generator).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::CcmGeneratorAbiWidth,
                    ))
                })
            }
        }
    }
    pub(super) fn fixed_bits(&self) -> u64 {
        match self {
            Self::Stream(_) => 0,
            Self::Gcm(n) => n.fixed_bits(),
            Self::Ccm { nonce, .. } => nonce.fixed_bits,
        }
    }
    pub(super) fn tag_bits(&self) -> u64 {
        match self {
            Self::Stream(_) => 128,
            Self::Gcm(n) => n.tag_bits(),
            Self::Ccm { mac_length, .. } => mac_length * 8,
        }
    }
    pub(super) fn tag_bytes(&self) -> Result<usize> {
        match self {
            Self::Stream(_) => Ok(16),
            Self::Gcm(n) => n.tag_bytes(),
            Self::Ccm { mac_length, .. }
                if matches!(*mac_length, 4 | 6 | 8 | 10 | 12 | 14 | 16) =>
            {
                Ok(*mac_length as usize)
            }
            Self::Ccm { .. } => Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::CcmMacLength,
            ))),
        }
    }
    pub(super) fn generated(&self) -> bool {
        match self {
            Self::Stream(_) => false,
            Self::Gcm(n) => n.generated(),
            Self::Ccm { nonce, .. } => nonce.generator != CKG_NO_GENERATE as u64,
        }
    }
    pub(super) fn retained_bytes(&self) -> usize {
        match self {
            Self::Stream(_) => 0,
            _ => self.iv().len(),
        }
    }
    pub(super) fn validate(&self, aad: usize, data: usize, decrypt: bool) -> Result<()> {
        match self {
            Self::Stream(_) => {
                bounds::ck_length(aad)?;
                Ok(())
            }
            Self::Gcm(n) if decrypt => n.validate_gcm_message_decrypt(aad),
            Self::Gcm(n) => n.validate_gcm_message_encrypt(aad),
            Self::Ccm { nonce, mac_length } => {
                crate::symmetric::validate_ccm_message(nonce, aad, *mac_length, data, decrypt)
            }
        }
    }
    pub(super) fn fixed_bits_unchanged(&self, actual: &[u8]) -> bool {
        match self {
            Self::Stream(nonce) => nonce.as_bytes() == actual,
            Self::Gcm(n) => n.fixed_bits_unchanged(actual),
            Self::Ccm { nonce, .. } => {
                if actual.len() != nonce.bytes.len() || nonce.fixed_bits > actual.len() as u64 * 8 {
                    return false;
                }
                let whole = nonce.fixed_bits as usize / 8;
                let part = nonce.fixed_bits as usize % 8;
                actual[..whole] == nonce.bytes[..whole]
                    && (part == 0
                        || (actual[whole] ^ nonce.bytes[whole]) & (0xffu8 << (8 - part)) == 0)
            }
        }
    }
    fn scalars(&self) -> Result<Scalars> {
        Ok(Scalars {
            kind: self.kind(),
            iv_len: self.iv().len(),
            generator: self.generator()? as u64,
            fixed_bits: self.fixed_bits(),
            tag_bits: self.tag_bits(),
        })
    }
    pub(super) fn fixed_scalars(&self, next: &Self) -> Result<()> {
        self.scalars()?.compare(next.scalars()?)
    }
}
#[derive(Clone, Copy)]
struct Scalars {
    kind: CipherKind,
    iv_len: usize,
    generator: u64,
    fixed_bits: u64,
    tag_bits: u64,
}
impl Scalars {
    fn compare(self, next: Self) -> Result<()> {
        if self.kind != next.kind {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::MixedAeadMessageMechanisms,
            )));
        }
        let ccm = self.kind == CipherKind::Ccm;
        let changed = if self.iv_len != next.iv_len {
            Some(if ccm {
                MessageInitField::NonceLength
            } else {
                MessageInitField::IvLength
            })
        } else if self.fixed_bits != next.fixed_bits {
            Some(if ccm {
                MessageInitField::NonceFixedBits
            } else {
                MessageInitField::IvFixedBits
            })
        } else if self.generator != next.generator {
            Some(if ccm {
                MessageInitField::NonceGenerator
            } else {
                MessageInitField::IvGenerator
            })
        } else if self.tag_bits != next.tag_bits {
            Some(if ccm {
                MessageInitField::MacLength
            } else {
                MessageInitField::TagBits
            })
        } else {
            None
        };
        match changed {
            Some(field) => Err(Error::InitParameterChangeBeforeEffect { field }),
            None => Ok(()),
        }
    }
}
/// Borrowed archive parameters are checked and sized without retaining an Arc.
/// Materialization is called only after admission of the complete destination.
pub(super) struct RecordSelection<'a> {
    scalars: Scalars,
    iv: &'a [u8],
}
impl<'a> RecordSelection<'a> {
    pub(super) fn new(kind: CipherKind, parameters: &record::Parameters<'a>) -> Result<Self> {
        if kind.stream()
            && (parameters.tag_bits != 128
                || parameters.iv_generator != Some(0)
                || parameters.iv_fixed_bits != Some(0))
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::StreamAeadRecordScalarSelection,
            )));
        }
        let iv = parameters
            .iv_initial
            .ok_or(Error::Rejected(if kind.stream() {
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::StreamAeadInitialNonceAbsent,
                )
            } else {
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadRecordedInitialNonce,
                )
            }))?;
        if kind.stream() {
            crate::StreamAeadNonce::from_record(kind.mechanism() as u64, iv)?;
        }
        if kind == CipherKind::Ccm && parameters.tag_bits % 8 != 0 {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::CcmRecordedMacAlignment,
            )));
        }
        Ok(Self {
            scalars: Scalars {
                kind,
                iv_len: iv.len(),
                generator: parameters.iv_generator.ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadRecordedGenerator,
                    ),
                ))?,
                fixed_bits: parameters.iv_fixed_bits.ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadRecordedFixedBits,
                    ),
                ))?,
                tag_bits: parameters.tag_bits as u64,
            },
            iv,
        })
    }
    pub(super) fn iv(&self) -> &'a [u8] {
        self.iv
    }
    pub(super) fn tag_bits(&self) -> u64 {
        self.scalars.tag_bits
    }
    pub(super) fn tag_bytes(&self) -> Result<usize> {
        match self.scalars.kind {
            CipherKind::Gcm if self.tag_bits() <= 128 => Ok(self.tag_bits().div_ceil(8) as usize),
            CipherKind::Gcm => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmTagBitLength,
                ),
            )),
            CipherKind::Ccm if matches!(self.tag_bits() / 8, 4 | 6 | 8 | 10 | 12 | 14 | 16) => {
                Ok((self.tag_bits() / 8) as usize)
            }
            CipherKind::Ccm => Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::CcmMacLength,
            ))),
            _ => Ok(16),
        }
    }
    pub(super) fn retained_bytes(&self) -> usize {
        if self.scalars.kind.stream() {
            0
        } else {
            self.iv.len()
        }
    }
    pub(super) fn generated(&self) -> bool {
        self.scalars.generator != 0
    }
    pub(super) fn validate(&self, aad: usize, data: usize, decrypt: bool) -> Result<()> {
        match self.scalars.kind {
            CipherKind::Gcm => {
                AeadNonce::validate_gcm_dimensions(
                    crate::symmetric::AeadParameterLayout::Message,
                    self.iv.len(),
                    aad,
                    self.scalars.fixed_bits,
                    self.scalars.generator,
                    self.tag_bits(),
                )?;
                if !decrypt && self.scalars.fixed_bits > self.iv.len() as u64 * 8 {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::GcmNormativeParameterBounds,
                        ),
                    ));
                }
                Ok(())
            }
            CipherKind::Ccm => crate::symmetric::validate_ccm_fields(
                crate::symmetric::AeadParameterLayout::Message,
                self.iv.len(),
                self.scalars.generator,
                self.scalars.fixed_bits,
                aad,
                self.tag_bits() / 8,
                data,
                decrypt,
            ),
            _ => {
                bounds::ck_length(aad)?;
                Ok(())
            }
        }
    }
    pub(super) fn fixed_scalars(&self, next: &Self) -> Result<()> {
        self.scalars.compare(next.scalars)
    }
    pub(super) fn materialize(&self) -> Result<Selection> {
        Ok(match self.scalars.kind {
            CipherKind::Gcm => Selection::Gcm(AeadNonce::Gcm {
                iv: Arc::from(self.iv),
                generator: self.scalars.generator,
                fixed_bits: self.scalars.fixed_bits,
                tag_bits: self.tag_bits(),
            }),
            CipherKind::Ccm => Selection::Ccm {
                nonce: CcmNonce {
                    bytes: Arc::from(self.iv),
                    generator: self.scalars.generator,
                    fixed_bits: self.scalars.fixed_bits,
                },
                mac_length: self.tag_bits() / 8,
            },
            kind => Selection::Stream(crate::StreamAeadNonce::from_record(
                kind.mechanism() as u64,
                self.iv,
            )?),
        })
    }
}
// The native pointer always addresses the selected member, never the Rust enum.
// Both the enum allocation and its variant remain stable throughout the sequence.
pub(super) enum NativeParameters {
    Stream(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS),
    Gcm(CK_GCM_MESSAGE_PARAMS),
    Ccm(CK_CCM_MESSAGE_PARAMS),
}
impl NativeParameters {
    pub(super) fn new(
        selection: &Selection,
        data: usize,
        nonce: CK_BYTE_PTR,
        tag: CK_BYTE_PTR,
    ) -> Result<Self> {
        let length = bounds::ck_length(selection.iv().len())?;
        let fixed = CK_ULONG::try_from(selection.fixed_bits()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadFixedBitsAbiWidth,
            ))
        })?;
        let generator = selection.generator()?;
        let mac_bytes = bounds::ck_length(selection.tag_bytes()?)?;
        match selection {
            Selection::Stream(selection) => {
                Ok(Self::Stream(CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
                    pNonce: nonce,
                    ulNonceLen: selection.native_bits(),
                    pTag: tag,
                }))
            }
            Selection::Gcm(_) => Ok(Self::Gcm(CK_GCM_MESSAGE_PARAMS {
                pIv: nonce,
                ulIvLen: length,
                ulIvFixedBits: fixed,
                ivGenerator: generator,
                pTag: tag,
                ulTagBits: selection.tag_bits() as CK_ULONG,
            })),
            Selection::Ccm { .. } => Ok(Self::Ccm(CK_CCM_MESSAGE_PARAMS {
                ulDataLen: bounds::ck_length(data)?,
                pNonce: nonce,
                ulNonceLen: length,
                ulNonceFixedBits: fixed,
                nonceGenerator: generator,
                pMAC: tag,
                ulMACLen: mac_bytes,
            })),
        }
    }
    pub(super) fn pointer(&self) -> CK_VOID_PTR {
        match self {
            Self::Stream(p) => (p as *const CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)
                .cast_mut()
                .cast(),
            Self::Gcm(p) => (p as *const CK_GCM_MESSAGE_PARAMS).cast_mut().cast(),
            Self::Ccm(p) => (p as *const CK_CCM_MESSAGE_PARAMS).cast_mut().cast(),
        }
    }
    pub(super) fn pointer_mut(&mut self) -> CK_VOID_PTR {
        match self {
            Self::Stream(p) => (p as *mut CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS).cast(),
            Self::Gcm(p) => (p as *mut CK_GCM_MESSAGE_PARAMS).cast(),
            Self::Ccm(p) => (p as *mut CK_CCM_MESSAGE_PARAMS).cast(),
        }
    }
    pub(super) fn size(&self) -> CK_ULONG {
        match self {
            Self::Stream(_) => {
                std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS>() as CK_ULONG
            }
            Self::Gcm(_) => std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG,
            Self::Ccm(_) => std::mem::size_of::<CK_CCM_MESSAGE_PARAMS>() as CK_ULONG,
        }
    }
    pub(super) fn bind(&mut self, nonce: CK_BYTE_PTR, tag: CK_BYTE_PTR) {
        match self {
            Self::Stream(p) => {
                p.pNonce = nonce;
                p.pTag = tag;
            }
            Self::Gcm(p) => {
                p.pIv = nonce;
                p.pTag = tag;
            }
            Self::Ccm(p) => {
                p.pNonce = nonce;
                p.pMAC = tag;
            }
        }
    }
    pub(super) fn set_data_length(&mut self, data: usize) -> Result<()> {
        if let Self::Ccm(p) = self {
            p.ulDataLen = bounds::ck_length(data)?;
        }
        Ok(())
    }
    pub(super) fn unchanged(
        &self,
        selection: &Selection,
        data: usize,
        nonce: CK_BYTE_PTR,
        tag: CK_BYTE_PTR,
    ) -> Result<bool> {
        let expected = Self::new(selection, data, nonce, tag)?;
        Ok(match (self, expected) {
            (Self::Stream(a), Self::Stream(b)) => {
                a.pNonce == b.pNonce && a.ulNonceLen == b.ulNonceLen && a.pTag == b.pTag
            }
            (Self::Gcm(a), Self::Gcm(b)) => {
                a.pIv == b.pIv
                    && a.ulIvLen == b.ulIvLen
                    && a.ulIvFixedBits == b.ulIvFixedBits
                    && a.ivGenerator == b.ivGenerator
                    && a.pTag == b.pTag
                    && a.ulTagBits == b.ulTagBits
            }
            (Self::Ccm(a), Self::Ccm(b)) => {
                a.ulDataLen == b.ulDataLen
                    && a.pNonce == b.pNonce
                    && a.ulNonceLen == b.ulNonceLen
                    && a.ulNonceFixedBits == b.ulNonceFixedBits
                    && a.nonceGenerator == b.nonceGenerator
                    && a.pMAC == b.pMAC
                    && a.ulMACLen == b.ulMACLen
            }
            _ => false,
        })
    }
}
