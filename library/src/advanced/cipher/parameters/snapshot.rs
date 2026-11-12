// SPDX-License-Identifier: Apache-2.0
//! Stable classic-AEAD parameter destinations. Native pointer values are always
//! rebuilt from destination allocations; only validated scalar selections travel.
use super::{padded_ietf, Aead, AeadFrame, Frame, GcmWithoutIvBits, Native, Selection};
use crate::{
    bounds,
    symmetric::memory::{Buffer, Credit},
    Error, Result,
};
use fe11_sys::{
    CK_CCM_PARAMS, CK_GCM_PARAMS, CK_MECHANISM, CK_MECHANISM_TYPE,
    CK_SALSA20_CHACHA20_POLY1305_PARAMS, CK_ULONG,
};

#[derive(Clone, Copy)]
enum Layout {
    Gcm,
    GcmWithoutIvBits,
    Ccm,
    Stream,
}
pub(in crate::advanced) struct AeadSnapshot {
    layout: Layout,
    kind: CK_MECHANISM_TYPE,
    iv: usize,
    expected_iv: usize,
    aad: usize,
    tag_bits: u64,
    data_length: CK_ULONG,
    nonce_length: CK_ULONG,
    bytes_encoding: bool,
    retained: usize,
    retention: Credit,
}
pub(in crate::advanced) enum Snapshot<'a> {
    Extension(super::super::extension::Source<'a>),
    Plain(crate::symmetric::cipher::snapshot::Snapshot),
    Aead(AeadSnapshot),
}
impl Frame {
    pub(in crate::advanced::cipher) fn fill_request(
        &mut self,
        selection: Selection<'_>,
    ) -> Result<()> {
        match (self, selection) {
            (Frame::Extension(frame), Selection::Extension(source)) => frame.fill_request(source),
            (Frame::Plain(frame), Selection::Plain(selection)) => {
                frame.fill_block_request(selection)
            }
            (Frame::Aead(frame), Selection::Aead(selection, _)) => {
                if frame.kind as u64 != selection.mechanism_number() {
                    return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::AeadSnapshotParameterShapeChanged,
                    )));
                }
                if padded_ietf(selection) {
                    let nonce = selection.nonce().try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::CipherContinuation(
                            crate::CipherContinuationRejection::IetfNonceWidth,
                        ))
                    })?;
                    copy_request(
                        &mut frame.iv,
                        &crate::symmetric::native_nonce_storage(nonce),
                    )?;
                } else {
                    copy_request(&mut frame.iv, selection.nonce())?;
                }
                copy_request(&mut frame.expected_iv, selection.nonce())?;
                copy_request(&mut frame.aad, selection.aad())?;
                copy_request(&mut frame.expected_aad, selection.aad())?;
                frame.validate()
            }
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotParameterFamilyChanged,
            ))),
        }
    }
    pub(in crate::advanced) fn snapshot_bytes(&self) -> Result<usize> {
        match self {
            Self::Extension(frame) => frame.graph()?.snapshot_allocation_bytes(),
            Self::Plain(frame) => frame.snapshot_bytes(),
            Self::Aead(frame) => frame
                .iv
                .capacity()
                .checked_add(frame.expected_iv.capacity())
                .and_then(|n| n.checked_add(frame.aad.capacity()))
                .and_then(|n| n.checked_add(frame.expected_aad.capacity()))
                .and_then(|n| n.checked_add(frame.retained))
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotAccounting,
                ))),
        }
    }
    pub(in crate::advanced) fn snapshot_native_bytes(&self) -> Result<usize> {
        Ok(match self {
            Self::Extension(_) => 0,
            Self::Plain(frame) => frame.snapshot_native_bytes()?,
            Self::Aead(frame) => match frame.native {
                Native::Gcm(_) => std::mem::size_of::<CK_GCM_PARAMS>(),
                Native::GcmWithoutIvBits(_) => std::mem::size_of::<GcmWithoutIvBits>(),
                Native::Ccm(_) => std::mem::size_of::<CK_CCM_PARAMS>(),
                Native::Stream(_) => std::mem::size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>(),
            },
        })
    }
    pub(in crate::advanced) fn prepare_snapshot_parameters(
        &self,
        prepaid: &mut Credit,
    ) -> Result<Snapshot<'static>> {
        Ok(match self {
            Self::Extension(_) => {
                return Err(Error::Rejected(
                    crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::ExtensionCipherRequiresGraphSnapshotPreparation),
                ))
            }
            Self::Plain(frame) => Snapshot::Plain(frame.prepare_snapshot_parameters(prepaid)?),
            Self::Aead(frame) => Snapshot::Aead(AeadSnapshot {
                layout: match frame.native {
                    Native::Gcm(_) => Layout::Gcm,
                    Native::GcmWithoutIvBits(_) => Layout::GcmWithoutIvBits,
                    Native::Ccm(_) => Layout::Ccm,
                    Native::Stream(_) => Layout::Stream,
                },
                kind: frame.kind,
                iv: frame.iv.capacity(),
                expected_iv: frame.expected_iv.capacity(),
                aad: frame.expected_aad.capacity(),
                tag_bits: frame.tag_bits,
                data_length: frame.data_length,
                nonce_length: frame.nonce_length,
                bytes_encoding: frame.bytes_encoding,
                retained: frame.retained,
                retention: prepaid.split(frame.retained)?,
            }),
        })
    }
    pub(in crate::advanced) fn fill_snapshot(&mut self, source: &Self) -> Result<()> {
        match (self, source) {
            (Self::Extension(target), Self::Extension(source)) => {
                // The graph was copied at the previous revision-checked capture
                // boundary. Rebinding checks identity without allocating under guards.
                source.validate_for_call()?;
                target.bind_contract(source.contract()?.clone())?;
                target.validate_for_call()
            }
            (Self::Plain(target), Self::Plain(source)) => target.fill_snapshot(source),
            (Self::Aead(target), Self::Aead(source)) => {
                if target.kind != source.kind {
                    return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::AeadSnapshotParameterShapeChanged,
                    )));
                }
                crate::advanced::continuation::copy(&mut target.iv, &source.iv)?;
                crate::advanced::continuation::copy(&mut target.expected_iv, &source.expected_iv)?;
                crate::advanced::continuation::copy(&mut target.aad, &source.aad)?;
                crate::advanced::continuation::copy(
                    &mut target.expected_aad,
                    &source.expected_aad,
                )?;
                target.validate()
            }
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotParameterFamilyChanged,
            ))),
        }
    }
}
impl<'a> Snapshot<'a> {
    pub(in crate::advanced::cipher) fn for_selection(
        selection: Selection<'a>,
        input: super::ParameterInput,
        decrypt: bool,
        prepaid: &mut Credit,
    ) -> Result<Self> {
        let (parameters, retained) = match selection {
            Selection::Extension(source) => return Ok(Self::Extension(source)),
            Selection::Plain(selection) => {
                return crate::symmetric::cipher::snapshot::Snapshot::for_block(selection, prepaid)
                    .map(Self::Plain)
            }
            Selection::Aead(parameters, retained) => (parameters, retained),
        };
        let data_length = match input {
            super::ParameterInput::Complete(input) => {
                let (_, output) = parameters.output_bounds(input, decrypt)?;
                if matches!(parameters, Aead::Ccm { .. }) {
                    bounds::ck_length(if decrypt { output } else { input })?
                } else {
                    0
                }
            }
            super::ParameterInput::Incremental { ccm_data_length } => {
                if matches!(parameters, Aead::Ccm { .. }) != ccm_data_length.is_some() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::CipherContinuation(crate::CipherContinuationRejection::CcmStreamFramingRequiresItsExactDataLength),
                    ));
                }
                let length = ccm_data_length
                    .map(|n| {
                        usize::try_from(n).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::CipherContinuation(
                                crate::CipherContinuationRejection::CcmDataLengthWidth,
                            ))
                        })
                    })
                    .transpose()?;
                parameters.validate_stream_parameters(length, decrypt)?;
                length.map(bounds::ck_length).transpose()?.unwrap_or(0)
            }
        };
        let nonce_length = match parameters {
            Aead::Stream { nonce, .. } => nonce.native_bits(),
            Aead::ChaCha20IetfBytes { .. } => {
                crate::ChaChaNonceLengthEncoding::BytesCompatibility.native_length()
            }
            _ => bounds::ck_length(parameters.nonce().len())?,
        };
        let layout = match parameters {
            Aead::Gcm { .. } => Layout::Gcm,
            Aead::GcmWithoutIvBits { .. } => Layout::GcmWithoutIvBits,
            Aead::Ccm { .. } => Layout::Ccm,
            _ => Layout::Stream,
        };
        Ok(Self::Aead(AeadSnapshot {
            layout,
            kind: CK_MECHANISM_TYPE::try_from(parameters.mechanism_number()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherMechanismWidth,
                ))
            })?,
            iv: if padded_ietf(parameters) {
                96
            } else {
                parameters.nonce().len()
            },
            expected_iv: parameters.nonce().len(),
            aad: parameters.aad().len(),
            tag_bits: parameters.tag_bits()?,
            data_length,
            nonce_length,
            bytes_encoding: matches!(parameters, Aead::ChaCha20IetfBytes { .. }),
            retained,
            retention: prepaid.split(retained)?,
        }))
    }
}

fn copy_request(destination: &mut Buffer, source: &[u8]) -> Result<()> {
    if destination.as_slice().len() != source.len() {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::AeadSnapshotParameterShapeChanged,
        )));
    }
    destination.as_mut().copy_from_slice(source);
    Ok(())
}
impl AeadSnapshot {
    fn from_buffers(
        self,
        mut iv: Buffer,
        expected_iv: Buffer,
        mut aad: Buffer,
        expected_aad: Buffer,
    ) -> Result<Frame> {
        let shape = self;
        let nonce = iv.as_mut().as_mut_ptr();
        let aad_pointer = if shape.aad == 0 {
            std::ptr::null_mut()
        } else {
            aad.as_mut().as_mut_ptr()
        };
        let aad_length = bounds::ck_length(shape.aad)?;
        let mut native = match shape.layout {
            Layout::Gcm => Native::Gcm(Box::new(CK_GCM_PARAMS {
                pIv: nonce,
                ulIvLen: shape.nonce_length,
                ulIvBits: bounds::gcm_iv_bits(shape.nonce_length),
                pAAD: aad_pointer,
                ulAADLen: aad_length,
                ulTagBits: shape.tag_bits as CK_ULONG,
            })),
            Layout::GcmWithoutIvBits => Native::GcmWithoutIvBits(Box::new(GcmWithoutIvBits {
                pIv: nonce,
                ulIvLen: shape.nonce_length,
                pAAD: aad_pointer,
                ulAADLen: aad_length,
                ulTagBits: shape.tag_bits as CK_ULONG,
            })),
            Layout::Ccm => Native::Ccm(Box::new(CK_CCM_PARAMS {
                ulDataLen: shape.data_length,
                pNonce: nonce,
                ulNonceLen: shape.nonce_length,
                pAAD: aad_pointer,
                ulAADLen: aad_length,
                ulMACLen: (shape.tag_bits / 8) as CK_ULONG,
            })),
            Layout::Stream => Native::Stream(Box::new(CK_SALSA20_CHACHA20_POLY1305_PARAMS {
                pNonce: nonce,
                ulNonceLen: shape.nonce_length,
                pAAD: aad_pointer,
                ulAADLen: aad_length,
            })),
        };
        let (pointer, length) = native.descriptor();
        Ok(Frame::Aead(AeadFrame {
            mechanism: Box::new(CK_MECHANISM {
                mechanism: shape.kind,
                pParameter: pointer,
                ulParameterLen: length,
            }),
            native,
            iv,
            expected_iv,
            aad,
            expected_aad,
            kind: shape.kind,
            tag_bits: shape.tag_bits,
            data_length: shape.data_length,
            nonce_length: shape.nonce_length,
            bytes_encoding: shape.bytes_encoding,
            retained: shape.retained,
            retention: shape.retention,
        }))
    }
}

pub(in crate::advanced) enum Storage<'a> {
    Extension(super::super::extension::Storage<'a>),
    Plain(crate::symmetric::cipher::snapshot::Storage),
    Aead {
        shape: AeadSnapshot,
        buffers: [crate::symmetric::memory::UnboundBuffer; 4],
    },
}
impl<'a> Snapshot<'a> {
    pub(in crate::advanced) fn allocate(self) -> Result<Storage<'a>> {
        use crate::symmetric::memory::UnboundBuffer;
        match self {
            Self::Extension(source) => {
                super::super::extension::Storage::allocate(source).map(Storage::Extension)
            }
            Self::Plain(shape) => Ok(Storage::Plain(shape.allocate()?)),
            Self::Aead(shape) => {
                let buffers = [
                    UnboundBuffer::allocate(shape.iv)?,
                    UnboundBuffer::allocate(shape.expected_iv)?,
                    UnboundBuffer::allocate(shape.aad)?,
                    UnboundBuffer::allocate(shape.aad)?,
                ];
                Ok(Storage::Aead { shape, buffers })
            }
        }
    }
}
impl Storage<'_> {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Extension(storage) => storage.allocated_bytes(),
            Self::Plain(storage) => storage.allocated_bytes(),
            Self::Aead { shape, buffers } => buffers
                .iter()
                .try_fold(shape.retained, |n, b| n.checked_add(b.allocated()))
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotAccounting,
                ))),
        }
    }
    pub(in crate::advanced::cipher) fn bind(self, prepaid: &mut Credit) -> Result<Frame> {
        match self {
            Self::Extension(storage) => storage.bind(prepaid).map(Frame::Extension),
            Self::Plain(storage) => storage.bind(prepaid).map(Frame::Plain),
            Self::Aead {
                shape,
                buffers: [iv, expected_iv, aad, expected_aad],
            } => shape.from_buffers(
                iv.bind(prepaid)?,
                expected_iv.bind(prepaid)?,
                aad.bind(prepaid)?,
                expected_aad.bind(prepaid)?,
            ),
        }
    }
}


