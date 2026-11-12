// SPDX-License-Identifier: Apache-2.0
//! Prepared parameter snapshots. Shared immutable nonce storage receives its
//! destination credit before the source guard can be released.
use super::{counter_width, CipherFrame, ClassicMode, DualCipher, FixedContract, Parameters};
use crate::{
    bounds,
    symmetric::{
        memory::{Buffer, Credit},
        stream::{StreamCipherParameters, StreamFrame},
        structured::{CipherOptions, RcCipherParameters, RcNative},
        token_iv::TokenIvCipher,
    },
    CipherParameters, Error, Result,
};
use fe11_sys::{
    CK_AES_CTR_PARAMS, CK_CAMELLIA_CTR_PARAMS, CK_GCM_PARAMS, CK_MECHANISM, CK_MECHANISM_TYPE,
    CK_ULONG, CK_VOID_PTR,
};

enum ParameterShape {
    Gcm(crate::AeadNonce),
    Classic(ClassicMode),
    Fixed(FixedContract),
    Gost28147,
    TokenIv {
        cipher: TokenIvCipher,
        generated: bool,
    },
    Stream(StreamCipherParameters),
    Rc {
        kind: CK_MECHANISM_TYPE,
        options: CipherOptions,
    },
    CamelliaCtr(u64),
    Ctr(u64),
}
pub(crate) struct Snapshot {
    kind: CK_MECHANISM_TYPE,
    parameters: ParameterShape,
    iv: usize,
    aad: usize,
    selection_credit: Credit,
}
impl CipherFrame {
    pub(crate) fn fill_dual_request(&mut self, request: &DualCipher<'_>) -> Result<()> {
        let (iv, aad) = dual_bytes(request);
        self.fill_record_bytes(super::mechanism(request) as u64, iv, aad)
    }
    /// Populate an admitted frame from an immutable record without rebuilding
    /// its retained parameter selection or allocating another IV owner.
    pub(crate) fn fill_record_bytes(&mut self, kind: u64, iv: &[u8], aad: &[u8]) -> Result<()> {
        if self.kind() as u64 != kind
            || self.iv.as_slice().len() != iv.len()
            || self.expected_iv.as_slice().len() != iv.len()
            || self.aad.as_slice().len() != aad.len()
            || self.expected_aad.as_slice().len() != aad.len()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CipherSnapshotParameterShapeChanged,
                ),
            ));
        }
        self.iv.as_mut().copy_from_slice(iv);
        self.expected_iv.as_mut().copy_from_slice(iv);
        self.aad.as_mut().copy_from_slice(aad);
        self.expected_aad.as_mut().copy_from_slice(aad);
        self.fill_native_iv()
    }
    pub(crate) fn fill_block_request(&mut self, selection: CipherParameters<'_>) -> Result<()> {
        if self.kind() as u64 != selection.mechanism_number()
            || self.iv.as_slice().len() != selection.iv_bytes().len()
            || self.expected_iv.as_slice().len() != selection.iv_bytes().len()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CipherSnapshotParameterShapeChanged,
                ),
            ));
        }
        self.iv.as_mut().copy_from_slice(selection.iv_bytes());
        self.expected_iv
            .as_mut()
            .copy_from_slice(selection.iv_bytes());
        self.fill_native_iv()
    }
    pub(crate) fn snapshot_native_bytes(&self) -> Result<usize> {
        Ok(match self.parameters {
            Parameters::Gcm { .. } => std::mem::size_of::<CK_GCM_PARAMS>(),
            _ => Self::block_parameter_bytes(self.block_request()?),
        })
    }
    /// Buffer and retained-selection bytes only. The enclosing frame accounts
    /// for native descriptor boxes, exactly as for its normal constructor.
    pub(crate) fn snapshot_bytes(&self) -> Result<usize> {
        let additional = match &self.parameters {
            Parameters::Gcm { selection, .. } => selection.retained_bytes(),
            Parameters::Stream(stream) => stream.counter().bytes().len(),
            _ => 0,
        };
        self.expected_iv
            .capacity()
            .checked_mul(2)
            .and_then(|n| n.checked_add(self.aad.capacity()))
            .and_then(|n| n.checked_add(self.expected_aad.capacity()))
            .and_then(|n| n.checked_add(additional))
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotAccounting,
            )))
    }
    /// Call only after the complete capture graph has been reserved. In
    /// particular, cloning a GCM selection must not retain its Arc payload
    /// across a resource wait without the destination's selection credit.
    pub(crate) fn prepare_snapshot_parameters(&self, prepaid: &mut Credit) -> Result<Snapshot> {
        let retained = self.selection().map_or(0, crate::AeadNonce::retained_bytes);
        let selection_credit = prepaid.split(retained)?;
        let parameters = match &self.parameters {
            Parameters::Gcm { selection, .. } => ParameterShape::Gcm(selection.clone()),
            Parameters::Classic(mode) => ParameterShape::Classic(*mode),
            Parameters::Fixed(contract) => ParameterShape::Fixed(*contract),
            Parameters::Gost28147 => ParameterShape::Gost28147,
            Parameters::TokenIv { cipher, generated } => ParameterShape::TokenIv {
                cipher: *cipher,
                generated: *generated,
            },
            Parameters::Stream(_) => match self.block_request()? {
                CipherParameters::Stream(selection) => ParameterShape::Stream(selection),
                _ => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::StreamSnapshotSelection,
                        ),
                    ))
                }
            },
            Parameters::Rc { kind, options, .. } => ParameterShape::Rc {
                kind: *kind,
                options: *options,
            },
            Parameters::CamelliaCtr { counter_bits, .. } => {
                ParameterShape::CamelliaCtr(*counter_bits)
            }
            Parameters::Ctr { counter_bits, .. } => ParameterShape::Ctr(*counter_bits),
        };
        Ok(Snapshot {
            kind: self.kind(),
            parameters,
            iv: self.expected_iv.capacity(),
            aad: self.aad.capacity(),
            selection_credit,
        })
    }
    /// All destination pointers already address independent stable storage.
    /// This copies the source's immutable parameter witnesses, never native
    /// pointer values, and must precede the destination's first native call.
    pub(crate) fn fill_snapshot(&mut self, source: &Self) -> Result<()> {
        // A copy must not turn changed native input into a new witness.
        if source.aad.as_slice() != source.expected_aad.as_slice() {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CipherParameterIdentity,
                ),
            ));
        }
        if self.kind() != source.kind()
            || self.iv.capacity() != source.expected_iv.capacity()
            || self.expected_iv.capacity() != source.expected_iv.capacity()
            || self.aad.capacity() != source.aad.capacity()
            || self.expected_aad.capacity() != source.expected_aad.capacity()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CipherSnapshotParameterShapeChanged,
                ),
            ));
        }
        self.iv
            .as_mut()
            .copy_from_slice(source.expected_iv.as_slice());
        self.expected_iv
            .as_mut()
            .copy_from_slice(source.expected_iv.as_slice());
        self.aad.as_mut().copy_from_slice(source.aad.as_slice());
        self.expected_aad
            .as_mut()
            .copy_from_slice(source.expected_aad.as_slice());
        self.fill_native_iv()
    }
    fn fill_native_iv(&mut self) -> Result<()> {
        match &mut self.parameters {
            Parameters::Ctr { native, .. } => {
                native.cb = self.expected_iv.as_slice().try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CtrCounterBlockWidth,
                    ))
                })?;
            }
            Parameters::CamelliaCtr { native, .. } => {
                native.cb = self.expected_iv.as_slice().try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CamelliaCounterBlockWidth,
                    ))
                })?;
            }
            Parameters::Rc { native, .. } => {
                native.fill_snapshot_iv(self.expected_iv.as_slice())?
            }
            _ => {}
        }
        Ok(())
    }
}
impl Snapshot {
    pub(crate) fn for_dual(request: &DualCipher<'_>, prepaid: &mut Credit) -> Result<Self> {
        let kind = super::mechanism(request);
        let (iv, aad) = dual_bytes(request);
        let retained = match request {
            DualCipher::Gcm { nonce, .. } => nonce.retained_bytes(),
            _ => 0,
        };
        let selection_credit = prepaid.split(retained)?;
        let parameters = match request {
            DualCipher::Gcm { nonce, aad } => {
                nonce.validate_gcm(aad.len())?;
                if nonce.generated() || nonce.fixed_bits() != 0 {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::ClassicGcmDoesNotGenerateAnIv,
                        ),
                    ));
                }
                ParameterShape::Gcm(nonce.clone())
            }
            DualCipher::Ctr { counter_bits, .. } => {
                counter_width(*counter_bits)?;
                ParameterShape::Ctr(*counter_bits)
            }
            _ => ParameterShape::Classic(ClassicMode::from_native(kind)?),
        };
        Ok(Self {
            kind,
            parameters,
            iv: iv.len(),
            aad: aad.len(),
            selection_credit,
        })
    }
    pub(crate) fn for_block(selection: CipherParameters<'_>, prepaid: &mut Credit) -> Result<Self> {
        let kind = CK_MECHANISM_TYPE::try_from(selection.mechanism_number()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::BlockCipherNativeIdentifierWidth,
            ))
        })?;
        let iv = selection.iv_bytes().len();
        let parameters = match selection {
            CipherParameters::AesKeyWrapPad { .. }
            | CipherParameters::AesKeyWrap { .. }
            | CipherParameters::AesKeyWrapKwp { .. }
            | CipherParameters::AesKeyWrapPkcs7 { .. } => {
                let mut contract = FixedContract::from_native(kind).ok_or(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::AesKeyWrapContractAbsent,
                    ),
                ))?;
                contract.iv = iv;
                ParameterShape::Fixed(contract)
            }
            CipherParameters::Gost28147 { .. } => ParameterShape::Gost28147,
            CipherParameters::TokenIv { cipher, iv } => ParameterShape::TokenIv {
                cipher,
                generated: iv.generated(),
            },
            CipherParameters::Stream(selection) => ParameterShape::Stream(selection),
            CipherParameters::Rc(value) => ParameterShape::Rc {
                kind,
                options: value.options(),
            },
            CipherParameters::CamelliaCtr { counter_bits, .. } => {
                counter_width(counter_bits)?;
                ParameterShape::CamelliaCtr(counter_bits)
            }
            CipherParameters::Aes(crate::AesCipherParameters::Ctr { counter_bits, .. }) => {
                counter_width(counter_bits)?;
                ParameterShape::Ctr(counter_bits)
            }
            CipherParameters::Aes(_) => ParameterShape::Classic(ClassicMode::from_native(kind)?),
            _ => ParameterShape::Fixed(FixedContract::from_native(kind).ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::FixedBlockCipherContractAbsent,
                ),
            ))?),
        };
        Ok(Self {
            kind,
            parameters,
            iv,
            aad: 0,
            selection_credit: prepaid.split(0)?,
        })
    }

    fn from_buffers(
        self,
        mut iv: Buffer,
        expected_iv: Buffer,
        mut aad: Buffer,
        expected_aad: Buffer,
        mut counter: Option<Buffer>,
    ) -> Result<CipherFrame> {
        let iv_pointer = iv.as_mut().as_mut_ptr();
        let mut parameters = match self.parameters {
            ParameterShape::Gcm(selection) => Parameters::Gcm {
                native: Box::new(CK_GCM_PARAMS {
                    pIv: iv_pointer,
                    ulIvLen: bounds::ck_length(self.iv)?,
                    ulIvBits: bounds::gcm_iv_bits(bounds::ck_length(self.iv)?),
                    pAAD: aad.as_mut().as_mut_ptr(),
                    ulAADLen: bounds::ck_length(self.aad)?,
                    ulTagBits: CK_ULONG::try_from(selection.tag_bits()).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::GcmTagAbiWidth,
                        ))
                    })?,
                }),
                selection,
            },
            ParameterShape::Classic(mode) => Parameters::Classic(mode),
            ParameterShape::Fixed(contract) => Parameters::Fixed(contract),
            ParameterShape::Gost28147 => Parameters::Gost28147,
            ParameterShape::TokenIv { cipher, generated } => {
                Parameters::TokenIv { cipher, generated }
            }
            ParameterShape::Stream(selection) => Parameters::Stream(StreamFrame::from_counter(
                selection,
                iv_pointer,
                counter.take().ok_or(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamSnapshotCounterAbsent,
                    ),
                ))?,
            )?),
            ParameterShape::Rc { kind, options } => Parameters::Rc {
                kind,
                options,
                native: RcNative::new(
                    RcCipherParameters::from_record(kind, options, expected_iv.as_slice())?,
                    iv_pointer,
                )?,
            },
            ParameterShape::CamelliaCtr(counter_bits) => Parameters::CamelliaCtr {
                counter_bits,
                native: Box::new(CK_CAMELLIA_CTR_PARAMS {
                    ulCounterBits: counter_width(counter_bits)?,
                    cb: [0; 16],
                }),
            },
            ParameterShape::Ctr(counter_bits) => Parameters::Ctr {
                counter_bits,
                native: Box::new(CK_AES_CTR_PARAMS {
                    ulCounterBits: counter_width(counter_bits)?,
                    cb: [0; 16],
                }),
            },
        };
        let (pointer, length): (CK_VOID_PTR, CK_ULONG) = match &mut parameters {
            Parameters::Gcm { native, .. } => (
                (&mut **native as *mut CK_GCM_PARAMS).cast(),
                std::mem::size_of::<CK_GCM_PARAMS>() as CK_ULONG,
            ),
            Parameters::Ctr { native, .. } => (
                (&mut **native as *mut CK_AES_CTR_PARAMS).cast(),
                std::mem::size_of::<CK_AES_CTR_PARAMS>() as CK_ULONG,
            ),
            Parameters::CamelliaCtr { native, .. } => (
                (&mut **native as *mut CK_CAMELLIA_CTR_PARAMS).cast(),
                std::mem::size_of::<CK_CAMELLIA_CTR_PARAMS>() as CK_ULONG,
            ),
            Parameters::Stream(frame) => frame.descriptor(),
            Parameters::Rc { native, .. } => native.descriptor(),
            Parameters::Classic(ClassicMode::Ecb) => (std::ptr::null_mut(), 0),
            Parameters::Fixed(contract) if contract.iv == 0 => (std::ptr::null_mut(), 0),
            Parameters::Gost28147 if self.iv == 0 => (std::ptr::null_mut(), 0),
            Parameters::Classic(_)
            | Parameters::Fixed(_)
            | Parameters::Gost28147
            | Parameters::TokenIv { .. } => (iv_pointer.cast(), bounds::ck_length(self.iv)?),
        };
        Ok(CipherFrame {
            mechanism: Box::new(CK_MECHANISM {
                mechanism: self.kind,
                pParameter: pointer,
                ulParameterLen: length,
            }),
            parameters,
            iv,
            expected_iv,
            aad,
            expected_aad,
            _selection_credit: self.selection_credit,
        })
    }
}

fn dual_bytes<'a>(request: &'a DualCipher<'_>) -> (&'a [u8], &'a [u8]) {
    match request {
        DualCipher::Gcm { nonce, aad } => (nonce.iv(), aad),
        DualCipher::Ctr { counter_block, .. } => (counter_block, &[]),
        DualCipher::Ecb => (&[], &[]),
        DualCipher::Cbc { iv }
        | DualCipher::CbcPad { iv }
        | DualCipher::Ofb { iv }
        | DualCipher::Cfb8 { iv }
        | DualCipher::Cfb64 { iv }
        | DualCipher::Cfb128 { iv } => (iv, &[]),
    }
}

/// Allocations contain no readable parameter values or native pointer until
/// the enclosing snapshot admits its complete measured resource graph.
pub(crate) struct Storage {
    shape: Snapshot,
    iv: crate::symmetric::memory::UnboundBuffer,
    expected_iv: crate::symmetric::memory::UnboundBuffer,
    aad: crate::symmetric::memory::UnboundBuffer,
    expected_aad: crate::symmetric::memory::UnboundBuffer,
    counter: Option<crate::symmetric::memory::UnboundBuffer>,
}
impl Snapshot {
    pub(crate) fn allocate(self) -> Result<Storage> {
        use crate::symmetric::memory::UnboundBuffer;
        let iv = UnboundBuffer::allocate(self.iv)?;
        let expected_iv = UnboundBuffer::allocate(self.iv)?;
        let aad = UnboundBuffer::allocate(self.aad)?;
        let expected_aad = UnboundBuffer::allocate(self.aad)?;
        let counter = match &self.parameters {
            ParameterShape::Stream(selection) => {
                Some(UnboundBuffer::allocate(selection.counter().bytes().len())?)
            }
            _ => None,
        };
        Ok(Storage {
            shape: self,
            iv,
            expected_iv,
            aad,
            expected_aad,
            counter,
        })
    }
}
impl Storage {
    /// Includes the already credited immutable selection retained by shape.
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let retained = match &self.shape.parameters {
            ParameterShape::Gcm(selection) => selection.retained_bytes(),
            _ => 0,
        };
        [
            self.iv.allocated(),
            self.expected_iv.allocated(),
            self.aad.allocated(),
            self.expected_aad.allocated(),
            self.counter.as_ref().map_or(0, |b| b.allocated()),
        ]
        .into_iter()
        .try_fold(retained, |n, size| n.checked_add(size))
        .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherSnapshotAccounting,
        )))
    }
    pub(crate) fn bind(self, prepaid: &mut Credit) -> Result<CipherFrame> {
        self.shape.from_buffers(
            self.iv.bind(prepaid)?,
            self.expected_iv.bind(prepaid)?,
            self.aad.bind(prepaid)?,
            self.expected_aad.bind(prepaid)?,
            self.counter.map(|b| b.bind(prepaid)).transpose()?,
        )
    }
}
