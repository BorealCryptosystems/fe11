// SPDX-License-Identifier: Apache-2.0
//! Complete signature-operation storage before acquiring source and session access.
use super::{NativeParameters, PqcAlgorithm, PqcCall, PqcSignatureParameters};
use crate::session::AdmissionProgress;
use crate::symmetric::memory::{Credit, UnboundBuffer};
use crate::{bounds, Error, Result, Session};

pub(in crate::crypto::pqc) struct PreparedPqcCall {
    call: PqcCall,
    // The native descriptor/context and frame metadata must outlive their charge.
    _credit: Credit,
}

enum SignatureStorage<'a> {
    Output(usize),
    Input(&'a [u8]),
}
impl SignatureStorage<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Output(length) => *length,
            Self::Input(bytes) => bytes.len(),
        }
    }
}

impl PreparedPqcCall {
    pub(in crate::crypto::pqc) fn verification(
        session: &Session,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        input_capacity: usize,
        signature: &[u8],
        progress: &AdmissionProgress,
        epoch: u64,
        overhead: usize,
    ) -> Result<((Self, crate::error::PreparedCompletionCell), Credit)> {
        Self::prepare(
            session,
            algorithm,
            parameters,
            input_capacity,
            SignatureStorage::Input(signature),
            std::mem::size_of::<Self>()
                .checked_add(crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes())
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcNativeFrameAccounting,
                )))?,
            progress,
            epoch,
            overhead,
        )
    }

    pub(in crate::crypto::pqc) fn signing(
        session: &Session,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        input_capacity: usize,
        progress: &AdmissionProgress,
        epoch: u64,
        overhead: usize,
    ) -> Result<(
        (super::SigningCall, crate::error::PreparedCompletionCell),
        Credit,
    )> {
        let ((prepared, diagnostic), coordination) = Self::prepare(
            session,
            algorithm,
            parameters,
            input_capacity,
            SignatureStorage::Output(algorithm.signature_length()),
            std::mem::size_of::<super::SigningCall>()
                .checked_add(
                    crate::native::frame::SessionFrame::<'_, super::SigningCall>::allocation_bytes(
                    ),
                )
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcNativeFrameAccounting,
                )))?,
            progress,
            epoch,
            overhead,
        )?;
        let length = bounds::ck_length(prepared.call.signature.capacity())?;
        Ok((
            (
                super::SigningCall {
                    buffers: prepared.call,
                    length,
                    _credit: prepared._credit,
                },
                diagnostic,
            ),
            coordination,
        ))
    }

    fn prepare(
        session: &Session,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        input_capacity: usize,
        signature: SignatureStorage<'_>,
        frame_bytes: usize,
        progress: &AdmissionProgress,
        epoch: u64,
        overhead: usize,
    ) -> Result<((Self, crate::error::PreparedCompletionCell), Credit)> {
        bounds::ck_length(input_capacity)?;
        bounds::ck_length(signature.len())?;
        let mut required = NativeParameters::requested_bytes(parameters)?
            .checked_add(frame_bytes)
            .and_then(|bytes| bytes.checked_add(input_capacity))
            .and_then(|bytes| bytes.checked_add(signature.len()))
            .and_then(|bytes| bytes.checked_add(overhead))
            .and_then(|bytes| {
                bytes.checked_add(crate::error::CompletionStorage::allocation_bytes())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcNativeStorageSize,
            )))?;
        loop {
            let mut prepaid =
                crate::advanced::reserve_preparation_at_epoch(session, required, progress, epoch)?;
            let mut native = NativeParameters::allocate(parameters)?;
            let input = UnboundBuffer::allocate(input_capacity)?;
            let output = UnboundBuffer::allocate(signature.len())?;
            let metadata =
                native
                    .allocated_bytes()?
                    .checked_add(frame_bytes)
                    .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcNativeStorageSize,
                    )))?;
            let actual = metadata
                .checked_add(input.allocated())
                .and_then(|bytes| bytes.checked_add(output.allocated()))
                .and_then(|bytes| bytes.checked_add(overhead))
                .and_then(|bytes| {
                    bytes.checked_add(crate::error::CompletionStorage::allocation_bytes())
                })
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcNativeStorageSize,
                )))?;
            if actual > required {
                drop(output);
                drop(input);
                drop(native);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            let input = input.bind(&mut prepaid)?;
            let mut output = output.bind(&mut prepaid)?;
            if let SignatureStorage::Input(source) = &signature {
                output.as_mut().copy_from_slice(source);
            }
            native.bind_context(parameters);
            let prepared = Self {
                call: PqcCall::from_prepared(algorithm, native, input, output)?,
                _credit: prepaid.split(metadata)?,
            };
            let diagnostic = crate::error::PreparedCompletionCell::prepare(&mut prepaid)?;
            return Ok(((prepared, diagnostic), prepaid));
        }
    }
}

impl PreparedPqcCall {
    pub(in crate::crypto::pqc) fn call_mut(&mut self) -> &mut PqcCall {
        &mut self.call
    }
}
