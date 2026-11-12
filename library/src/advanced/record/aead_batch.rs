// SPDX-License-Identifier: Apache-2.0
//! Queued AEAD storage continuation, independent of the native call's input size.
//!
//! Tag 8 also keeps the original declared input length independently of the
//! bytes still required for dispatch or fresh decryption. Tag 7 carries
//! actual output capacities; historical tag 0 keeps its input-length convention.
//! Neither representation attests output authenticity; native state, provenance
//! and destination checks remain separate.
use super::{Descriptor, Family, Function, MessageState, Messages, Reader, Writer};
use crate::advanced::{CipherBufferRequest, MessageRoute};
use crate::{bounds, Error, Result};

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Output {
    pub request: CipherBufferRequest,
    pub prepared: bool,
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct State<'a> {
    pub output: Option<Output>,
    // Borrowed fixed-width scalars, never a request to allocate input history.
    pub declared: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Default)]
pub(in crate::advanced) struct RowLayout {
    pub output_capacity: bool,
    pub declared_input: Option<usize>,
}

impl<'a> State<'a> {
    pub(super) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(u8::from(self.output.is_some()))?;
        if let Some(output) = self.output {
            Function::from_name(output.request.function)?.write(writer)?;
            writer.u64(output.request.code)?;
            writer.u64(output.request.required as u64)?;
            writer.u64(output.request.previous_capacity as u64)?;
            writer.u8(u8::from(output.prepared))?;
        }
        Ok(())
    }

    pub(super) fn read(
        reader: &mut Reader<'a>,
        limits: super::Limits,
        lengths: bool,
    ) -> Result<Self> {
        let output = if reader.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::AeadBatchOutputContinuation,
        ))? {
            let function = Function::read(reader)?.name();
            let code = reader.u64()?;
            let required = usize::try_from(reader.u64()?).map_err(|_| {
                Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::AeadRequiredOutputWidth,
                ))
            })?;
            let previous_capacity = usize::try_from(reader.u64()?).map_err(|_| {
                Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::AeadPreviousOutputWidth,
                ))
            })?;
            Some(Output {
                request: CipherBufferRequest {
                    function,
                    code,
                    required,
                    previous_capacity,
                },
                prepared: reader.boolean(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::AeadBatchOutputPrepared,
                ))?,
            })
        } else {
            None
        };
        let declared = if lengths {
            let count = reader.count(limits.messages)?;
            let start = reader.position;
            // These totals describe host-side history. Mechanism and phase
            // validation separately bound lengths that will be passed to C.
            for _ in 0..count {
                usize::try_from(reader.u64()?).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadDeclaredInputWidth,
                    ))
                })?;
            }
            Some(&reader.bytes[start..reader.position])
        } else {
            None
        };
        Ok(Self { output, declared })
    }

    pub(in crate::advanced) fn row_layout(self, index: usize) -> Result<RowLayout> {
        let declared_input = self
            .declared
            .map(|bytes| {
                let start = index.checked_mul(8).ok_or(Error::Rejected(
                    crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadDeclaredInputIndex,
                    ),
                ))?;
                let end = start.checked_add(8).ok_or(Error::Rejected(
                    crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadDeclaredInputIndex,
                    ),
                ))?;
                let value: [u8; 8] = bytes
                    .get(start..end)
                    .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadDeclaredInputAbsent,
                    )))?
                    .try_into()
                    .map_err(|_| {
                        Error::Rejected(crate::RejectionReason::MessageRecord(
                            crate::MessageRecordRejection::AeadDeclaredInputWidth,
                        ))
                    })?;
                usize::try_from(u64::from_be_bytes(value)).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadDeclaredInputWidth,
                    ))
                })
            })
            .transpose()?;
        Ok(RowLayout {
            output_capacity: true,
            declared_input,
        })
    }

    pub(in crate::advanced) fn validate(
        self,
        descriptor: Descriptor,
        messages: &Messages<'_>,
        detached: bool,
    ) -> Result<()> {
        if !matches!(
            descriptor.family,
            Family::MessageEncrypt | Family::MessageDecrypt
        ) || messages.stream().is_some()
            || messages.output().is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::AeadBatchRecordAssociation,
            )));
        }
        // Output widths are real retained allocations. Reader limits and the
        // destination's aggregate admission bound them; required is merely the
        // module's observation and must never drive an implicit allocation.
        if self
            .declared
            .is_some_and(|bytes| bytes.len() / 8 != messages.len() || bytes.len() % 8 != 0)
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::AeadDeclaredInputRowCount,
            )));
        }
        for (index, row) in messages.iter().enumerate() {
            let row = row?;
            if row.state != MessageState::Finished {
                let remaining = row
                    .expected
                    .checked_sub(row.produced)
                    .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadCapacityPrefixExceedsStorage,
                    )))?;
                bounds::ck_length(remaining)?;
            }
            if let Some(declared) = self.row_layout(index)?.declared_input {
                let retained = row.fragments.iter().try_fold(0usize, |sum, part| {
                    sum.checked_add(part?.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::MessageRecord(
                            crate::MessageRecordRejection::AeadRetainedInputOverflow,
                        ),
                    ))
                })?;
                // A future call and an unfinished recovery ciphertext need their
                // entire input. Completed rows carry only their output. An
                // encryption continuation may already have retired its prefix.
                if retained > declared
                    || (row.state == MessageState::Planned
                        || descriptor.family == Family::MessageDecrypt
                            && row.state == MessageState::Engaged)
                        && retained != declared
                    || row.state == MessageState::Finished && retained != 0
                {
                    return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::AeadDeclaredRetainedInputAssociation,
                    )));
                }
            }
        }
        let Some(output) = self.output else {
            return Ok(());
        };
        if detached
            || output.request.code != fe11_sys::CKR_BUFFER_TOO_SMALL as u64
            || output.request.function != descriptor.phase.name()
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::AeadCapacityContinuationAssociation,
            )));
        }
        bounds::ck_length(output.request.required)?;
        bounds::ck_length(output.request.previous_capacity)?;
        let row = messages
            .iter()
            .find_map(|row| match row {
                Ok(row) if row.state != MessageState::Finished => Some(Ok(row)),
                Err(error) => Some(Err(error)),
                _ => None,
            })
            .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::AeadCapacityRowAbsent,
            )))??;
        let decrypt = descriptor.family == Family::MessageDecrypt;
        let valid_call = match (row.route, row.state) {
            (MessageRoute::Single, MessageState::Planned) => {
                output.request.function
                    == if decrypt {
                        "C_DecryptMessage"
                    } else {
                        "C_EncryptMessage"
                    }
            }
            (MessageRoute::Multipart, MessageState::Engaged) => {
                row.next_fragment < row.fragments.len().max(1)
                    && output.request.function
                        == if decrypt {
                            "C_DecryptMessageNext"
                        } else {
                            "C_EncryptMessageNext"
                        }
            }
            _ => false,
        };
        let remaining = row
            .expected
            .checked_sub(row.produced)
            .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::AeadCapacityPrefixExceedsStorage,
            )))?;
        if !valid_call || !output.prepared && remaining != output.request.previous_capacity {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::AeadCapacityContinuationPhase,
            )));
        }
        Ok(())
    }
}
