// SPDX-License-Identifier: Apache-2.0
//! Borrowed completed observations. The enclosing record checks correlation.

use super::{Function, Limits, Reader, Writer};
use crate::advanced::validation::ValidationObservation;
use crate::advanced::SessionValidation;
use crate::{Error, Result};

fn observation_shape(function: Function, index: Option<usize>, limits: Limits) -> Result<()> {
    let indexed = match function.name() {
        "C_EncryptMessage"
        | "C_EncryptMessageNext"
        | "C_DecryptMessage"
        | "C_DecryptMessageNext"
        | "C_SignMessage"
        | "C_SignMessageNext"
        | "C_VerifyMessage"
        | "C_VerifyMessageNext" => true,
        "C_MessageEncryptFinal"
        | "C_MessageDecryptFinal"
        | "C_MessageSignFinal"
        | "C_MessageVerifyFinal"
        | "C_Digest"
        | "C_DigestFinal"
        | "C_Sign"
        | "C_Verify"
        | "C_VerifySignature"
        | "C_VerifySignatureFinal"
        | "C_SignFinal"
        | "C_VerifyFinal"
        | "C_EncryptFinal"
        | "C_DecryptFinal"
        | "C_Encrypt"
        | "C_Decrypt"
        | "C_SignRecover"
        | "C_VerifyRecover" => false,
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordValidationFunction,
            )))
        }
    };
    if indexed != index.is_some() || index.is_some_and(|n| n >= limits.messages) {
        return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
            crate::OperationRecordRejection::RecordValidationIndex,
        )));
    }
    Ok(())
}

fn read_observation(reader: &mut Reader<'_>, limits: Limits) -> Result<ValidationObservation> {
    let function = Function::read(reader)?;
    let index = reader
        .optional_u64()?
        .map(|n| {
            usize::try_from(n).map_err(|_| {
                Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordValidationIndex,
                ))
            })
        })
        .transpose()?;
    observation_shape(function, index, limits)?;
    let validation = match reader.optional_u64()? {
        None => SessionValidation::Unavailable,
        Some(flags) => SessionValidation::Reported(flags),
    };
    Ok(ValidationObservation {
        function: function.name(),
        message_index: index,
        validation,
    })
}
// Immutable decoded view; copying it never copies or owns archive bytes.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct ValidationRecord<'a> {
    maximum: usize,
    count: usize,
    bytes: &'a [u8],
    limits: Limits,
}
impl<'a> ValidationRecord<'a> {
    pub(in crate::advanced) fn maximum(&self) -> usize {
        self.maximum
    }
    pub(in crate::advanced) fn iter(
        &self,
    ) -> impl Iterator<Item = Result<ValidationObservation>> + '_ {
        let mut reader = Reader {
            graph_observer: None,
            bytes: self.bytes,
            position: 0,
        };
        (0..self.count).map(move |_| read_observation(&mut reader, self.limits))
    }
    pub(in crate::advanced) fn write(
        writer: &mut Writer<'_>,
        value: Option<(usize, &[ValidationObservation])>,
        limits: Limits,
    ) -> Result<()> {
        limits.validate()?;
        let Some((maximum, observations)) = value else {
            return writer.u8(0);
        };
        if maximum == 0 || maximum - 1 > limits.messages || observations.len() > maximum {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordValidationCapacity,
            )));
        }
        writer.u8(1)?;
        writer.u32(u32::try_from(maximum).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordValidationWidth,
            ))
        })?)?;
        writer.u32(u32::try_from(observations.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordObservationWidth,
            ))
        })?)?;
        for observation in observations {
            let function = Function::from_name(observation.function)?;
            observation_shape(function, observation.message_index, limits)?;
            function.write(writer)?;
            writer.optional_u64(observation.message_index.map(|n| n as u64))?;
            writer.optional_u64(match observation.validation {
                SessionValidation::Unavailable => None,
                SessionValidation::Reported(flags) => Some(flags),
            })?;
        }
        Ok(())
    }
    pub(in crate::advanced) fn read(
        reader: &mut Reader<'a>,
        limits: Limits,
    ) -> Result<Option<Self>> {
        limits.validate()?;
        match reader.u8()? {
            0 => return Ok(None),
            1 => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                    crate::OperationRecordRejection::RecordValidationMode,
                )))
            }
        };
        // The encoded count is checked first; subtracting one avoids overflow
        // when the caller selects usize::MAX as its message ceiling.
        let maximum = reader.count(usize::MAX)?;
        if maximum == 0 || maximum - 1 > limits.messages {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordValidationCapacity,
            )));
        }
        let count = reader.count(maximum)?;
        let start = reader.position;
        for _ in 0..count {
            read_observation(reader, limits)?;
        }
        Ok(Some(Self {
            maximum,
            count,
            bytes: &reader.bytes[start..reader.position],
            limits,
        }))
    }
}
