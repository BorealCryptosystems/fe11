// SPDX-License-Identifier: Apache-2.0
//! Storage continuation metadata, distinct from native asynchronous ownership.
use super::{Descriptor, Family, Function, MessageState, Messages, Reader, Writer};
use crate::advanced::{MessageRoute, SignatureBufferRequest};
use crate::{bounds, Error, Result};

#[derive(Clone, Copy)]
pub(in crate::advanced) struct MessageOutput {
    pub request: SignatureBufferRequest,
    // A wire representation flag, converted to the owner's typed storage state.
    pub prepared: bool,
}

impl MessageOutput {
    pub(super) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        Function::from_name(self.request.function)?.write(writer)?;
        writer.u64(self.request.code)?;
        writer.u64(self.request.required as u64)?;
        writer.u64(self.request.previous_capacity as u64)?;
        writer.u8(u8::from(self.prepared))
    }

    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let function = Function::read(reader)?.name();
        let code = reader.u64()?;
        let required = usize::try_from(reader.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::MessageRequiredOutputWidth,
            ))
        })?;
        let previous_capacity = usize::try_from(reader.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::MessagePreviousOutputWidth,
            ))
        })?;
        let prepared = reader.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::MessageOutputPrepared,
        ))?;
        Ok(Self {
            request: SignatureBufferRequest {
                function,
                code,
                required,
                previous_capacity,
            },
            prepared,
        })
    }

    pub(super) fn validate(
        self,
        descriptor: Descriptor,
        messages: &Messages<'_>,
        detached: bool,
    ) -> Result<()> {
        if detached
            || descriptor.family != Family::MessageSign
            || self.request.code != fe11_sys::CKR_BUFFER_TOO_SMALL as u64
            || self.request.function != descriptor.phase.name()
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::MessageOutputContinuationAssociation,
            )));
        }
        bounds::ck_length(self.request.required)?;
        bounds::ck_length(self.request.previous_capacity)?;
        let message = messages
            .iter()
            .find_map(|message| match message {
                Ok(message) if message.state != MessageState::Finished => Some(Ok(message)),
                Err(error) => Some(Err(error)),
                _ => None,
            })
            .ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::MessageOutputContinuationRowAbsent,
            )))??;
        let terminal = match (self.request.function, message.route, message.state) {
            ("C_SignMessage", MessageRoute::Single, MessageState::Planned) => true,
            ("C_SignMessageNext", MessageRoute::Multipart, MessageState::Engaged) => {
                message.next_fragment.checked_add(1) == Some(message.fragments.len().max(1))
            }
            _ => false,
        };
        if !terminal || message.produced != 0 || !self.prepared && message.expected != 0 {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::MessageOutputContinuationPhase,
            )));
        }
        // Required and previous capacity are observations, not allocations or
        // a promise of success. Only the prepared buffer has a writable bound.
        bounds::ck_length(message.expected)?;
        Ok(())
    }
}
