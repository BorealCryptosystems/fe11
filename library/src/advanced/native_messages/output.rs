// SPDX-License-Identifier: Apache-2.0
//! Replace only the retained signature output; never reconstruct its input call.
use super::{CapacityStorage, MessageOutput, NativeMessageOperation, Phase};
use crate::symmetric::memory::Buffer;
use crate::{bounds, Error, Result, SignatureBufferRequest};

impl NativeMessageOperation {
    pub(in crate::advanced) fn output_preparation(
        &self,
        capacity: usize,
    ) -> Result<SignatureBufferRequest> {
        let request = self.buffer_request().ok_or(Error::Rejected(
            crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageIsNotWaitingForOutput,
            ),
        ))?;
        bounds::ck_length(capacity)?;
        self.input.produced(capacity)?;
        Ok(request)
    }

    pub(in crate::advanced) fn output_storage_bytes(&self, capacity: usize) -> Result<usize> {
        crate::advanced::signature::output_storage_bytes(self.expected.0 as u64, capacity)
    }

    pub(in crate::advanced) fn attach_output(
        &mut self,
        capacity: usize,
        mut output: Buffer,
    ) -> Result<Option<Buffer>> {
        self.output_preparation(capacity)?;
        if output.capacity() != self.output_storage_bytes(capacity)? {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessagePreparedOutputWidth,
            )));
        }
        let length = bounds::ck_length(capacity)?;
        let offset =
            crate::advanced::signature::output_offset(self.expected.0 as u64, &mut output)?;
        let Phase::Capacity { call, storage, .. } = &mut self.phase else {
            unreachable!()
        };
        let MessageOutput::Sign(Some(target)) = &mut self
            .messages
            .get_mut(call.message)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageOutputRowAbsent,
            )))?
            .output
        else {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageSigningOutputAbsent,
            )));
        };
        let old = std::mem::replace(&mut target.bytes, output);
        target.offset = offset;
        target.capacity = capacity;
        target.produced = None;
        *target.length = length;
        *storage = CapacityStorage::Prepared;
        Ok(Some(old))
    }
}
