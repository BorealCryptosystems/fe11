// SPDX-License-Identifier: Apache-2.0
//! Explicit output replacement retains the exact AEAD call and produced prefix.
use super::{AeadMessageOperation, AeadStep};
use crate::advanced::CipherBufferRequest;
use crate::{bounds, symmetric::memory::Buffer, Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Call {
    Single(usize),
    Next(usize, usize),
    StreamUpdate(usize),
    StreamLast(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Storage {
    Missing,
    Prepared,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Pending {
    call: Call,
    request: CipherBufferRequest,
    storage: Storage,
}

impl Pending {
    pub(super) fn from_record(
        step: AeadStep,
        request: CipherBufferRequest,
        prepared: bool,
    ) -> Result<Self> {
        let mut value = Self::new(step, request)?;
        if prepared {
            value.storage = Storage::Prepared;
        }
        Ok(value)
    }

    pub(super) fn new(step: AeadStep, request: CipherBufferRequest) -> Result<Self> {
        let call = match step {
            AeadStep::Single(index) => Call::Single(index),
            AeadStep::Next(index, part) => Call::Next(index, part),
            AeadStep::StreamUpdate(index) => Call::StreamUpdate(index),
            AeadStep::StreamLast(index) => Call::StreamLast(index),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadOutputCallAbsent,
                )))
            }
        };
        Ok(Self {
            call,
            request,
            storage: Storage::Missing,
        })
    }

    pub(super) fn step(self) -> AeadStep {
        match self.call {
            Call::Single(index) => AeadStep::Single(index),
            Call::Next(index, part) => AeadStep::Next(index, part),
            Call::StreamUpdate(index) => AeadStep::StreamUpdate(index),
            Call::StreamLast(index) => AeadStep::StreamLast(index),
        }
    }

    pub(super) fn batch_record(self) -> Result<crate::advanced::record::aead_batch::Output> {
        if !matches!(self.call, Call::Single(_) | Call::Next(_, _)) {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::QueuedAeadCapacityCall,
            )));
        }
        Ok(crate::advanced::record::aead_batch::Output {
            request: self.request,
            prepared: self.storage == Storage::Prepared,
        })
    }

    pub(super) fn record_boundary(
        self,
    ) -> Result<crate::advanced::record::aead_messages::Boundary> {
        Ok(crate::advanced::record::aead_messages::Boundary::Capacity {
            call: super::checkpoint::data_call(self.step())?,
            required: self.request.required,
            previous: self.request.previous_capacity,
            prepared: self.storage == Storage::Prepared,
        })
    }

    fn index(self) -> usize {
        match self.call {
            Call::Single(index)
            | Call::Next(index, _)
            | Call::StreamUpdate(index)
            | Call::StreamLast(index) => index,
        }
    }
}

impl AeadMessageOperation {
    pub(super) fn dispatch_step(&self) -> AeadStep {
        match self.step {
            AeadStep::Output(pending) => pending.step(),
            step => step,
        }
    }

    /// Waiting for input or replacement storage is not a native call ready
    /// to run. Prepared capacity still projects the exact retained function.
    pub(in crate::advanced) fn next_function(&self) -> Result<Option<&'static str>> {
        if matches!(
            self.step,
            AeadStep::Ready | AeadStep::Receive(_) | AeadStep::Done
        ) || self.buffer_request().is_some()
        {
            Ok(None)
        } else {
            self.function().map(Some)
        }
    }

    pub(in crate::advanced) fn buffer_request(&self) -> Option<CipherBufferRequest> {
        match self.step {
            AeadStep::Output(Pending {
                request,
                storage: Storage::Missing,
                ..
            }) => Some(request),
            _ => None,
        }
    }

    pub(in crate::advanced) fn output_preparation(
        &self,
        capacity: usize,
    ) -> Result<(CipherBufferRequest, usize)> {
        let request =
            self.buffer_request()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadIsNotWaitingForStorage,
                )))?;
        if self.pending() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadOutputStillReferencedByPendingCall,
            )));
        }
        bounds::ck_length(capacity)?;
        self.input_submission(capacity)?;
        let AeadStep::Output(pending) = self.step else {
            unreachable!("checked AEAD output request")
        };
        let frame = &self.frames[pending.index()];
        let total = frame.used.checked_add(capacity).ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadOutputCapacityOverflow,
            ),
        ))?;
        self.outputs
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadOutputsAbsent,
            )))?
            .entries[pending.index()]
        .bytes
        .as_slice()
        .get(..frame.used)
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadRetainedOutputRange,
        )))?;
        Ok((request, total))
    }

    /// Only the output allocation changes. Native parameters, nonce, tag and
    /// retained input keep their addresses; produced plaintext stays private.
    pub(in crate::advanced) fn attach_output(
        &mut self,
        capacity: usize,
        mut replacement: Buffer,
    ) -> Result<Option<Buffer>> {
        let (_, total) = self.output_preparation(capacity)?;
        if replacement.capacity() != total || replacement.as_slice().len() != total {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadPreparedOutputWidth,
            )));
        }
        let length = bounds::ck_length(capacity)?;
        let AeadStep::Output(mut pending) = self.step else {
            unreachable!("checked AEAD output preparation")
        };
        let index = pending.index();
        let used = self.frames[index].used;
        let target = &mut self.outputs.as_mut().expect("checked AEAD outputs").entries[index].bytes;
        replacement.as_mut()[..used].copy_from_slice(&target.as_slice()[..used]);
        let old = std::mem::replace(target, replacement);
        *self.frames[index].length = length;
        pending.storage = Storage::Prepared;
        self.step = AeadStep::Output(pending);
        // The shared preparation owner destroys this buffer after releasing
        // possession. Explicit polling, not attachment, issues the retained call.
        Ok(Some(old))
    }
}
