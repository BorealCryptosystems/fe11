// SPDX-License-Identifier: Apache-2.0
//! Exact terminal data call retained while the caller replaces output storage.
use super::{MacOperation, MessageStep};
use crate::advanced::{record, SignatureBufferRequest};
use crate::symmetric::memory::Buffer;
use crate::{bounds, Error, Result};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Call {
    Single { message: usize },
    Next { message: usize, part: usize },
    StreamLast { message: usize },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Storage {
    Missing,
    Prepared,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Pending {
    call: Call,
    request: SignatureBufferRequest,
    storage: Storage,
}

impl Pending {
    pub(super) fn new(step: MessageStep, request: SignatureBufferRequest) -> Result<Self> {
        let call = match step {
            MessageStep::Single(message) => Call::Single { message },
            MessageStep::Next(message, part) => Call::Next { message, part },
            MessageStep::StreamLast(message) => Call::StreamLast { message },
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageOutputCallAbsent,
                )))
            }
        };
        Ok(Self {
            call,
            request,
            storage: Storage::Missing,
        })
    }

    pub(super) fn step(self) -> MessageStep {
        match self.call {
            Call::Single { message } => MessageStep::Single(message),
            Call::Next { message, part } => MessageStep::Next(message, part),
            Call::StreamLast { message } => MessageStep::StreamLast(message),
        }
    }

    fn message(self) -> usize {
        match self.call {
            Call::Single { message }
            | Call::Next { message, .. }
            | Call::StreamLast { message } => message,
        }
    }

    pub(super) fn record(self) -> record::MessageOutput {
        record::MessageOutput {
            request: self.request,
            prepared: self.storage == Storage::Prepared,
        }
    }

    pub(super) fn from_record(step: MessageStep, output: record::MessageOutput) -> Result<Self> {
        let mut pending = Self::new(step, output.request)?;
        if output.prepared {
            pending.storage = Storage::Prepared;
        }
        Ok(pending)
    }
}

impl MacOperation {
    pub(super) fn dispatch_step(&self) -> MessageStep {
        match self.step {
            MessageStep::Output(pending) => pending.step(),
            step => step,
        }
    }

    pub(super) fn output_record(&self) -> Option<record::MessageOutput> {
        match self.step {
            MessageStep::Output(pending) => Some(pending.record()),
            _ => None,
        }
    }

    pub(in crate::advanced) fn buffer_request(&self) -> Option<SignatureBufferRequest> {
        match self.step {
            MessageStep::Output(Pending {
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
    ) -> Result<SignatureBufferRequest> {
        let request = self.buffer_request().ok_or(Error::Rejected(
            crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSignatureIsNotWaitingForStorage,
            ),
        ))?;
        bounds::ck_length(capacity)?;
        self.input.produced(capacity)?;
        Ok(request)
    }

    pub(in crate::advanced) fn attach_output(
        &mut self,
        capacity: usize,
        mut output: Buffer,
    ) -> Result<Option<Buffer>> {
        self.output_preparation(capacity)?;
        if output.capacity() != capacity {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessagePreparedOutputWidth,
            )));
        }
        let length = bounds::ck_length(capacity)?;
        let MessageStep::Output(mut pending) = self.step else {
            unreachable!("checked output preparation")
        };
        let message = pending.message();
        let target = self
            .signatures
            .as_mut()
            .and_then(|signatures| signatures.bytes.get_mut(message))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSignatureStorageAbsent,
            )))?;
        output.set_length(0)?;
        let old = std::mem::replace(target, output);
        *self.lengths[message] = length;
        pending.storage = Storage::Prepared;
        // Keep the retained call visible to captures until explicit polling
        // issues it. Attaching storage neither consumes input nor enters C.
        self.step = MessageStep::Output(pending);
        Ok(Some(old))
    }
}
