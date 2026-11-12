// SPDX-License-Identifier: Apache-2.0
//! Borrow the parent and current submission without retaining input history.
use super::{MacOperation, MessageRoute, MessageStep};
use crate::advanced::record::{
    Fragments, Limits, Message, MessageState, MessageStream, Messages, NonceOrigin, Parameters,
    StreamBoundary, Writer,
};
use crate::{Error, Result};

impl MacOperation {
    pub(super) fn stream_boundary(&self) -> Result<StreamBoundary> {
        Ok(match self.dispatch_step() {
            MessageStep::Init => StreamBoundary::Init,
            MessageStep::Ready => StreamBoundary::Ready,
            MessageStep::Begin(_) => StreamBoundary::Begin,
            MessageStep::Receive(_) => StreamBoundary::Receive,
            MessageStep::Single(_) => StreamBoundary::Single,
            MessageStep::StreamUpdate(_) => StreamBoundary::Update,
            MessageStep::StreamLast(_) => StreamBoundary::Last,
            MessageStep::Finish | MessageStep::Done => StreamBoundary::Finish,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageStreamCapturePhase,
                )))
            }
        })
    }

    pub(super) fn record_parameters(&self) -> Result<Parameters<'static>> {
        let (tag_bits, hash, mgf, salt) = match &self.pss {
            Some(parameters) => (
                0,
                Some(parameters.hashAlg as u64),
                Some(parameters.mgf as u64),
                Some(parameters.sLen as u64),
            ),
            None => (
                u32::try_from(self.size)
                    .ok()
                    .and_then(|n| n.checked_mul(8))
                    .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::MacTagSize,
                    )))?,
                None,
                None,
                None,
            ),
        };
        Ok(Parameters {
            digest_output: None,
            cipher_extension: None,
            digest_extension: None,
            signature: None,
            digest_oid: None,
            message_init: None,
            counter_bits: None,
            iv_generator: None,
            iv_fixed_bits: None,
            iv_initial: None,
            nonce: None,
            aad: None,
            tag_bits,
            hash,
            mgf,
            salt,
        })
    }

    pub(super) fn write_stream_messages(
        &self,
        writer: &mut Writer<'_>,
        limits: Limits,
    ) -> Result<()> {
        let boundary = self.stream_boundary()?;
        let outputs = &self
            .signatures
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageStreamResultsAbsent,
            )))?
            .bytes;
        let completed = self
            .inputs
            .len()
            .checked_sub(usize::from(boundary.has_message()))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageStreamActiveRowAbsent,
            )))?;
        let current = match self.dispatch_step() {
            MessageStep::Begin(index)
            | MessageStep::Receive(index)
            | MessageStep::Single(index)
            | MessageStep::StreamUpdate(index)
            | MessageStep::StreamLast(index) => Some(index),
            _ => None,
        };
        if self
            .signatures
            .as_ref()
            .expect("checked results")
            .rejections
            .len()
            != self.inputs.len()
            || outputs.len() != self.inputs.len()
            || self.lengths.len() != self.inputs.len()
            || self.layouts.len() != self.inputs.len()
            || current.is_some_and(|index| index != completed)
            || boundary.has_fragment() != self.stream_fragment.is_some()
            || self.inputs.iter().any(|row| !row.is_empty())
            || self.layouts.iter().any(|row| !row.lengths().is_empty())
            || self.route == MessageRoute::Single
                && matches!(
                    boundary,
                    StreamBoundary::Begin
                        | StreamBoundary::Receive
                        | StreamBoundary::Update
                        | StreamBoundary::Last
                )
            || self.route == MessageRoute::Multipart && boundary == StreamBoundary::Single
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageStreamCaptureShape,
            )));
        }
        let parameters = self.record_parameters()?;
        Messages::write_generated_with_state(
            writer,
            self.inputs.len(),
            limits,
            Some(MessageStream {
                boundary,
                route: self.route,
                invalid: !self.outcome.valid(),
                rejections: crate::advanced::record::MessageRejections::Live(
                    &self
                        .signatures
                        .as_ref()
                        .expect("checked results")
                        .rejections,
                ),
                parameters,
            }),
            self.output_record(),
            |index| {
                let finished = index < completed;
                let output = &outputs[index];
                let rejected = self
                    .signatures
                    .as_ref()
                    .expect("checked results")
                    .rejections[index]
                    .is_some();
                let result = if finished && !self.verify && !rejected {
                    output.as_slice()
                } else {
                    &[]
                };
                let state = if finished {
                    MessageState::Finished
                } else if matches!(boundary, StreamBoundary::Single | StreamBoundary::Begin) {
                    MessageState::Planned
                } else {
                    MessageState::Engaged
                };
                let fragments = if !finished && boundary.has_fragment() {
                    Fragments::Buffers(std::slice::from_ref(self.stream_fragment.as_ref().ok_or(
                        Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageStreamFragmentAbsent,
                        )),
                    )?))
                } else {
                    Fragments::Slices(&[])
                };
                let tag_or_signature = if self.verify {
                    (!finished && boundary.terminal_message()).then(|| output.as_slice())
                } else {
                    finished.then_some(result)
                };
                Ok(Message {
                    route: self.route,
                    params: parameters,
                    origin: NonceOrigin::None,
                    state,
                    fragments,
                    next_fragment: 0,
                    produced: result.len(),
                    expected: if self.verify { 0 } else { output.capacity() },
                    result,
                    tag_or_signature,
                    residual_start: 0,
                    residual_length: 0,
                })
            },
        )
    }
}
