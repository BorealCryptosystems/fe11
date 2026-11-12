// SPDX-License-Identifier: Apache-2.0
//! Message-signature reconstruction without temporary request/reference tables.
use super::{reserve, sum as storage_sum, MacStorage, Shape, Storage};
use crate::advanced::record::profile;
use crate::advanced::{
    continuation,
    messages::{pss, MessageStep, PreparedMac},
    record, MessageRoute, NativeActivity,
};
use crate::{
    bounds,
    symmetric::memory::{Credit, UnboundBuffer},
    Error, Result,
};

pub(in crate::advanced) struct RecordPlan<'a> {
    descriptor: record::Descriptor,
    messages: record::Messages<'a>,
    shape: Shape,
    pending: bool,
}
impl<'a> RecordPlan<'a> {
    pub(in crate::advanced) fn new(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        ceilings.validate()?;
        // Batch count is an input bound. Stream rows are retained results;
        // only their current fragment is subject to the input limits below.
        if messages.stream().is_none()
            && (messages.len() == 0 || messages.len() > ceilings.maximum_parts)
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageCount,
            )));
        }
        let (route, parameters) = if let Some(stream) = messages.stream() {
            (stream.route, stream.parameters)
        } else {
            let first = messages.iter().next().ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageCount,
                ),
            ))??;
            (first.route, first.params)
        };
        let streaming = messages.stream().is_some();
        let mut fragment = None;
        let verify = descriptor.family == record::Family::MessageVerify;
        let pss = if matches!(
            descriptor.profile,
            profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED
        ) {
            Some(pss::record_parameters(descriptor, &parameters)?)
        } else {
            None
        };
        let kind = descriptor.mechanism.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::ReconstructionMechanismWidth,
            ))
        })?;
        if let Some(selection) = pss {
            if selection.mechanism(crate::HashExecution::Pkcs11Combined)? != kind {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::PssMessageMechanismMismatch,
                )));
            }
        }
        let mut parts = 0usize;
        let mut fragments = 0usize;
        let mut requested_parts = 0usize;
        let mut input_bytes = 0usize;
        let mut buffers = 0usize;
        for message in messages.iter() {
            let message = message?;
            let count = message.fragments.len();
            let input = if streaming {
                let mut bytes = 0;
                for part in message.fragments.iter() {
                    let size = part?.len();
                    bounds::ck_length(size)?;
                    if fragment.replace(size).is_some() {
                        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageStreamRepeatedFragment,
                        )));
                    }
                    bytes = size;
                }
                bytes
            } else {
                crate::InputLimits {
                    maximum_parts: ceilings.maximum_parts,
                    maximum_total_bytes: ceilings.maximum_total_bytes,
                }
                .validate_lengths(
                    ceilings,
                    count,
                    message.fragments.iter().map(|part| part.map(<[u8]>::len)),
                )?
            };
            requested_parts = storage_sum(&[
                requested_parts,
                if streaming { count } else { count.max(1) },
            ])?;
            input_bytes = storage_sum(&[input_bytes, input])?;
            let output = if verify {
                let expected = if streaming {
                    message.tag_or_signature.unwrap_or(&[])
                } else {
                    message.tag_or_signature.ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::ReconstructionExpectedSignature,
                        ),
                    ))?
                };
                input_bytes = storage_sum(&[input_bytes, expected.len()])?;
                expected.len()
            } else {
                message.expected
            };
            bounds::ck_length(output)?;
            if route == MessageRoute::Single {
                bounds::ck_length(input)?;
            }
            parts = storage_sum(&[
                parts,
                if streaming {
                    0
                } else if route == MessageRoute::Single {
                    1
                } else {
                    count.max(1)
                },
            ])?;
            fragments = storage_sum(&[fragments, if streaming { 0 } else { count }])?;
            buffers = storage_sum(&[
                buffers,
                input,
                output,
                continuation::InputLayout::allocation_bytes(if streaming { 0 } else { count })?,
            ])?;
        }
        if requested_parts > ceilings.maximum_parts || input_bytes > ceilings.maximum_total_bytes {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageInputCeiling,
            )));
        }
        let storage = MacStorage::with_buffer_bytes(messages.len(), parts, pss.is_some(), buffers)?;
        let shape = Shape {
            input: descriptor.input,
            invalid_seen: messages.stream().is_some_and(|stream| stream.invalid),
            fragment,
            rows: messages.len(),
            parts,
            lengths: storage_sum(&[parts, fragments])?,
            storage,
            kind,
            route,
            verify,
            size: descriptor.size,
            pss,
        };
        Ok(Self {
            descriptor,
            messages: *messages,
            shape,
            pending,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(&self) -> Result<usize> {
        self.shape.request_bytes()
    }
    pub(in crate::advanced) fn allocate(&self) -> Result<Storage> {
        let mut rows = reserve(self.shape.rows)?;
        let mut lengths = reserve(self.shape.rows)?;
        let streaming = self.messages.stream().is_some();
        for message in self.messages.iter() {
            let message = message?;
            let count = if streaming {
                0
            } else if self.shape.route == MessageRoute::Single {
                1
            } else {
                message.fragments.len().max(1)
            };
            let mut parts = reserve(count)?;
            if streaming {
                // The sole live fragment is allocated below, outside row history.
            } else if self.shape.route == MessageRoute::Single {
                let size = message.fragments.iter().try_fold(0usize, |n, part| {
                    n.checked_add(part?.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageByteOverflow,
                        ),
                    ))
                })?;
                parts.push(UnboundBuffer::allocate(size)?);
            } else if message.fragments.len() == 0 {
                parts.push(UnboundBuffer::allocate(0)?);
            } else {
                for part in message.fragments.iter() {
                    parts.push(UnboundBuffer::allocate(part?.len())?);
                }
            }
            let mut fragments = reserve(if streaming {
                0
            } else {
                message.fragments.len()
            })?;
            if !streaming {
                for part in message.fragments.iter() {
                    fragments.push(part?.len());
                }
            }
            let output = if self.shape.verify {
                if streaming {
                    message.tag_or_signature.map_or(0, <[u8]>::len)
                } else {
                    message
                        .tag_or_signature
                        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::ReconstructionExpectedSignature,
                        )))?
                        .len()
                }
            } else {
                message.expected
            };
            rows.push(super::RowStorage {
                parts,
                destination: reserve(count)?,
                fragments,
                output: UnboundBuffer::allocate(output)?,
            });
            lengths.push(Box::new(bounds::ck_length(output)?));
        }
        if rows.len() != self.shape.rows {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
            )));
        }
        Ok(Storage {
            shape: self.shape,
            stream_fragment: self
                .shape
                .fragment
                .map(UnboundBuffer::allocate)
                .transpose()?,
            rows,
            inputs: reserve(self.shape.rows)?,
            outputs: reserve(self.shape.rows)?,
            rejections: reserve(self.shape.rows)?,
            layouts: reserve(self.shape.rows)?,
            lengths,
            cleanup_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
            result_credit: None,
            temporary_credit: None,
        })
    }
    pub(in crate::advanced) fn bind(
        self,
        storage: Storage,
        prepaid: &mut Credit,
    ) -> Result<PreparedMac> {
        let mut body = storage.bind(prepaid)?.frame;
        if let Some(stream) = self.messages.stream() {
            let rows = stream.rejections.iter(self.messages.len())?;
            for (target, original) in body
                .signatures
                .as_mut()
                .expect("prepared message results")
                .rejections
                .iter_mut()
                .zip(rows)
            {
                *target = original?;
            }
        }
        let outputs = &mut body
            .signatures
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultsAbsent,
            )))?
            .bytes;
        let streaming = self.messages.stream().is_some();
        let mut next = 0usize;
        let mut prefix = true;
        for (index, message) in self.messages.iter().enumerate() {
            let message = message?;
            if prefix && message.state == record::MessageState::Finished {
                next += 1;
            } else {
                prefix = false;
            }
            let row = body.inputs.get_mut(index).ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                ),
            ))?;
            let mut offset = 0usize;
            for (part_index, part) in message.fragments.iter().enumerate() {
                let part = part?;
                if streaming {
                    let target =
                        body.stream_fragment
                            .as_mut()
                            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageStreamReconstructionFragment,
                        )))?;
                    if target.as_slice().len() != part.len() {
                        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageStreamReconstructionSize,
                        )));
                    }
                    target.as_mut().copy_from_slice(part);
                } else if self.shape.route == MessageRoute::Single {
                    let end = offset.checked_add(part.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageByteOverflow,
                        ),
                    ))?;
                    row[0]
                        .as_mut()
                        .get_mut(offset..end)
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                        )))?
                        .copy_from_slice(part);
                    offset = end;
                } else {
                    let target = row.get_mut(part_index).ok_or(Error::Rejected(
                        crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                        ),
                    ))?;
                    if target.as_slice().len() != part.len() {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                        )));
                    }
                    target.as_mut().copy_from_slice(part);
                }
            }
            if !streaming
                && self.shape.route == MessageRoute::Single
                && offset != row[0].as_slice().len()
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                )));
            }
            let output = outputs.get_mut(index).ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                ),
            ))?;
            if self.shape.verify {
                let expected = if streaming {
                    message.tag_or_signature.unwrap_or(&[])
                } else {
                    message.tag_or_signature.ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::ReconstructionExpectedSignature,
                        ),
                    ))?
                };
                if output.as_slice().len() != expected.len() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                    )));
                }
                output.as_mut().copy_from_slice(expected);
            } else if message.state == record::MessageState::Finished {
                crate::advanced::reconstruction::output(output, message.result, true)?;
                *body.lengths[index] = bounds::ck_length(message.result.len())?;
            }
        }
        body.activity = NativeActivity::restored(self.pending);
        body.step = if let Some(stream) = self.messages.stream() {
            use record::StreamBoundary;
            match stream.boundary {
                StreamBoundary::Init => MessageStep::Init,
                StreamBoundary::Ready => MessageStep::Ready,
                StreamBoundary::Begin => MessageStep::Begin(next),
                StreamBoundary::Receive => MessageStep::Receive(next),
                StreamBoundary::Single => MessageStep::Single(next),
                StreamBoundary::Update => MessageStep::StreamUpdate(next),
                StreamBoundary::Last => MessageStep::StreamLast(next),
                StreamBoundary::Finish => MessageStep::Finish,
            }
        } else {
            match self.descriptor.phase.name() {
                "C_MessageSignInit" | "C_MessageVerifyInit" => MessageStep::Init,
                "C_SignMessage" | "C_VerifyMessage" => MessageStep::Single(next),
                "C_SignMessageBegin" | "C_VerifyMessageBegin" => MessageStep::Begin(next),
                "C_SignMessageNext" | "C_VerifyMessageNext" => MessageStep::Next(
                    next,
                    self.messages
                        .iter()
                        .nth(next)
                        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::ReconstructionSignaturePhase,
                        )))??
                        .next_fragment,
                ),
                "C_MessageSignFinal" | "C_MessageVerifyFinal" => MessageStep::Finish,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::ReconstructionSignaturePhase,
                    )))
                }
            }
        };
        if let Some(output) = self.messages.output() {
            let pending =
                crate::advanced::messages::output::Pending::from_record(body.step, output)?;
            if !output.prepared {
                *body.lengths[next] = bounds::ck_length(output.request.required)?;
            }
            body.step = MessageStep::Output(pending);
        }
        Ok(body)
    }
}
