// SPDX-License-Identifier: Apache-2.0
//! AEAD archive reconstruction under one measured destination reservation.
use super::{
    bytes, copy_request, reserve, storage_sum, temporary_bytes, AeadStoragePlan, CipherKind,
    Description, InitBinding, PreparedAead, Retention, RowStorage, Shape, Storage, StorageMetadata,
};
use crate::advanced::{
    aead_parameters::RecordSelection, capture_parts, gcm::RowDimensions, record, MessageRoute,
};
use crate::{
    bounds,
    symmetric::memory::{Credit, UnboundBuffer},
    Error, MessageInitLayout, Result,
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
        if messages.len() == 0 || messages.len() > ceilings.maximum_parts {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageMessageCount,
            )));
        }
        let first = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::EmptyAeadMessageSequence,
            ),
        ))??;
        let kind = CipherKind::from_mechanism(descriptor.mechanism)?;
        let decrypt = descriptor.family == record::Family::MessageDecrypt;
        let route = first.route;
        let init = first
            .params
            .message_init
            .unwrap_or(MessageInitLayout::InitWithoutParameters);
        if kind.stream() && init != MessageInitLayout::InitWithoutParameters {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::StreamAeadMessageinitHasNoParameters,
            )));
        }
        let first_selection = RecordSelection::new(kind, &first.params)?;
        let shared = if init == MessageInitLayout::InitWithOwnedMessageParameters {
            Some((first_selection.iv().len(), first_selection.tag_bytes()?))
        } else {
            None
        };
        let mut plan = AeadStoragePlan::empty(messages.len())?;
        let mut parts = 0usize;
        let mut lengths = 0usize;
        let mut requested_parts = 0usize;
        let mut requested_bytes = 0usize;
        for (index, message) in messages.iter().enumerate() {
            let message = message?;
            if message
                .params
                .message_init
                .unwrap_or(MessageInitLayout::InitWithoutParameters)
                != init
            {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::RecordGcmInitLayoutChangedWithinSequence,
                )));
            }
            let selection = RecordSelection::new(kind, &message.params)?;
            let data = data_length(&message)?;
            let aad =
                message
                    .params
                    .aad
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::ReconstructionAad,
                    )))?;
            let declared = messages
                .aead_row_layout(index)?
                .declared_input
                .unwrap_or(data);
            selection.validate(aad.len(), declared, decrypt)?;
            let tag = selection.tag_bytes()?;
            let expected_tag = if decrypt {
                let expected = message.tag_or_signature.ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::ReconstructionMac,
                    ),
                ))?;
                if expected.len() != tag {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageDecryptParameters,
                    )));
                }
                expected.len()
            } else {
                0
            };
            crate::InputLimits {
                maximum_parts: ceilings.maximum_parts,
                maximum_total_bytes: ceilings.maximum_total_bytes,
            }
            .validate_lengths(
                ceilings,
                message.fragments.len(),
                message.fragments.iter().map(|part| part.map(<[u8]>::len)),
            )?;
            bounds::ck_length(aad.len())?;
            requested_parts = storage_sum(&[requested_parts, message.fragments.len().max(1)])?;
            requested_bytes = storage_sum(&[
                requested_bytes,
                data,
                aad.len(),
                selection.iv().len(),
                expected_tag,
            ])?;
            if shared.is_some() {
                first_selection.fixed_scalars(&selection)?;
            }
            let count = if route == MessageRoute::Single {
                1
            } else {
                message.fragments.len().max(1)
            };
            parts = storage_sum(&[parts, count])?;
            lengths = storage_sum(&[lengths, count, message.fragments.len()])?;
            plan.push(
                RowDimensions {
                    parts: count,
                    fragments: message.fragments.len(),
                    data,
                    aad: aad.len(),
                    nonce: selection.iv().len(),
                    tag,
                    expected_tag,
                    retained: selection.retained_bytes(),
                    generated: if !decrypt && selection.generated() {
                        selection.iv().len()
                    } else {
                        0
                    },
                },
                route,
                restored_output(messages, &message, data)?,
            )?;
        }
        if requested_parts > ceilings.maximum_parts
            || requested_bytes > ceilings.maximum_total_bytes
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageBatchCeiling,
            )));
        }
        if let Some((nonce, tag)) = shared {
            plan.shared(nonce, tag)?;
        }
        let total = storage_sum(&[
            plan.total,
            temporary_bytes(messages.len(), parts)?,
            bytes::<Description>(messages.len())?,
        ])?;
        let shape = Shape {
            kind,
            route,
            decrypt,
            rows: messages.len(),
            lengths,
            parts,
            owner: plan.owner,
            results: plan.results,
            shared,
            total,
        };
        Ok(Self {
            descriptor,
            messages: *messages,
            shape,
            pending,
        })
    }

    pub(in crate::advanced) fn allocation_bytes(&self) -> usize {
        self.shape.total
    }

    pub(in crate::advanced) fn allocate(&self) -> Result<Storage> {
        // The caller owns the complete reservation, including retained selections.
        // No descriptor receives a native pointer until actual capacities pass.
        let mut descriptions = reserve(self.shape.rows)?;
        let mut rows = reserve(self.shape.rows)?;
        for (index, message) in self.messages.iter().enumerate() {
            let message = message?;
            let selection = RecordSelection::new(self.shape.kind, &message.params)?;
            let data = data_length(&message)?;
            let output = output_capacity(&self.messages, &message, data);
            let parts = if self.shape.route == MessageRoute::Single {
                capture_parts::Storage::allocate_fallible(
                    1,
                    std::iter::once(Ok(data)),
                    message.fragments.len(),
                    message.fragments.iter().map(|p| p.map(<[u8]>::len)),
                    output,
                )?
            } else if message.fragments.len() == 0 {
                capture_parts::Storage::allocate_lengths(
                    std::iter::once(0),
                    std::iter::empty(),
                    output,
                )?
            } else {
                capture_parts::Storage::allocate_fallible(
                    message.fragments.len(),
                    message.fragments.iter().map(|p| p.map(<[u8]>::len)),
                    message.fragments.len(),
                    message.fragments.iter().map(|p| p.map(<[u8]>::len)),
                    output,
                )?
            };
            let aad = message
                .params
                .aad
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::ReconstructionAad,
                )))?
                .len();
            let nonce = selection.iv().len();
            let tag = selection.tag_bytes()?;
            let expected_tag = self.shape.decrypt.then_some(tag);
            let generated = (!self.shape.decrypt && selection.generated()).then_some(nonce);
            rows.push(RowStorage {
                parts,
                retirement: super::super::queued_input::Storage::allocate(
                    if self.shape.route == MessageRoute::Single {
                        1
                    } else {
                        message.fragments.len().max(1)
                    },
                )?,
                aad: UnboundBuffer::allocate(aad)?,
                nonce: UnboundBuffer::allocate(nonce)?,
                tag: UnboundBuffer::allocate(tag)?,
                expected_tag: expected_tag.map(UnboundBuffer::allocate).transpose()?,
                generated: generated.map(UnboundBuffer::allocate).transpose()?,
            });
            descriptions.push(Description {
                origin: selection.materialize()?,
                expected: self
                    .messages
                    .aead_row_layout(index)?
                    .declared_input
                    .unwrap_or(data),
                aad,
                nonce,
                tag,
                tag_bits: selection.tag_bits(),
                expected_tag,
                generated,
            });
        }
        Ok(Storage {
            shape: self.shape,
            rows,
            frames: reserve(self.shape.rows)?,
            outputs: reserve(self.shape.rows)?,
            shared: self
                .shape
                .shared
                .map(|(nonce, tag)| {
                    Ok((
                        UnboundBuffer::allocate(nonce)?,
                        UnboundBuffer::allocate(tag)?,
                    ))
                })
                .transpose()?,
            metadata: StorageMetadata {
                descriptions,
                retention: Retention::Record,
            },
            cleanup_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            return_diagnostic: crate::error::CompletionStorage::allocate()?,
            result_credit: None,
            temporary_credit: None,
        })
    }

    pub(in crate::advanced) fn bind(
        self,
        storage: Storage,
        prepaid: &mut Credit,
    ) -> Result<PreparedAead> {
        let mut body = storage.bind(prepaid)?.body;
        let mut next = 0usize;
        let mut next_fragment = None;
        let mut prefix = true;
        for (index, message) in self.messages.iter().enumerate() {
            let message = message?;
            if prefix && message.state == record::MessageState::Finished {
                next += 1;
            } else if prefix {
                prefix = false;
                next_fragment = Some(message.next_fragment);
            }
            let frame = body.frames.get_mut(index).ok_or(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                ),
            ))?;
            let output = body
                .outputs
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
                )))?
                .entries
                .get_mut(index)
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                )))?;
            let selection = RecordSelection::new(self.shape.kind, &message.params)?;
            copy_request(
                &mut frame.aad,
                message
                    .params
                    .aad
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::ReconstructionAad,
                    )))?,
            )?;
            copy_request(&mut output.nonce, selection.iv())?;
            if self.shape.decrypt {
                let tag = message.tag_or_signature.ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::ReconstructionMac,
                    ),
                ))?;
                copy_request(&mut output.tag, tag)?;
                copy_request(
                    frame.expected_tag.as_mut().ok_or(Error::Rejected(
                        crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                        ),
                    ))?,
                    tag,
                )?;
            }
            let mut offset = 0usize;
            for (part_index, part) in message.fragments.iter().enumerate() {
                let part = part?;
                if self.shape.route == MessageRoute::Single {
                    let end = offset.checked_add(part.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadStorageOverflow,
                        ),
                    ))?;
                    frame.inputs[0]
                        .as_mut()
                        .get_mut(offset..end)
                        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                        )))?
                        .copy_from_slice(part);
                    offset = end;
                } else {
                    copy_request(
                        frame.inputs.get_mut(part_index).ok_or(Error::Rejected(
                            crate::RejectionReason::AeadMessages(
                                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                            ),
                        ))?,
                        part,
                    )?;
                }
            }
            if self.shape.route == MessageRoute::Single
                && offset != frame.inputs[0].as_slice().len()
            {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                )));
            }
            if index == 0 {
                if let InitBinding::Shared { nonce, tag, .. } = &mut body.init {
                    copy_request(nonce, selection.iv())?;
                    if self.shape.decrypt {
                        copy_request(
                            tag,
                            message.tag_or_signature.ok_or(Error::Rejected(
                                crate::RejectionReason::AeadMessages(
                                    crate::AeadMessagesRejection::ReconstructionMac,
                                ),
                            ))?,
                        )?;
                    }
                }
            }
            body.restore_row(index, &message)?;
        }
        let mut body = body.finish_record(self.descriptor, self.pending, next, next_fragment)?;
        if let Some(output) = self.messages.aead_batch().and_then(|state| state.output) {
            let frame = body.frames.get_mut(next).ok_or(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadCapacityRestoreRow,
                ),
            ))?;
            let capacity = body
                .outputs
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadCapacityRestoreOutputs,
                )))?
                .entries
                .get(next)
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadCapacityRestoreRow,
                )))?
                .bytes
                .capacity();
            *frame.length = bounds::ck_length(if output.prepared {
                capacity.checked_sub(frame.used).ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadCapacityRestorePrefix,
                    ),
                ))?
            } else {
                output.request.required
            })?;
            body.step = super::super::AeadStep::Output(super::super::output::Pending::from_record(
                body.step,
                output.request,
                output.prepared,
            )?);
        }
        // This prepared owner has no native role or destination possession.
        // Historical archives may include input already consumed by their saved
        // phase; never carry that obsolete history into the restored owner.
        body.discard_restored_history();
        Ok(body)
    }
}

fn data_length(message: &record::Message<'_>) -> Result<usize> {
    message.fragments.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part?.len())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageInputOverflow,
            )))
    })
}

// Legacy records encode input size; tag 7 encodes actual output allocation.
// A required length is intentionally never used as an allocation request.
fn output_capacity(
    messages: &record::Messages<'_>,
    row: &record::Message<'_>,
    data: usize,
) -> usize {
    if messages.aead_batch().is_some() {
        row.expected
    } else {
        data.max(1)
    }
}

fn restored_output(
    messages: &record::Messages<'_>,
    row: &record::Message<'_>,
    data: usize,
) -> Result<super::super::storage::OutputStorage> {
    let capacity = output_capacity(messages, row, data);
    let remaining = capacity.checked_sub(row.produced).ok_or(Error::Rejected(
        crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::AeadCapacityPrefixExceedsStorage,
        ),
    ))?;
    let offered = if row.state == record::MessageState::Finished {
        None
    } else {
        Some(remaining)
    };
    Ok(super::super::storage::OutputStorage::Restored { capacity, offered })
}
