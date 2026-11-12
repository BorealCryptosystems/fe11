// SPDX-License-Identifier: Apache-2.0
//! Message snapshot preparation retains shape metadata, never source borrows.
mod record_plan;
use super::{
    MacMessage, MacOperation, MacStorage, MessageSignatures, MessageStep, PreparedMac, PssFrame,
};
use crate::advanced::{capture_layout::Layouts, continuation, MessageRoute, NativeActivity};
use crate::{
    bounds,
    module::SessionEntry,
    symmetric::memory::{Buffer, Credit},
    Error, Result,
};
use fe11_sys::{CK_ASYNC_DATA, CK_MECHANISM, CK_MECHANISM_TYPE, CK_RSA_PKCS_PSS_PARAMS, CK_ULONG};
pub(in crate::advanced) use record_plan::RecordPlan;
use std::mem::size_of;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    input: crate::advanced::input::InputState,
    invalid_seen: bool,
    // Independent of row layouts: consumed stream fragments are not retained.
    fragment: Option<usize>,
    rows: usize,
    parts: usize,
    lengths: usize,
    storage: MacStorage,
    kind: CK_MECHANISM_TYPE,
    route: MessageRoute,
    verify: bool,
    size: usize,
    pss: Option<crate::RsaPssParameters>,
}
pub(in crate::advanced) struct PreparedSnapshot {
    shape: Shape,
    frame: PreparedMac,
}
impl MacOperation {
    pub(in crate::advanced) fn snapshot_shape(&self, entry: &SessionEntry) -> Result<Shape> {
        if self.pending()
            || self.outcome.closing()
            || !self.outcome.valid() && !self.input.incremental
            || matches!(
                self.step,
                MessageStep::Init | MessageStep::Done | MessageStep::Failed
            )
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageNotCapturable,
            )));
        }
        self.key.check(entry)?;
        let fragment = if self.input.incremental {
            let expected = self.current_input_bytes()?;
            if expected != self.stream_fragment.as_ref().map(Buffer::capacity)
                || self.inputs.iter().any(|row| !row.is_empty())
                || self.layouts.iter().any(|row| !row.lengths().is_empty())
            {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageStreamSnapshotShape,
                )));
            }
            expected
        } else {
            if self.stream_fragment.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::BufferedMessageHasStreamFragment,
                )));
            }
            None
        };
        let outputs = &self
            .signatures
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultsAbsent,
            )))?
            .bytes;
        if self.inputs.len() != self.layouts.len()
            || self.inputs.len() != self.lengths.len()
            || self.inputs.len() != outputs.len()
            || self.inputs.len()
                != self
                    .signatures
                    .as_ref()
                    .expect("checked results")
                    .rejections
                    .len()
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
            )));
        }
        if self
            .pss
            .as_ref()
            .is_some_and(|p| !p.unchanged().unwrap_or(false))
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::PssSnapshotParameterIdentity,
            )));
        }
        let pss = self.pss.as_ref().map(|p| p.selection);
        let fixed = size_of::<MacOperation>()
            + crate::error::CleanupDiagnostic::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes()
            + size_of::<CK_MECHANISM>()
            + size_of::<CK_ASYNC_DATA>()
            + usize::from(pss.is_some()) * size_of::<CK_RSA_PKCS_PSS_PARAMS>();
        let parts = self
            .inputs
            .iter()
            .try_fold(0usize, |n, row| n.checked_add(row.len()))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessagePartOverflow,
            )))?;
        let fragments = self
            .layouts
            .iter()
            .try_fold(0usize, |n, row| n.checked_add(row.lengths().len()))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessagePartOverflow,
            )))?;
        let metadata = parts
            .checked_mul(size_of::<Buffer>())
            .and_then(|n| {
                self.inputs
                    .len()
                    .checked_mul(
                        size_of::<Vec<Buffer>>()
                            + size_of::<continuation::InputLayout>()
                            + size_of::<Box<CK_ULONG>>()
                            + size_of::<CK_ULONG>(),
                    )
                    .and_then(|rows| n.checked_add(rows))
            })
            .and_then(|n| n.checked_add(fixed))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageMetadataOverflow,
            )))?;
        let results = outputs
            .len()
            .checked_mul(size_of::<Buffer>() + size_of::<Option<crate::NativeMessageRejection>>())
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultMetadata,
            )))?;
        let total = self
            .inputs
            .iter()
            .flatten()
            .chain(outputs.iter())
            .chain(self.stream_fragment.iter())
            .try_fold(
                metadata
                    .checked_add(results)
                    .and_then(|n| {
                        fragments
                            .checked_mul(size_of::<usize>())
                            .and_then(|f| n.checked_add(f))
                    })
                    .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::MessageMetadataOverflow,
                    )))?,
                |n, buffer| {
                    n.checked_add(buffer.capacity()).ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageByteOverflow,
                        ),
                    ))
                },
            )?;
        Ok(Shape {
            input: self.input,
            invalid_seen: !self.outcome.valid(),
            fragment,
            rows: self.inputs.len(),
            parts,
            lengths: parts.checked_add(fragments).ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessagePartOverflow,
                ),
            ))?,
            storage: MacStorage {
                metadata,
                results,
                total,
            },
            kind: self.kind,
            route: self.route,
            verify: self.verify,
            size: self.size,
            pss,
        })
    }
    pub(in crate::advanced) fn describe_snapshot(&self, layout: &mut Layouts) -> Result<()> {
        let outputs = &self
            .signatures
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultsAbsent,
            )))?
            .bytes;
        if self.inputs.len() != self.layouts.len() || self.inputs.len() != outputs.len() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
            )));
        }
        for ((inputs, fragments), output) in self.inputs.iter().zip(&self.layouts).zip(outputs) {
            if self.input.incremental {
                if !inputs.is_empty() || !fragments.lengths().is_empty() {
                    return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::MessageStreamSnapshotRow,
                    )));
                }
            } else {
                fragments.fragments(inputs, self.route)?;
            }
            layout.push(inputs, fragments, output.capacity())?;
        }
        layout.complete()
    }
}
impl Shape {
    pub(super) fn for_request(
        kind: CK_MECHANISM_TYPE,
        size: usize,
        messages: &[MacMessage<'_>],
        expected: Option<&[&[u8]]>,
        route: MessageRoute,
        pss: Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<Self> {
        let storage = MacStorage::for_messages(size, messages, expected, route, pss.is_some())?;
        let parts = messages.iter().try_fold(0usize, |n, message| {
            n.checked_add(if route == MessageRoute::Single {
                1
            } else {
                message.parts.len().max(1)
            })
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessagePartOverflow,
            )))
        })?;
        let fragments = messages.iter().try_fold(0usize, |n, message| {
            n.checked_add(message.parts.len()).ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessagePartOverflow,
                ),
            ))
        })?;
        let pss = pss
            .as_ref()
            .map(crate::RsaPssParameters::from_native)
            .transpose()?;
        if let Some(selection) = pss {
            if selection.mechanism(crate::HashExecution::Pkcs11Combined)? != kind {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::PssMessageMechanismMismatch,
                )));
            }
        }
        Ok(Self {
            input: crate::advanced::input::InputState::closed(),
            invalid_seen: false,
            fragment: None,
            rows: messages.len(),
            parts,
            lengths: parts.checked_add(fragments).ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessagePartOverflow,
                ),
            ))?,
            storage,
            kind,
            route,
            verify: expected.is_some(),
            size,
            pss,
        })
    }

    pub(super) fn request_bytes(self) -> Result<usize> {
        self.storage
            .total
            .checked_add(self.temporary_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSnapshotAccounting,
            )))
    }

    pub(super) fn allocate_request(
        self,
        messages: &[MacMessage<'_>],
        expected: Option<&[&[u8]]>,
    ) -> Result<Storage> {
        use crate::symmetric::memory::UnboundBuffer;
        if messages.len() != self.rows
            || expected.is_some() != self.verify
            || expected.is_some_and(|values| values.len() != self.rows)
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
            )));
        }
        let mut rows = reserve(self.rows)?;
        let mut lengths = reserve(self.rows)?;
        for (index, message) in messages.iter().enumerate() {
            let count = if self.route == MessageRoute::Single {
                1
            } else {
                message.parts.len().max(1)
            };
            let mut parts = reserve(count)?;
            if self.route == MessageRoute::Single {
                let input = message.parts.iter().try_fold(0usize, |n, part| {
                    n.checked_add(part.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageByteOverflow,
                        ),
                    ))
                })?;
                parts.push(UnboundBuffer::allocate(input)?);
            } else if message.parts.is_empty() {
                parts.push(UnboundBuffer::allocate(0)?);
            } else {
                for part in message.parts {
                    parts.push(UnboundBuffer::allocate(part.len())?);
                }
            }
            let mut fragments = reserve(message.parts.len())?;
            fragments.extend(message.parts.iter().map(|part| part.len()));
            let output = expected.map_or(self.size, |values| values[index].len());
            rows.push(RowStorage {
                parts,
                destination: reserve(count)?,
                fragments,
                output: UnboundBuffer::allocate(output)?,
            });
            lengths.push(Box::new(bounds::ck_length(output)?));
        }
        Ok(Storage {
            shape: self,
            stream_fragment: None,
            rows,
            inputs: reserve(self.rows)?,
            outputs: reserve(self.rows)?,
            rejections: reserve(self.rows)?,
            layouts: reserve(self.rows)?,
            lengths,
            cleanup_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
            result_credit: None,
            temporary_credit: None,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> Result<usize> {
        let temporary = self.temporary_bytes()?;
        self.storage
            .total
            .checked_add(Layouts::allocation_bytes(self.rows, self.lengths)?)
            .and_then(|n| n.checked_add(temporary))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSnapshotAccounting,
            )))
    }
    pub(in crate::advanced) fn layout_bytes(self) -> Result<usize> {
        Layouts::allocation_bytes(self.rows, self.lengths)
    }
    pub(in crate::advanced) fn allocate_layout(
        self,
    ) -> Result<crate::advanced::capture_layout::Storage> {
        Layouts::allocate(self.rows, self.lengths)
    }
    fn temporary_bytes(self) -> Result<usize> {
        self.rows
            .checked_mul(size_of::<RowStorage>())
            .and_then(|n| {
                self.parts
                    .checked_mul(size_of::<crate::symmetric::memory::UnboundBuffer>())
                    .and_then(|v| n.checked_add(v))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSnapshotAccounting,
            )))
    }
    pub(in crate::advanced) fn allocate(self, layout: &Layouts) -> Result<Storage> {
        Storage::allocate(self, layout)
    }
}
impl PreparedSnapshot {
    pub(super) fn fill_request(
        mut self,
        messages: &[MacMessage<'_>],
        expected: Option<&[&[u8]]>,
    ) -> Result<PreparedMac> {
        if messages.len() != self.shape.rows
            || expected.is_some() != self.shape.verify
            || expected.is_some_and(|values| values.len() != self.shape.rows)
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
            )));
        }
        for (destination, message) in self.frame.inputs.iter_mut().zip(messages) {
            if self.shape.route == MessageRoute::Single {
                let mut offset = 0usize;
                for part in message.parts {
                    let end = offset.checked_add(part.len()).ok_or(Error::Rejected(
                        crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageByteOverflow,
                        ),
                    ))?;
                    destination[0]
                        .as_mut()
                        .get_mut(offset..end)
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                        )))?
                        .copy_from_slice(part);
                    offset = end;
                }
                if offset != destination[0].as_slice().len() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                    )));
                }
            } else if !message.parts.is_empty() {
                if destination.len() != message.parts.len() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                    )));
                }
                for (target, part) in destination.iter_mut().zip(message.parts) {
                    if target.as_slice().len() != part.len() {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                        )));
                    }
                    target.as_mut().copy_from_slice(part);
                }
            }
        }
        if let Some(expected) = expected {
            let outputs = &mut self
                .frame
                .signatures
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageResultsAbsent,
                )))?
                .bytes;
            for (output, source) in outputs.iter_mut().zip(expected) {
                if output.as_slice().len() != source.len() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                    )));
                }
                output.as_mut().copy_from_slice(source);
            }
        }
        Ok(self.frame)
    }
    pub(in crate::advanced) fn copy_from(
        mut self,
        source: &MacOperation,
        entry: &SessionEntry,
    ) -> Result<MacOperation> {
        if self.shape != source.snapshot_shape(entry)? {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
            )));
        }
        match (&mut self.frame.stream_fragment, &source.stream_fragment) {
            (Some(target), Some(original)) => continuation::copy(target, original)?,
            (None, None) => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageStreamSnapshotFragment,
                )))
            }
        }
        for (targets, originals) in self.frame.inputs.iter_mut().zip(&source.inputs) {
            if targets.len() != originals.len() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::MessageSnapshotShapeChanged,
                )));
            }
            for (target, original) in targets.iter_mut().zip(originals) {
                continuation::copy(target, original)?;
            }
        }
        let targets = &mut self
            .frame
            .signatures
            .as_mut()
            .expect("prepared signatures")
            .bytes;
        let originals = &source
            .signatures
            .as_ref()
            .expect("checked source signatures")
            .bytes;
        for (target, original) in targets.iter_mut().zip(originals) {
            continuation::copy(target, original)?;
        }
        for (target, original) in self.frame.lengths.iter_mut().zip(&source.lengths) {
            **target = **original;
        }
        self.frame
            .signatures
            .as_mut()
            .expect("prepared signatures")
            .rejections
            .copy_from_slice(
                &source
                    .signatures
                    .as_ref()
                    .expect("checked source signatures")
                    .rejections,
            );
        self.frame.step = source.step;
        self.frame.activity = source.activity;
        Ok(self.frame.bind(source.key.duplicate()?))
    }
}

struct RowStorage {
    parts: Vec<crate::symmetric::memory::UnboundBuffer>,
    destination: Vec<Buffer>,
    fragments: Vec<usize>,
    output: crate::symmetric::memory::UnboundBuffer,
}
pub(in crate::advanced) struct Storage {
    shape: Shape,
    stream_fragment: Option<crate::symmetric::memory::UnboundBuffer>,
    rows: Vec<RowStorage>,
    inputs: Vec<Vec<Buffer>>,
    outputs: Vec<Buffer>,
    rejections: Vec<Option<crate::NativeMessageRejection>>,
    layouts: Vec<continuation::InputLayout>,
    lengths: Vec<Box<CK_ULONG>>,
    cleanup_diagnostic: crate::error::CleanupDiagnostic,
    completion_diagnostic: crate::error::CompletionStorage,
    // Binding can fail after moving only part of a row. These independent
    // credits leave after all remaining tables and diagnostic leaves, not
    // before `self` as early locals would on a fallible return.
    metadata_credit: Option<Credit>,
    result_credit: Option<Credit>,
    temporary_credit: Option<Credit>,
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageAllocation,
        ))
    })?;
    Ok(values)
}
fn sum(values: &[usize]) -> Result<usize> {
    values
        .iter()
        .try_fold(0usize, |n, v| n.checked_add(*v))
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSnapshotAccounting,
        )))
}
fn vector_bytes<T>(values: &Vec<T>) -> Result<usize> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSnapshotAccounting,
        )))
}
impl Storage {
    fn allocate(shape: Shape, layout: &Layouts) -> Result<Self> {
        use crate::symmetric::memory::UnboundBuffer;
        layout.complete()?;
        if layout.len() != shape.rows {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSnapshotRowCount,
            )));
        }
        let mut rows = reserve(shape.rows)?;
        let mut lengths = reserve(shape.rows)?;
        for i in 0..shape.rows {
            let (sizes, fragments, output) = layout.row(i)?;
            let mut parts = reserve(sizes.len())?;
            for &size in sizes {
                parts.push(UnboundBuffer::allocate(size)?);
            }
            let mut owned_fragments = reserve(fragments.len())?;
            owned_fragments.extend_from_slice(fragments);
            rows.push(RowStorage {
                parts,
                destination: reserve(sizes.len())?,
                fragments: owned_fragments,
                output: UnboundBuffer::allocate(output)?,
            });
            lengths.push(Box::new(bounds::ck_length(output)?));
        }
        Ok(Self {
            shape,
            stream_fragment: shape.fragment.map(UnboundBuffer::allocate).transpose()?,
            rows,
            inputs: reserve(shape.rows)?,
            outputs: reserve(shape.rows)?,
            rejections: reserve(shape.rows)?,
            layouts: reserve(shape.rows)?,
            lengths,
            cleanup_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
            result_credit: None,
            temporary_credit: None,
        })
    }
    fn metadata_bytes(&self) -> Result<usize> {
        let fixed = size_of::<MacOperation>()
            + crate::error::CleanupDiagnostic::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes()
            + size_of::<CK_MECHANISM>()
            + size_of::<CK_ASYNC_DATA>()
            + usize::from(self.shape.pss.is_some()) * size_of::<CK_RSA_PKCS_PSS_PARAMS>();
        let native_lengths =
            self.shape
                .rows
                .checked_mul(size_of::<CK_ULONG>())
                .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageSnapshotAccounting,
                )))?;
        let mut total = sum(&[
            fixed,
            native_lengths,
            vector_bytes(&self.inputs)?,
            vector_bytes(&self.layouts)?,
            vector_bytes(&self.lengths)?,
        ])?;
        for row in &self.rows {
            total = sum(&[total, vector_bytes(&row.destination)?])?;
        }
        Ok(total)
    }
    fn temporary_bytes(&self) -> Result<usize> {
        let mut total = vector_bytes(&self.rows)?;
        for row in &self.rows {
            total = sum(&[total, vector_bytes(&row.parts)?])?;
        }
        Ok(total)
    }
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        let mut total = sum(&[
            self.metadata_bytes()?,
            vector_bytes(&self.outputs)?,
            vector_bytes(&self.rejections)?,
            self.temporary_bytes()?,
            self.stream_fragment
                .as_ref()
                .map_or(0, |part| part.allocated()),
        ])?;
        for row in &self.rows {
            total = sum(&[total, vector_bytes(&row.fragments)?, row.output.allocated()])?;
            for part in &row.parts {
                total = sum(&[total, part.allocated()])?;
            }
        }
        Ok(total)
    }
    pub(in crate::advanced) fn bind(mut self, prepaid: &mut Credit) -> Result<PreparedSnapshot> {
        self.metadata_credit = Some(prepaid.split(self.metadata_bytes()?)?);
        self.result_credit = Some(prepaid.split(sum(&[
            vector_bytes(&self.outputs)?,
            vector_bytes(&self.rejections)?,
        ])?)?);
        self.temporary_credit = Some(prepaid.split(self.temporary_bytes()?)?);
        let stream_fragment = self
            .stream_fragment
            .take()
            .map(|part| part.bind(prepaid))
            .transpose()?;
        for mut row in self.rows.drain(..) {
            for part in row.parts.drain(..) {
                row.destination.push(part.bind(prepaid)?);
            }
            self.inputs.push(row.destination);
            self.outputs.push(row.output.bind(prepaid)?);
            self.rejections.push(None);
            self.layouts
                .push(continuation::InputLayout::from_owned_lengths(
                    prepaid,
                    row.fragments,
                )?);
        }
        drop(self.rows);
        drop(self.temporary_credit.take());
        let shape = self.shape;
        let inputs = self.inputs;
        let outputs = self.outputs;
        let rejections = self.rejections;
        let layouts = self.layouts;
        let lengths = self.lengths;
        let mut pss = shape
            .pss
            .map(|selection| PssFrame::new(selection.checked()?))
            .transpose()?;
        if let Some(parameters) = &pss {
            if parameters
                .selection
                .mechanism(crate::HashExecution::Pkcs11Combined)?
                != shape.kind
            {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::PssMessageMechanismMismatch,
                )));
            }
        }
        let (pointer, length) = pss.as_mut().map_or((std::ptr::null_mut(), 0), |p| {
            (
                (&mut **p as *mut CK_RSA_PKCS_PSS_PARAMS).cast(),
                size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
            )
        });
        Ok(PreparedSnapshot {
            shape,
            frame: PreparedMac {
                input: shape.input,
                invalid_seen: shape.invalid_seen,
                stream_fragment,
                step: MessageStep::Init,
                activity: NativeActivity::Inactive,
                kind: shape.kind,
                route: shape.route,
                verify: shape.verify,
                size: shape.size,
                mechanism: Box::new(CK_MECHANISM {
                    mechanism: shape.kind,
                    pParameter: pointer,
                    ulParameterLen: length,
                }),
                pss,
                inputs,
                layouts,
                signatures: Some(MessageSignatures {
                    bytes: outputs,
                    rejections,
                    _metadata: self
                        .result_credit
                        .take()
                        .expect("bound message result credit"),
                }),
                lengths,
                completion: Box::new(crate::native::output::async_data()),
                name: [0; 32],
                cleanup_diagnostic: Some(self.cleanup_diagnostic),
                completion_diagnostic: Some(self.completion_diagnostic),
                _metadata: self
                    .metadata_credit
                    .take()
                    .expect("bound message metadata credit"),
            },
        })
    }
}


