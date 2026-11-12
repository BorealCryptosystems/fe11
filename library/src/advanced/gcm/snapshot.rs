// SPDX-License-Identifier: Apache-2.0
//! AEAD message snapshots retain shared Init targets and generated nonce state.

use super::{
    observe_generated_nonce, storage_sum, AeadMessageOperation, AeadOutcome, AeadStep,
    AeadStoragePlan, CipherKind, Frame, GeneratedNonce, InitBinding, InitReference,
    NativeParameters, Output, Outputs, PreparedAead, Requests, Selection,
};
use crate::advanced::{capture_layout::Layouts, continuation, MessageRoute, NativeActivity};
use crate::{
    module::SessionEntry,
    symmetric::memory::{Buffer, Credit, UnboundBuffer},
    Error, MessageInitLayout, Result,
};
use fe11_sys::{CK_ASYNC_DATA, CK_MECHANISM, CK_ULONG};
use std::mem::size_of;
mod record_plan;
pub(in crate::advanced) use record_plan::RecordPlan;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    kind: CipherKind,
    route: MessageRoute,
    decrypt: bool,
    rows: usize,
    lengths: usize,
    parts: usize,
    owner: usize,
    results: usize,
    shared: Option<(usize, usize)>,
    total: usize,
}
struct Description {
    origin: Selection,
    expected: usize,
    aad: usize,
    nonce: usize,
    tag: usize,
    tag_bits: u64,
    expected_tag: Option<usize>,
    generated: Option<usize>,
}
pub(in crate::advanced) struct Metadata {
    layout: Layouts,
    descriptions: Vec<Description>,
    owner: Credit,
    _description_credit: Credit,
}
pub(in crate::advanced) struct PreparedSnapshot {
    shape: Shape,
    body: PreparedAead,
}
impl AeadMessageOperation {
    pub(in crate::advanced) fn snapshot_shape(&self, entry: &SessionEntry) -> Result<Shape> {
        if self.input.is_some()
            || !self.retired_queued.is_empty()
            || self.pending()
            || !matches!(self.outcome, AeadOutcome::Nominal)
            || matches!(
                self.step,
                AeadStep::Init | AeadStep::Done | AeadStep::Failed
            )
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageNotCapturable,
            )));
        }
        self.key.check(entry)?;
        let outputs = &self
            .outputs
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
            )))?
            .entries;
        if self.frames.is_empty() || self.frames.len() != outputs.len() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )));
        }
        let mut owner = storage_sum(&[
            size_of::<AeadMessageOperation>(),
            crate::error::CleanupDiagnostic::allocation_bytes(),
            crate::error::CompletionStorage::allocation_bytes(),
            size_of::<CK_MECHANISM>(),
            size_of::<CK_ASYNC_DATA>(),
        ])?;
        let results = outputs
            .len()
            .checked_mul(size_of::<Output>())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadResultMetadataOverflow,
            )))?;
        let mut lengths = 0usize;
        let mut parts = 0usize;
        let mut buffers = 0usize;
        for (index, (frame, output)) in self.frames.iter().zip(outputs).enumerate() {
            self.queued_fragments(index)?;
            if self.init.layout()? == MessageInitLayout::InitWithOwnedMessageParameters {
                self.frames[0].origin.fixed_scalars(&frame.origin)?;
            }
            owner = storage_sum(&[
                owner,
                size_of::<Frame>(),
                size_of::<NativeParameters>(),
                size_of::<CK_ULONG>(),
                frame
                    .inputs
                    .len()
                    .checked_mul(size_of::<Buffer>())
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadInputMetadataOverflow,
                    )))?,
                frame.origin.retained_bytes(),
            ])?;
            parts = parts
                .checked_add(frame.inputs.len())
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotAccounting,
                )))?;
            lengths = lengths
                .checked_add(frame.inputs.len())
                .and_then(|n| n.checked_add(frame.layout.lengths().len()))
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotAccounting,
                )))?;
            buffers = storage_sum(&[
                buffers,
                frame.aad.capacity(),
                output.bytes.capacity(),
                output.nonce.capacity(),
                output.tag.capacity(),
                frame.expected_tag.as_ref().map_or(0, Buffer::capacity),
                generated_capacity(&frame.observed_nonce).unwrap_or(0),
                super::queued_input::Storage::required_bytes(frame.inputs.len())?,
                continuation::InputLayout::allocation_bytes(frame.layout.lengths().len())?,
            ])?;
            for input in &frame.inputs {
                buffers = storage_sum(&[buffers, input.capacity()])?;
            }
        }
        let shared = match &self.init {
            InitBinding::Declared(_) => {
                return Err(Error::Unsupported(crate::UnsupportedReason::AeadMessages(
                    crate::AeadMessagesUnsupported::DeclaredGcmMessageStateCapture,
                )))
            }
            InitBinding::WithoutParameters => None,
            InitBinding::Shared {
                nonce,
                tag,
                prepared_message,
                ..
            } => {
                let InitReference::Message(index) = prepared_message else {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadStreamInitCapturePending,
                    )));
                };
                if *index >= self.frames.len() {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadSnapshotInitIndex,
                    )));
                }
                buffers = storage_sum(&[
                    buffers,
                    nonce.capacity(),
                    tag.capacity(),
                    size_of::<NativeParameters>(),
                ])?;
                Some((nonce.capacity(), tag.capacity()))
            }
        };
        let descriptors = self
            .frames
            .len()
            .checked_mul(size_of::<Description>())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotAccounting,
            )))?;
        let total = storage_sum(&[
            owner,
            results,
            buffers,
            descriptors,
            Layouts::allocation_bytes(self.frames.len(), lengths)?,
            temporary_bytes(self.frames.len(), parts)?,
        ])?;
        Ok(Shape {
            kind: self.kind,
            route: self.route,
            decrypt: self.decrypt,
            rows: self.frames.len(),
            lengths,
            parts,
            owner,
            results,
            shared,
            total,
        })
    }
    pub(in crate::advanced) fn describe_snapshot(&self, metadata: &mut Metadata) -> Result<()> {
        let outputs = &self
            .outputs
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
            )))?
            .entries;
        if self.frames.len() != outputs.len()
            || !metadata.descriptions.is_empty()
            || metadata.descriptions.capacity() < self.frames.len()
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )));
        }
        for (index, (frame, output)) in self.frames.iter().zip(outputs).enumerate() {
            self.queued_fragments(index)?;
            metadata
                .layout
                .push(&frame.inputs, &frame.layout, output.bytes.capacity())?;
            // The full destination owner credit already includes retained
            // selection bytes before cloning any immutable nonce Arc.
            metadata.descriptions.push(Description {
                origin: frame.origin.clone(),
                expected: frame.expected,
                aad: frame.aad.capacity(),
                nonce: output.nonce.capacity(),
                tag: output.tag.capacity(),
                tag_bits: output.tag_bits,
                expected_tag: frame.expected_tag.as_ref().map(Buffer::capacity),
                generated: generated_capacity(&frame.observed_nonce),
            });
        }
        metadata.layout.complete()
    }
}
fn generated_capacity(value: &GeneratedNonce) -> Option<usize> {
    match value {
        GeneratedNonce::NotGenerated => None,
        GeneratedNonce::Awaiting(bytes) | GeneratedNonce::Observed(bytes) => Some(bytes.capacity()),
    }
}
impl Shape {
    pub(super) fn for_requests(
        requests: &Requests<'_>,
        route: MessageRoute,
        init: MessageInitLayout,
    ) -> Result<Self> {
        let plan = AeadStoragePlan::for_requests(requests, route, init)?;
        let mut parts = 0usize;
        let mut lengths = 0usize;
        for index in 0..requests.len() {
            let request = requests.get(index);
            let count = if route == MessageRoute::Single {
                1
            } else {
                request.parts.len().max(1)
            };
            parts = storage_sum(&[parts, count])?;
            lengths = storage_sum(&[lengths, count, request.parts.len()])?;
        }
        let shared = if init == MessageInitLayout::InitWithOwnedMessageParameters {
            let first = requests.get(0);
            Some((first.nonce.iv().len(), first.nonce.tag_bytes()?))
        } else {
            None
        };
        let mut shape = Self {
            kind: requests.kind(),
            route,
            decrypt: requests.decrypt(),
            rows: requests.len(),
            lengths,
            parts,
            owner: plan.owner,
            results: plan.results,
            shared,
            total: 0,
        };
        shape.total = storage_sum(&[
            plan.total,
            shape.metadata_bytes()?,
            temporary_bytes(shape.rows, shape.parts)?,
        ])?;
        Ok(shape)
    }

    pub(super) fn describe_request(
        self,
        metadata: &mut Metadata,
        requests: &Requests<'_>,
    ) -> Result<()> {
        if requests.len() != self.rows
            || requests.kind() != self.kind
            || requests.decrypt() != self.decrypt
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )));
        }
        for index in 0..self.rows {
            let request = requests.get(index);
            let expected = request.data_len()?;
            let output = expected.max(1);
            if self.route == MessageRoute::Single {
                metadata.layout.push_lengths(
                    std::iter::once(expected),
                    request.parts.iter().map(|part| part.len()),
                    output,
                )?;
            } else if request.parts.is_empty() {
                metadata
                    .layout
                    .push_lengths(std::iter::once(0), std::iter::empty(), output)?;
            } else {
                metadata.layout.push_lengths(
                    request.parts.iter().map(|part| part.len()),
                    request.parts.iter().map(|part| part.len()),
                    output,
                )?;
            }
            metadata.descriptions.push(Description {
                expected,
                aad: request.aad.len(),
                nonce: request.nonce.iv().len(),
                tag: request.nonce.tag_bytes()?,
                tag_bits: request.nonce.tag_bits(),
                expected_tag: request.tag.map(<[u8]>::len),
                generated: (!self.decrypt && request.nonce.generated())
                    .then_some(request.nonce.iv().len()),
                origin: request.nonce,
            });
        }
        metadata.layout.complete()
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> usize {
        self.total
    }
}
impl PreparedSnapshot {
    pub(super) fn fill_request(mut self, requests: &Requests<'_>) -> Result<PreparedAead> {
        if requests.len() != self.shape.rows {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )));
        }
        let outputs = &mut self
            .body
            .outputs
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
            )))?
            .entries;
        for (index, (frame, output)) in self.body.frames.iter_mut().zip(outputs).enumerate() {
            let request = requests.get(index);
            copy_request(&mut frame.aad, request.aad)?;
            copy_request(&mut output.nonce, request.nonce.iv())?;
            if let Some(tag) = request.tag {
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
            if self.shape.route == MessageRoute::Single {
                let mut offset = 0usize;
                for part in request.parts {
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
                }
                if offset != frame.inputs[0].as_slice().len() {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                    )));
                }
            } else if !request.parts.is_empty() {
                if frame.inputs.len() != request.parts.len() {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                    )));
                }
                for (destination, source) in frame.inputs.iter_mut().zip(request.parts) {
                    copy_request(destination, source)?;
                }
            }
        }
        if let InitBinding::Shared { nonce, tag, .. } = &mut self.body.init {
            let first = requests.get(0);
            copy_request(nonce, first.nonce.iv())?;
            if let Some(expected) = first.tag {
                copy_request(tag, expected)?;
            }
        }
        Ok(self.body)
    }
    pub(in crate::advanced) fn copy_from(
        mut self,
        source: &AeadMessageOperation,
        entry: &SessionEntry,
    ) -> Result<AeadMessageOperation> {
        if self.shape != source.snapshot_shape(entry)? {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )));
        }
        let outputs = &mut self
            .body
            .outputs
            .as_mut()
            .expect("prepared outputs")
            .entries;
        let originals = &source
            .outputs
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
            )))?
            .entries;
        for (target, original) in outputs.iter_mut().zip(originals) {
            target.disposition = original.disposition;
            continuation::copy(&mut target.bytes, &original.bytes)?;
            continuation::copy(&mut target.nonce, &original.nonce)?;
            continuation::copy(&mut target.tag, &original.tag)?;
        }
        for (target, original) in self.body.frames.iter_mut().zip(&source.frames) {
            if target.inputs.len() != original.inputs.len() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                )));
            }
            for (input, prior) in target.inputs.iter_mut().zip(&original.inputs) {
                continuation::copy(input, prior)?;
            }
            continuation::copy(&mut target.aad, &original.aad)?;
            match (&mut target.expected_tag, &original.expected_tag) {
                (Some(to), Some(from)) => continuation::copy(to, from)?,
                (None, None) => {}
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadSnapshotTagShapeChanged,
                    )))
                }
            }
            target.used = original.used;
            if let Some(observed) = original.observed_nonce.as_ref() {
                observe_generated_nonce(&mut target.observed_nonce, observed.as_slice())?;
            }
            *target.length = *original.length;
        }
        if let (
            InitBinding::Shared {
                nonce: prior_nonce,
                tag: prior_tag,
                prepared_message: prior_index,
                ..
            },
            InitBinding::Shared {
                params,
                nonce,
                tag,
                prepared_message,
                ..
            },
        ) = (&source.init, &mut self.body.init)
        {
            let InitReference::Message(index) = prior_index else {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadStreamInitCapturePending,
                )));
            };
            let frame = self.body.frames.get(*index).ok_or(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSnapshotInitIndex,
                ),
            ))?;
            params.set_data_length(frame.expected)?;
            *prepared_message = *prior_index;
            continuation::copy(nonce, prior_nonce)?;
            continuation::copy(tag, prior_tag)?;
        }
        self.body.step = source.step;
        self.body.activity = source.activity;
        self.body.restart_at = source.restart_at;
        Ok(self.body.bind(source.key.duplicate()?))
    }
}

fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadSnapshotAllocation,
        ))
    })?;
    Ok(values)
}
fn copy_request(destination: &mut Buffer, source: &[u8]) -> Result<()> {
    if destination.as_slice().len() != source.len() {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
        )));
    }
    destination.as_mut().copy_from_slice(source);
    Ok(())
}
fn bytes<T>(count: usize) -> Result<usize> {
    count
        .checked_mul(size_of::<T>())
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadSnapshotAccounting,
        )))
}
fn temporary_bytes(rows: usize, parts: usize) -> Result<usize> {
    storage_sum(&[
        bytes::<RowStorage>(rows)?,
        crate::advanced::capture_parts::Storage::temporary_bytes(parts)?,
    ])
}

/// Empty metadata is measured before the source can clone an immutable
/// selection. Its owner credit then covers every retained selection.
pub(in crate::advanced) struct MetadataStorage {
    shape: Shape,
    layout: crate::advanced::capture_layout::Storage,
    descriptions: Vec<Description>,
}
impl Shape {
    pub(in crate::advanced) fn metadata_bytes(self) -> Result<usize> {
        storage_sum(&[
            Layouts::allocation_bytes(self.rows, self.lengths)?,
            bytes::<Description>(self.rows)?,
        ])
    }
    pub(in crate::advanced) fn allocate_metadata(self) -> Result<MetadataStorage> {
        Ok(MetadataStorage {
            shape: self,
            layout: Layouts::allocate(self.rows, self.lengths)?,
            descriptions: reserve(self.rows)?,
        })
    }
    pub(in crate::advanced) fn allocate(self, metadata: Metadata) -> Result<Storage> {
        metadata.layout.complete()?;
        if metadata.descriptions.len() != self.rows || metadata.layout.len() != self.rows {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )));
        }
        let mut rows = reserve(self.rows)?;
        for (index, description) in metadata.descriptions.iter().enumerate() {
            let (sizes, fragments, capacity) = metadata.layout.row(index)?;
            rows.push(RowStorage {
                parts: crate::advanced::capture_parts::Storage::allocate(
                    sizes, fragments, capacity,
                )?,
                retirement: super::queued_input::Storage::allocate(sizes.len())?,
                aad: UnboundBuffer::allocate(description.aad)?,
                nonce: UnboundBuffer::allocate(description.nonce)?,
                tag: UnboundBuffer::allocate(description.tag)?,
                expected_tag: description
                    .expected_tag
                    .map(UnboundBuffer::allocate)
                    .transpose()?,
                generated: description
                    .generated
                    .map(UnboundBuffer::allocate)
                    .transpose()?,
            });
        }
        Ok(Storage {
            cleanup_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            return_diagnostic: crate::error::CompletionStorage::allocate()?,
            result_credit: None,
            temporary_credit: None,
            shape: self,
            metadata: StorageMetadata {
                descriptions: metadata.descriptions,
                retention: Retention::Captured {
                    owner: metadata.owner,
                    _layout: metadata.layout,
                    _descriptions: metadata._description_credit,
                },
            },
            rows,
            frames: reserve(self.rows)?,
            outputs: reserve(self.rows)?,
            shared: self
                .shared
                .map(|(nonce, tag)| {
                    Ok((
                        UnboundBuffer::allocate(nonce)?,
                        UnboundBuffer::allocate(tag)?,
                    ))
                })
                .transpose()?,
        })
    }
}
impl MetadataStorage {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        storage_sum(&[
            self.layout.allocated_bytes()?,
            bytes::<Description>(self.descriptions.capacity())?,
        ])
    }
    pub(in crate::advanced) fn bind(self, prepaid: &mut Credit) -> Result<Metadata> {
        Ok(Metadata {
            owner: prepaid.split(self.shape.owner)?,
            _description_credit: prepaid
                .split(bytes::<Description>(self.descriptions.capacity())?)?,
            layout: self.layout.bind(prepaid)?,
            descriptions: self.descriptions,
        })
    }
}
struct RowStorage {
    parts: crate::advanced::capture_parts::Storage,
    retirement: super::queued_input::Storage,
    aad: UnboundBuffer,
    nonce: UnboundBuffer,
    tag: UnboundBuffer,
    expected_tag: Option<UnboundBuffer>,
    generated: Option<UnboundBuffer>,
}
/// Capture descriptions already own credits; archive descriptions are covered
/// by the enclosing reservation until the whole candidate has been measured.
struct StorageMetadata {
    descriptions: Vec<Description>,
    retention: Retention,
}
enum Retention {
    Captured {
        owner: Credit,
        _layout: Layouts,
        _descriptions: Credit,
    },
    Record,
    Admitted {
        owner: Credit,
        _descriptions: Credit,
    },
}
impl StorageMetadata {
    fn unbound_bytes(&self) -> Result<usize> {
        if matches!(self.retention, Retention::Record) {
            bytes::<Description>(self.descriptions.capacity())
        } else {
            Ok(0)
        }
    }
    fn admit(&mut self, prepaid: &mut Credit, base: usize, actual: usize) -> Result<()> {
        match &mut self.retention {
            Retention::Captured { owner, .. } => {
                owner.merge(prepaid.split(actual.checked_sub(base).ok_or(
                    Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadSnapshotAccounting,
                    )),
                )?)?)?
            }
            Retention::Record => {
                self.retention = Retention::Admitted {
                    owner: prepaid.split(actual)?,
                    _descriptions: prepaid
                        .split(bytes::<Description>(self.descriptions.capacity())?)?,
                };
            }
            Retention::Admitted { .. } => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadStorageAlreadyBound,
                )))
            }
        }
        Ok(())
    }
    fn into_owner(self) -> Result<Credit> {
        let Self {
            descriptions,
            retention,
        } = self;
        // Empty descriptions still own their vector allocation. Free it before
        // releasing its credit, whose notification may wake another allocator.
        drop(descriptions);
        match retention {
            Retention::Captured { owner, .. } | Retention::Admitted { owner, .. } => Ok(owner),
            Retention::Record => Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadStorageNotBound,
            ))),
        }
    }
}
/// No native pointer or key lease is bound while any capacity is undecided.
pub(in crate::advanced) struct Storage {
    shape: Shape,
    rows: Vec<RowStorage>,
    frames: Vec<Frame>,
    outputs: Vec<Output>,
    shared: Option<(UnboundBuffer, UnboundBuffer)>,
    cleanup_diagnostic: crate::error::CleanupDiagnostic,
    return_diagnostic: crate::error::CompletionStorage,
    result_credit: Option<Credit>,
    temporary_credit: Option<Credit>,
    // A failed bind may already have moved selections into frames. Keep the
    // owner credit alive until those partially bound frames have been dropped.
    metadata: StorageMetadata,
}
impl Storage {
    fn owner_bytes(&self) -> Result<usize> {
        let mut total = self
            .shape
            .owner
            .checked_sub(bytes::<Frame>(self.shape.rows)?)
            .and_then(|n| n.checked_sub(self.shape.parts.checked_mul(size_of::<Buffer>())?))
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotAccounting,
            )))?;
        total = storage_sum(&[total, bytes::<Frame>(self.frames.capacity())?])?;
        for row in &self.rows {
            total = storage_sum(&[total, row.parts.input_metadata_bytes()?])?;
        }
        Ok(total)
    }
    /// The caller separately counts the still-owned layout and descriptions.
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        let mut total = storage_sum(&[
            self.owner_bytes()?,
            bytes::<Output>(self.outputs.capacity())?,
            bytes::<RowStorage>(self.rows.capacity())?,
            self.metadata.unbound_bytes()?,
        ])?;
        for row in &self.rows {
            total = storage_sum(&[
                total,
                row.parts.allocated_bytes()?,
                row.retirement.allocated_bytes()?,
                row.aad.allocated(),
                row.nonce.allocated(),
                row.tag.allocated(),
                row.expected_tag
                    .as_ref()
                    .map_or(0, UnboundBuffer::allocated),
                row.generated.as_ref().map_or(0, UnboundBuffer::allocated),
            ])?;
        }
        if let Some((nonce, tag)) = &self.shared {
            total = storage_sum(&[
                total,
                nonce.allocated(),
                tag.allocated(),
                size_of::<NativeParameters>(),
            ])?;
        }
        Ok(total)
    }
    pub(in crate::advanced) fn bind(mut self, prepaid: &mut Credit) -> Result<PreparedSnapshot> {
        let owner_bytes = self.owner_bytes()?;
        self.metadata
            .admit(prepaid, self.shape.owner, owner_bytes)?;
        // Partial row binding leaves its storage in this envelope. Retain
        // each table's charge here until the corresponding table is gone.
        self.result_credit = Some(prepaid.split(bytes::<Output>(self.outputs.capacity())?)?);
        self.temporary_credit = Some(prepaid.split(bytes::<RowStorage>(self.rows.capacity())?)?);
        for (row, description) in self
            .rows
            .drain(..)
            .zip(self.metadata.descriptions.drain(..))
        {
            let parts = row.parts.bind(prepaid)?;
            let mut output = Output {
                disposition: crate::advanced::gcm::result::Disposition::Candidate,
                bytes: parts.output,
                nonce: row.nonce.bind(prepaid)?,
                tag: row.tag.bind(prepaid)?,
                tag_bits: description.tag_bits,
            };
            let params = Box::new(NativeParameters::new(
                &description.origin,
                description.expected,
                output.nonce.as_mut().as_mut_ptr(),
                output.tag.as_mut().as_mut_ptr(),
            )?);
            self.frames.push(Frame {
                params,
                aad: row.aad.bind(prepaid)?,
                inputs: parts.inputs,
                retirement: Some(row.retirement.bind(prepaid)?),
                layout: parts.layout,
                length: Box::new(0),
                expected: description.expected,
                used: 0,
                accepted_input: None,
                origin: description.origin,
                observed_nonce: match row.generated {
                    Some(buffer) => GeneratedNonce::Awaiting(buffer.bind(prepaid)?),
                    None => GeneratedNonce::NotGenerated,
                },
                expected_tag: row
                    .expected_tag
                    .map(|buffer| buffer.bind(prepaid))
                    .transpose()?,
            });
            self.outputs.push(output);
        }
        drop(self.rows);
        drop(self.temporary_credit.take());
        let mut frames = self.frames;
        let outputs = self.outputs;
        let shape = self.shape;
        let mut init = match self.shared {
            None => InitBinding::WithoutParameters,
            Some((nonce, tag)) => {
                let mut nonce = nonce.bind(prepaid)?;
                let mut tag = tag.bind(prepaid)?;
                let first =
                    frames
                        .first()
                        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
                        )))?;
                let params = Box::new(NativeParameters::new(
                    &first.origin,
                    first.expected,
                    nonce.as_mut().as_mut_ptr(),
                    tag.as_mut().as_mut_ptr(),
                )?);
                InitBinding::Shared {
                    params,
                    nonce,
                    tag,
                    prepared_message: InitReference::Message(0),
                    seed: None,
                    _metadata: prepaid.split(size_of::<NativeParameters>())?,
                }
            }
        };
        let mut mechanism = Box::new(CK_MECHANISM {
            mechanism: shape.kind.mechanism(),
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        });
        if let InitBinding::Shared {
            params, nonce, tag, ..
        } = &mut init
        {
            mechanism.pParameter = params.pointer_mut();
            mechanism.ulParameterLen = params.size();
            for frame in &mut frames {
                frame
                    .params
                    .bind(nonce.as_mut().as_mut_ptr(), tag.as_mut().as_mut_ptr());
            }
        }
        let layout = init.layout()?;
        // Keep the metadata charge in the storage envelope through every
        // fallible Init binding above, including its unconsumed error leaves.
        let owner_credit = self.metadata.into_owner()?;
        Ok(PreparedSnapshot {
            shape,
            body: PreparedAead {
                input: None,
                kind: shape.kind,
                route: shape.route,
                decrypt: shape.decrypt,
                outcome: AeadOutcome::Nominal,
                step: AeadStep::Init,
                activity: NativeActivity::Inactive,
                mechanism,
                init,
                frames,
                outputs: Some(Outputs {
                    entries: outputs,
                    init: layout,
                    _credit: self.result_credit.take().expect("bound AEAD result credit"),
                }),
                restart_at: 0,
                completion: Box::new(crate::native::output::async_data()),
                name: [0; 32],
                cleanup_diagnostic: Some(self.cleanup_diagnostic),
                return_diagnostic: Some(self.return_diagnostic),
                _metadata: owner_credit,
            },
        })
    }
}
