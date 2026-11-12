// SPDX-License-Identifier: Apache-2.0
//! Standalone cipher snapshots keep negotiation and output capacity separate.
use super::{
    parameters::snapshot::Snapshot as Parameters, parameters::Selection, CipherOperation,
    CipherOutputPlan, CipherStorage, Direction, OutputStorage, PreparedCipher,
};
use crate::advanced::{capture_layout::Layouts, continuation, MessageRoute};
use crate::{
    module::SessionEntry,
    symmetric::memory::{Buffer, Credit},
    Error, Result,
};
use fe11_sys::{CK_MECHANISM, CK_ULONG};
use std::mem::size_of;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    direction: Direction,
    route: MessageRoute,
    parts: usize,
    fragments: usize,
    expected: usize,
    graph_packet: Option<usize>,
    minimum: usize,
    maximum: usize,
    metadata: usize,
    total: usize,
}
pub(in crate::advanced) struct PreparedSnapshot {
    shape: Shape,
    frame: PreparedCipher,
}
/// Initial classic request, sized without retaining any destination credit.
pub(super) struct Request<'a> {
    parameter_input: super::parameters::ParameterInput,
    shape: Shape,
    selection: Selection<'a>,
    output: usize,
}
impl<'a> Request<'a> {
    pub(super) fn incremental(
        direction: Direction,
        selection: Selection<'a>,
        output: CipherOutputPlan,
        ccm_data_length: Option<u64>,
    ) -> Result<Self> {
        let plan = CipherStorage::for_shape(
            direction,
            MessageRoute::Multipart,
            selection,
            0,
            0,
            OutputStorage::Initial(output),
            true,
        )?;
        let mut request = Self::with_plan(direction, MessageRoute::Multipart, selection, 0, plan)?;
        request.parameter_input =
            super::parameters::ParameterInput::Incremental { ccm_data_length };
        Ok(request)
    }

    pub(super) fn new(
        direction: Direction,
        route: MessageRoute,
        selection: Selection<'a>,
        parts: &[&[u8]],
        output: CipherOutputPlan,
    ) -> Result<Self> {
        let plan = CipherStorage::for_request(direction, route, selection, parts, output)?;
        Self::with_plan(direction, route, selection, parts.len(), plan)
    }
    pub(super) fn for_record(
        direction: Direction,
        selection: Selection<'a>,
        message: &crate::advanced::record::Message<'_>,
        input: usize,
        output: OutputStorage,
        incremental: bool,
        established_input: u128,
        ccm_data_length: Option<u64>,
    ) -> Result<Self> {
        // Allocate the remaining input only; mechanism framing still knows
        // the complete input size of a complete-input facade (not its history).
        let mut plan = CipherStorage::for_shape(
            direction,
            message.route,
            selection,
            message.fragments.len(),
            input,
            output,
            true,
        )?;
        let parameter_input = if incremental {
            input
        } else {
            usize::try_from(established_input)
                .ok()
                .and_then(|n| n.checked_add(input))
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherCompleteInputSizeOverflow,
                )))?
        };
        if !incremental {
            (plan.minimum, plan.maximum) =
                selection.output_bounds(parameter_input, direction.decrypts())?;
        }
        let mut request = Self::with_plan(
            direction,
            message.route,
            selection,
            message.fragments.len(),
            plan,
        )?;
        request.parameter_input = if incremental {
            super::parameters::ParameterInput::Incremental { ccm_data_length }
        } else {
            super::parameters::ParameterInput::Complete(parameter_input)
        };
        Ok(request)
    }
    fn with_plan(
        direction: Direction,
        route: MessageRoute,
        selection: Selection<'a>,
        fragments: usize,
        plan: CipherStorage,
    ) -> Result<Self> {
        let temporary = crate::advanced::capture_parts::Storage::temporary_bytes(plan.count)?;
        Ok(Self {
            parameter_input: super::parameters::ParameterInput::Complete(plan.total),
            shape: Shape {
                direction,
                route,
                parts: plan.count,
                fragments,
                expected: plan.total,
                graph_packet: None,
                minimum: plan.minimum,
                maximum: plan.maximum,
                metadata: plan.metadata,
                total: plan.peak.checked_add(temporary).ok_or(Error::Rejected(
                    crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherSnapshotAccounting,
                    ),
                ))?,
            },
            selection,
            output: plan.output_capacity,
        })
    }
    pub(super) fn allocation_bytes(&self) -> usize {
        self.shape.total
    }
    pub(super) fn allocate(&self, parts: &[&[u8]], prepaid: &mut Credit) -> Result<Storage<'a>> {
        if parts.len() != self.shape.fragments {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
            )));
        }
        let parameters = Parameters::for_selection(
            self.selection,
            self.parameter_input,
            self.shape.direction.decrypts(),
            prepaid,
        )?
        .allocate()?;
        let buffers = if self.shape.route == MessageRoute::Single {
            crate::advanced::capture_parts::Storage::allocate_lengths(
                std::iter::once(self.shape.expected),
                parts.iter().map(|part| part.len()),
                self.output,
            )?
        } else if parts.is_empty() {
            crate::advanced::capture_parts::Storage::allocate_lengths(
                std::iter::once(0),
                std::iter::empty(),
                self.output,
            )?
        } else {
            crate::advanced::capture_parts::Storage::allocate_lengths(
                parts.iter().map(|part| part.len()),
                parts.iter().map(|part| part.len()),
                self.output,
            )?
        };
        Ok(Storage {
            shape: self.shape,
            parts: buffers,
            retirement: super::retirement::Storage::allocate(self.shape.parts, true)?,
            parameters,
            extra: crate::symmetric::memory::UnboundBuffer::allocate(self.shape.expected)?,
        })
    }
    pub(super) fn allocate_record(
        &self,
        fragments: crate::advanced::record::Fragments<'_>,
        prepaid: &mut Credit,
    ) -> Result<Storage<'a>> {
        if fragments.len() != self.shape.fragments {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
            )));
        }
        let parameters = Parameters::for_selection(
            self.selection,
            self.parameter_input,
            self.shape.direction.decrypts(),
            prepaid,
        )?
        .allocate()?;
        let buffers = if self.shape.route == MessageRoute::Single {
            crate::advanced::capture_parts::Storage::allocate_fallible(
                1,
                std::iter::once(Ok(self.shape.expected)),
                fragments.len(),
                fragments.iter().map(|part| part.map(<[u8]>::len)),
                self.output,
            )?
        } else if fragments.len() == 0 {
            crate::advanced::capture_parts::Storage::allocate_fallible(
                1,
                std::iter::once(Ok(0)),
                0,
                std::iter::empty(),
                self.output,
            )?
        } else {
            crate::advanced::capture_parts::Storage::allocate_fallible(
                fragments.len(),
                fragments.iter().map(|part| part.map(<[u8]>::len)),
                fragments.len(),
                fragments.iter().map(|part| part.map(<[u8]>::len)),
                self.output,
            )?
        };
        Ok(Storage {
            shape: self.shape,
            parts: buffers,
            retirement: super::retirement::Storage::allocate(self.shape.parts, true)?,
            parameters,
            extra: crate::symmetric::memory::UnboundBuffer::allocate(self.shape.expected)?,
        })
    }
}
impl CipherOperation {
    pub(in crate::advanced) fn snapshot_shape(&self, entry: &SessionEntry) -> Result<Shape> {
        self.capturable()?;
        if !self.returned.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherReturnedOperandsAwaitingRelease,
            )));
        }
        if self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherTerminalOwnerRequiresTerminalCapture,
            )));
        }
        self.key.check(entry)?;
        self.frame
            .layout
            .fragments(&self.frame.inputs, self.frame.route)?;
        let output = self.frame.output.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherContinuationUnavailable,
            ),
        ))?;
        let graph_packet = match &self.frame.parameters {
            super::CipherFrame::Extension(frame) => Some(frame.graph()?.snapshot_bytes()?),
            _ => None,
        };
        let native_bytes = self.frame.parameters.snapshot_native_bytes()?;
        let metadata = self
            .frame
            .inputs
            .len()
            .checked_mul(size_of::<Buffer>())
            .and_then(|n| {
                n.checked_add(
                    size_of::<CipherOperation>()
                        + size_of::<CK_MECHANISM>()
                        + size_of::<CK_ULONG>()
                        + crate::error::CompletionStorage::allocation_bytes(),
                )
            })
            .and_then(|n| n.checked_add(native_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherFrameAccountingOverflow,
            )))?;
        let metadata = metadata
            .checked_sub(if graph_packet.is_some() {
                size_of::<crate::mechanism_extension::graph::OwnedGraph>()
            } else {
                0
            })
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherGraphMetadataAccounting,
            )))?;
        let fragments = self.frame.layout.lengths().len();
        let lengths = self
            .frame
            .inputs
            .len()
            .checked_add(fragments)
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotAccounting,
            )))?;
        let shape_bytes = Layouts::allocation_bytes(1, lengths)?;
        let mut total = metadata
            .checked_add(super::retirement::Storage::required_bytes(
                self.frame.inputs.len(),
                true,
            )?)
            .and_then(|n| n.checked_add(self.frame.parameters.snapshot_bytes().ok()?))
            .and_then(|n| n.checked_add(self.frame.expected.capacity()))
            .and_then(|n| n.checked_add(output.capacity()))
            .and_then(|n| {
                fragments
                    .checked_mul(size_of::<usize>())
                    .and_then(|v| n.checked_add(v))
            })
            .and_then(|n| n.checked_add(shape_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotAccounting,
            )))?;
        for input in &self.frame.inputs {
            total = total.checked_add(input.capacity()).ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherSnapshotAccounting,
                ),
            ))?;
        }
        total = total
            .checked_add(graph_packet.unwrap_or(0))
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherGraphPacketAccounting,
            )))?;
        total = total
            .checked_add(crate::advanced::capture_parts::Storage::temporary_bytes(
                self.frame.inputs.len(),
            )?)
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotAccounting,
            )))?;
        Ok(Shape {
            direction: self.frame.direction,
            route: self.frame.route,
            parts: self.frame.inputs.len(),
            fragments,
            expected: self.frame.expected.capacity(),
            graph_packet,
            minimum: self.frame.minimum,
            maximum: self.frame.maximum,
            metadata,
            total,
        })
    }
    pub(in crate::advanced) fn describe_snapshot_with_graph(
        &self,
        layout: &mut Layouts,
        prepaid: &mut Credit,
        graph: Option<&mut super::extension_snapshot::Packet>,
    ) -> Result<Option<Parameters<'static>>> {
        if let super::CipherFrame::Extension(frame) = &self.frame.parameters {
            self.frame
                .layout
                .fragments(&self.frame.inputs, self.frame.route)?;
            layout.push(
                &self.frame.inputs,
                &self.frame.layout,
                self.frame
                    .output
                    .as_ref()
                    .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherOutputAbsent,
                    )))?
                    .capacity(),
            )?;
            layout.complete()?;
            graph
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherGraphPacketAbsent,
                )))?
                .copy_from(frame)?;
            Ok(None)
        } else {
            if graph.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::UnexpectedCipherGraphPacket,
                )));
            }
            self.describe_snapshot(layout, prepaid).map(Some)
        }
    }
    pub(in crate::advanced) fn describe_snapshot(
        &self,
        layout: &mut Layouts,
        prepaid: &mut Credit,
    ) -> Result<Parameters<'static>> {
        self.frame
            .layout
            .fragments(&self.frame.inputs, self.frame.route)?;
        layout.push(
            &self.frame.inputs,
            &self.frame.layout,
            self.frame
                .output
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherContinuationUnavailable,
                )))?
                .capacity(),
        )?;
        layout.complete()?;
        self.frame.parameters.prepare_snapshot_parameters(prepaid)
    }
}
impl Shape {
    pub(in crate::advanced) fn graph_packet_bytes(self) -> Option<usize> {
        self.graph_packet
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> usize {
        self.total
    }
    pub(in crate::advanced) fn layout_bytes(self) -> Result<usize> {
        Layouts::allocation_bytes(
            1,
            self.parts
                .checked_add(self.fragments)
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherSnapshotAccounting,
                )))?,
        )
    }
    pub(in crate::advanced) fn allocate_layout(
        self,
    ) -> Result<crate::advanced::capture_layout::Storage> {
        Layouts::allocate(
            1,
            self.parts
                .checked_add(self.fragments)
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherSnapshotAccounting,
                )))?,
        )
    }
    pub(in crate::advanced) fn allocate<'a>(
        self,
        layout: &Layouts,
        parameters: Parameters<'a>,
    ) -> Result<Storage<'a>> {
        let (sizes, fragments, output) = layout.row(0)?;
        if layout.len() != 1 || sizes.len() != self.parts || fragments.len() != self.fragments {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
            )));
        }
        Ok(Storage {
            shape: self,
            parts: crate::advanced::capture_parts::Storage::allocate(sizes, fragments, output)?,
            retirement: super::retirement::Storage::allocate(self.parts, true)?,
            parameters: parameters.allocate()?,
            extra: crate::symmetric::memory::UnboundBuffer::allocate(self.expected)?,
        })
    }
}
impl PreparedSnapshot {
    pub(in crate::advanced) fn bind_extension_contract(
        &mut self,
        contract: crate::MechanismExtension,
    ) -> Result<()> {
        match &mut self.frame.parameters {
            super::CipherFrame::Extension(frame) => frame.bind_contract(contract),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherExtensionDestinationAbsent,
            ))),
        }
    }
    pub(super) fn fill_request(
        self,
        selection: Selection<'_>,
        parts: &[&[u8]],
    ) -> Result<PreparedCipher> {
        self.fill_parts(selection, parts.len(), parts.iter().copied().map(Ok))
    }
    pub(super) fn fill_record(
        self,
        selection: Selection<'_>,
        fragments: crate::advanced::record::Fragments<'_>,
    ) -> Result<PreparedCipher> {
        self.fill_parts(selection, fragments.len(), fragments.iter())
    }
    fn fill_parts<'a>(
        mut self,
        selection: Selection<'_>,
        count: usize,
        parts: impl Iterator<Item = Result<&'a [u8]>>,
    ) -> Result<PreparedCipher> {
        if count != self.shape.fragments {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
            )));
        }
        self.frame.parameters.fill_request(selection)?;
        let mut offset = 0usize;
        let mut observed = 0usize;
        for part in parts {
            let part = part?;
            if observed == count {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
                )));
            }
            let end = offset.checked_add(part.len()).ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherInputLengthOverflow,
                ),
            ))?;
            self.frame
                .expected
                .as_mut()
                .get_mut(offset..end)
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
                )))?
                .copy_from_slice(part);
            if self.shape.route == MessageRoute::Multipart {
                let target = self.frame.inputs.get_mut(observed).ok_or(Error::Rejected(
                    crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
                    ),
                ))?;
                if target.as_slice().len() != part.len() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
                    )));
                }
                target.as_mut().copy_from_slice(part);
            }
            offset = end;
            observed += 1;
        }
        if observed != count || offset != self.frame.expected.as_slice().len() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
            )));
        }
        if self.shape.route == MessageRoute::Single {
            self.frame.inputs[0]
                .as_mut()
                .copy_from_slice(self.frame.expected.as_slice());
        }
        Ok(self.frame)
    }
    pub(in crate::advanced) fn copy_from(
        mut self,
        source: &CipherOperation,
        entry: &SessionEntry,
    ) -> Result<CipherOperation> {
        if self.shape != source.snapshot_shape(entry)? {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
            )));
        }
        for (target, original) in self.frame.inputs.iter_mut().zip(&source.frame.inputs) {
            continuation::copy(target, original)?;
        }
        self.frame.expected.copy_from(&source.frame.expected)?;
        self.frame
            .parameters
            .fill_snapshot(&source.frame.parameters)?;
        continuation::copy(
            self.frame.output.as_mut().expect("prepared output"),
            source.frame.output.as_ref().ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherContinuationUnavailable,
                ),
            ))?,
        )?;
        *self.frame.length = *source.frame.length;
        let mut result = CipherOperation::new(
            source.key.duplicate()?,
            self.frame,
            CipherOutputPlan::MechanismBound,
        );
        result.input = source.input;
        result.stage = source.stage;
        result.used = source.used;
        result.activity = source.activity;
        Ok(result)
    }
}

pub(in crate::advanced) struct Storage<'a> {
    shape: Shape,
    parts: crate::advanced::capture_parts::Storage,
    retirement: super::retirement::Storage,
    parameters: super::parameters::snapshot::Storage<'a>,
    extra: crate::symmetric::memory::UnboundBuffer,
}
impl Storage<'_> {
    fn metadata_bytes(&self) -> Result<usize> {
        let planned = self
            .shape
            .parts
            .checked_mul(size_of::<Buffer>())
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotAccounting,
            )))?;
        let actual = self.parts.input_metadata_bytes()?;
        self.shape
            .metadata
            .checked_sub(planned)
            .and_then(|n| n.checked_add(actual))
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherSnapshotAccounting,
            )))
    }
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        [
            self.metadata_bytes()?,
            self.parts.allocated_bytes()?,
            self.retirement.allocated_bytes()?,
            self.parameters.allocated_bytes()?,
            self.extra.allocated(),
        ]
        .into_iter()
        .try_fold(0usize, |n, v| n.checked_add(v))
        .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::CipherSnapshotAccounting,
        )))
    }
    pub(in crate::advanced) fn bind(self, prepaid: &mut Credit) -> Result<PreparedSnapshot> {
        let credit = prepaid.split(self.metadata_bytes()?)?;
        let parts = self.parts.bind(prepaid)?;
        let parameters = self.parameters.bind(prepaid)?;
        let shape = self.shape;
        Ok(PreparedSnapshot {
            shape,
            frame: PreparedCipher {
                direction: shape.direction,
                route: shape.route,
                parameters,
                inputs: parts.inputs.into(),
                expected: self.extra.bind(prepaid)?.into(),
                retirement: self.retirement.bind(prepaid)?,
                layout: parts.layout,
                output: Some(parts.output),
                length: Box::new(0),
                minimum: shape.minimum,
                maximum: shape.maximum,
                completion_diagnostic: Some(crate::error::CompletionStorage::allocate()?),
                _credit: credit,
            },
        })
    }
}
