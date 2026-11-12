// SPDX-License-Identifier: Apache-2.0
//! Complete unpublished digest graph; all real capacities precede binding.
use super::{DigestFrame, DigestOperation, DigestSelection, Step};
use crate::advanced::{record, NativeActivity};
use crate::mechanism_extension::graph::{
    recipe, snapshot::SnapshotRecipe, GraphStorage, OwnedGraph,
};
use crate::{
    native::derivation::InputBytes,
    symmetric::memory::{Buffer, Credit, UnboundBuffer},
    Error, Result,
};

pub(in crate::advanced) struct Storage {
    selection: DigestSelection,
    parts: Vec<UnboundBuffer>,
    destination: Vec<Buffer>,
    retirement: crate::advanced::fragment_retirement::Storage,
    oid: Option<(UnboundBuffer, UnboundBuffer)>,
    output: UnboundBuffer,
    completion_diagnostic: crate::error::CompletionStorage,
    // Keep table/leaf charges with the partially bound storage on every error.
    metadata_credit: Option<Credit>,
    temporary_credit: Option<Credit>,
}
/// A decoded digest contributes its entire destination size without allocating
/// a vector of fragment references. The archive stays borrowed until binding.
pub(in crate::advanced) struct RecordPlan<'a> {
    input: crate::advanced::input::InputState,
    message: record::Message<'a>,
    selection: DigestSelection,
    step: Step,
    pending: bool,
    validation_requested: bool,
    bytes: usize,
    graph: Option<SnapshotRecipe<'a>>,
    output_capacity: usize,
}
impl<'a> RecordPlan<'a> {
    pub(in crate::advanced) fn new(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        let message = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::ReconstructionDigestMessageAbsent,
            ),
        ))??;
        let count = message.fragments.len();
        let input = crate::InputLimits {
            maximum_parts: ceilings.maximum_parts,
            maximum_total_bytes: ceilings.maximum_total_bytes,
        }
        .validate_lengths(
            ceilings,
            count,
            message.fragments.iter().map(|part| part.map(<[u8]>::len)),
        )?;
        let selection = DigestSelection::from_descriptor(descriptor)?;
        let output_capacity = message
            .params
            .digest_output
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestOutputDescriptorAbsent,
            )))?
            .capacity;
        if selection.route() == crate::advanced::MessageRoute::Single
            && count != usize::from(message.state != record::MessageState::Finished)
        {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::SingleDigestInputCount,
            )));
        }
        if selection.has_oid() != message.params.digest_oid.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestOidSelection,
            )));
        }
        let oid = message.params.digest_oid.map_or(0, <[u8]>::len);
        crate::bounds::ck_length(oid)?;
        let temporary = Storage::temporary_bytes(count)?;
        let graph = message
            .params
            .digest_extension
            .map(|extension| SnapshotRecipe::decode(extension.graph.encoded()?))
            .transpose()?;
        let graph_bytes = graph
            .as_ref()
            .map(|recipe| OwnedGraph::recipe_bytes(recipe))
            .transpose()?
            .unwrap_or(0);
        let bytes = DigestFrame::metadata_bytes_for_count(count, selection)?
            .checked_add(input)
            .and_then(|n| n.checked_add(output_capacity))
            .and_then(|n| n.checked_add(oid.checked_mul(2)?))
            .and_then(|n| n.checked_add(temporary))
            .and_then(|n| n.checked_add(graph_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestGraphAccounting,
            )))?;
        let mut step = match descriptor.phase.name() {
            "C_DigestInit" => Step::Init,
            "C_Digest" => Step::Single,
            "C_DigestUpdate" => Step::Update(message.next_fragment),
            "C_DigestFinal" => Step::Final,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::ReconstructionDigestPhase,
                )))
            }
        };
        if graph.is_some() && (pending || step == Step::Init) {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestExtensionAsynchronousModeOrInitReplayIsUnavailable,
            )));
        }
        if let Some(required) = message
            .params
            .digest_output
            .and_then(|output| output.waiting)
        {
            if pending || !matches!(step, Step::Single | Step::Final) || descriptor.input.is_open()
            {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestOutputWaitingPhase,
                )));
            }
            step = Step::OutputRequired {
                single: step == Step::Single,
                required,
            };
        }
        Ok(Self {
            input: descriptor.input,
            message,
            selection,
            step,
            pending,
            validation_requested: descriptor.validation_requested,
            bytes,
            graph,
            output_capacity,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(&self) -> usize {
        self.bytes
    }
    pub(in crate::advanced) fn allocate(&self) -> Result<RecordStorage<'a>> {
        let frame = Storage::allocate_with_output(
            self.selection,
            self.message.fragments.len(),
            self.message
                .fragments
                .iter()
                .map(|part| part.map(<[u8]>::len)),
            self.message.params.digest_oid.map(<[u8]>::len),
            self.output_capacity,
        )?;
        Ok(RecordStorage {
            frame,
            graph: self
                .graph
                .map(|recipe| GraphStorage::allocate_input(recipe::Input::Snapshot(recipe)))
                .transpose()?,
        })
    }
    pub(in crate::advanced) fn bind(
        self,
        storage: RecordStorage<'a>,
        prepaid: &mut Credit,
    ) -> Result<PreparedCheckpoint> {
        let mut frame = storage.frame.bind(prepaid)?;
        let graph = storage.graph.map(|graph| graph.bind(prepaid)).transpose()?;
        for (target, source) in frame.parts.iter_mut().zip(self.message.fragments.iter()) {
            let source = source?;
            if target.as_slice().len() != source.len() {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestSnapshotPartCount,
                )));
            }
            target.as_mut().copy_from_slice(source);
        }
        if let (Some(target), Some(source)) = (&mut frame.oid, self.message.params.digest_oid) {
            target.fill_before_dispatch(source)?;
        }
        Ok(PreparedCheckpoint {
            graph,
            operation: DigestOperation {
                observer: crate::advanced::digest::Observer::Ticket,
                input: self.input,
                frame,
                step: self.step,
                activity: NativeActivity::restored(self.pending),
                validation_requested: self.validation_requested,
            },
        })
    }
}
impl Storage {
    pub(in crate::advanced) fn temporary_bytes(count: usize) -> Result<usize> {
        count
            .checked_mul(std::mem::size_of::<UnboundBuffer>())
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestSnapshotMetadataAccounting,
            )))
    }

    pub(in crate::advanced) fn allocate_lengths(
        selection: DigestSelection,
        lengths: impl ExactSizeIterator<Item = usize>,
        oid: Option<usize>,
    ) -> Result<Self> {
        Self::allocate_fallible_lengths(selection, lengths.len(), lengths.map(Ok), oid)
    }
    pub(in crate::advanced) fn allocate_fallible_lengths(
        selection: DigestSelection,
        count: usize,
        lengths: impl Iterator<Item = Result<usize>>,
        oid: Option<usize>,
    ) -> Result<Self> {
        Self::allocate_with_output(selection, count, lengths, oid, selection.length())
    }
    pub(in crate::advanced) fn allocate_with_output(
        selection: DigestSelection,
        count: usize,
        lengths: impl Iterator<Item = Result<usize>>,
        oid: Option<usize>,
        capacity: usize,
    ) -> Result<Self> {
        crate::bounds::ck_length(capacity)?;
        let mut parts = Vec::new();
        parts.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::AdvancedInputAllocation,
            ))
        })?;
        let mut destination = Vec::new();
        destination.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::AdvancedInputAllocation,
            ))
        })?;
        for length in lengths {
            if parts.len() == count {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestSnapshotPartCount,
                )));
            }
            parts.push(UnboundBuffer::allocate(length?)?);
        }
        if parts.len() != count {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestSnapshotPartCount,
            )));
        }
        let oid = oid
            .map(|length| -> Result<_> {
                Ok((
                    UnboundBuffer::allocate(length)?,
                    UnboundBuffer::allocate(length)?,
                ))
            })
            .transpose()?;
        Ok(Self {
            selection,
            parts,
            destination,
            retirement: crate::advanced::fragment_retirement::Storage::allocate(count, false)?,
            oid,
            output: UnboundBuffer::allocate(capacity)?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
            temporary_credit: None,
        })
    }
    fn metadata_bytes(&self) -> Result<usize> {
        // Buffer slots and retirement slots may have different real capacities.
        // Replace only the requested retirement component, never double-charge
        // either vector or allocate its nodes before actual capacity admission.
        let provisional =
            DigestFrame::metadata_bytes_for_count(self.destination.capacity(), self.selection)?;
        let requested = crate::advanced::fragment_retirement::Storage::required_bytes(
            self.destination.capacity(),
            false,
        )?;
        provisional
            .checked_sub(requested)
            .and_then(|n| n.checked_add(self.retirement.allocated_bytes().ok()?))
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestRetirementAccounting,
            )))
    }
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        let mut bytes = self
            .metadata_bytes()?
            .checked_add(Self::temporary_bytes(self.parts.capacity())?)
            .and_then(|n| n.checked_add(self.output.allocated()))
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestSnapshotStorageAccounting,
            )))?;
        for part in &self.parts {
            bytes = bytes.checked_add(part.allocated()).ok_or(Error::Rejected(
                crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestSnapshotStorageAccounting,
                ),
            ))?;
        }
        if let Some((value, witness)) = &self.oid {
            bytes = bytes
                .checked_add(value.allocated())
                .and_then(|n| n.checked_add(witness.allocated()))
                .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestSnapshotStorageAccounting,
                )))?;
        }
        Ok(bytes)
    }
    pub(in crate::advanced) fn bind(mut self, prepaid: &mut Credit) -> Result<DigestFrame> {
        self.metadata_credit = Some(prepaid.split(self.metadata_bytes()?)?);
        self.temporary_credit = Some(prepaid.split(Self::temporary_bytes(self.parts.capacity())?)?);
        for part in self.parts.drain(..) {
            self.destination.push(part.bind(prepaid)?);
        }
        drop(self.parts);
        drop(self.temporary_credit.take());
        let oid = self
            .oid
            .map(|(value, witness)| {
                InputBytes::from_buffers(value.bind(prepaid)?, witness.bind(prepaid)?)
            })
            .transpose()?;
        let output = self.output.bind(prepaid)?;
        let retirement = self.retirement.bind(
            self.metadata_credit
                .as_mut()
                .expect("bound digest metadata credit"),
        )?;
        DigestFrame::from_buffers(
            self.metadata_credit
                .take()
                .expect("bound digest metadata credit"),
            self.selection,
            self.destination,
            retirement,
            oid,
            output,
            self.completion_diagnostic,
        )
    }
}

/// Reconstructed bytes remain unpublished until a destination declaration is bound.
pub(in crate::advanced) struct RecordStorage<'a> {
    frame: Storage,
    graph: Option<GraphStorage<'a>>,
}
impl RecordStorage<'_> {
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        self.frame
            .allocated_bytes()?
            .checked_add(
                self.graph
                    .as_ref()
                    .map(GraphStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            )
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestReconstructionAccounting,
            )))
    }
}
pub(in crate::advanced) struct PreparedCheckpoint {
    operation: DigestOperation,
    graph: Option<OwnedGraph>,
}
impl PreparedCheckpoint {
    pub(in crate::advanced) fn check_binding(
        &self,
        contract: Option<&crate::MechanismExtension>,
    ) -> Result<()> {
        match (self.graph.as_ref(), contract) {
            (Some(_), Some(_)) | (None, None) => Ok(()),
            _ => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestDestinationDeclarationAbsentOrUnexpected,
            ))),
        }
    }
    /// Transfer immediately after check_binding with unchanged inputs.
    pub(in crate::advanced) fn bind_checked(
        mut self,
        contract: Option<crate::MechanismExtension>,
    ) -> DigestOperation {
        match (self.graph, contract) {
            (Some(graph), Some(contract)) => {
                let mut parameters = super::extension::Parameters::new(contract, graph);
                parameters.attach(&mut self.operation.frame.mechanism);
                self.operation.frame.extension = Some(parameters);
            }
            (None, None) => {}
            _ => unreachable!("validated digest destination declaration"),
        }
        self.operation
    }
}
