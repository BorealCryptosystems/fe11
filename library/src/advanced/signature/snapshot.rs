// SPDX-License-Identifier: Apache-2.0
//! Two-phase copies of a signature continuation. Guarded copying allocates
//! nothing; graph relocation and buffer allocation occur after releasing it.
use super::{
    preparation, InputState, Kind, NativeActivity, SignatureOperation, SignatureOutputPlan, Stage,
};
use crate::mechanism_extension::graph::{recipe, snapshot::SnapshotRecipe, GraphStorage};
use crate::native::derivation::InputBytesStorage;
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{Error, MechanismExtension, MessageRoute, Result};
use fe11_sys::{CK_MECHANISM, CK_ULONG};
use std::sync::Arc;

fn overflow() -> Error {
    Error::Rejected(crate::RejectionReason::SignatureContinuation(
        crate::SignatureContinuationRejection::SignatureSnapshotAccounting,
    ))
}

/// No references, permits, heap storage or native pointers escape discovery.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    graph_bytes: usize,
    graph_storage: usize,
    fragment: Option<usize>,
    signature: Option<usize>,
    output_capacity: Option<usize>,
    output_length: usize,
}

struct Metadata {
    key: Arc<crate::managed::NativeIdentity>,
    authentication: u64,
    roles: super::roles::Roles,
    own_revocation: bool,
    contract: MechanismExtension,
    kind: Kind,
    route: MessageRoute,
    plan: SignatureOutputPlan,
    maximum_output: usize,
    input: InputState,
    stage: Stage,
    activity: NativeActivity,
    length: CK_ULONG,
}

/// Private staging bytes cannot execute C. Cloned exclusions keep the source
/// protected; publication is conditional on its unchanged ledger revision.
pub(in crate::advanced) struct Packet {
    shape: Shape,
    bytes: Buffer,
    metadata: Option<Metadata>,
}

pub(in crate::advanced) enum Materialized {
    Ready(SignatureOperation),
    /// All unpublished allocations are dropped before another admission wait.
    Retry(usize),
}

impl SignatureOperation {
    pub(in crate::advanced) fn snapshot_shape(
        &self,
        entry: &crate::module::SessionEntry,
    ) -> Result<Shape> {
        self.check_key(entry)?;
        // Capturing an old authentication observation is distinct from issuing
        // another native call on the live owner after Logout.
        entry
            .snapshot
            .check_authentication_unchanged(self.authentication)?;
        if !matches!(
            self.stage,
            Stage::Ready | Stage::Update | Stage::Terminal | Stage::Waiting(_)
        ) || self.pending()
            || self.native_inactive()
            || self.revocation.is_some()
            || !self.returned.is_empty()
            || self.observer != super::Observer::Ticket
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureNotAtACapturableBoundary,
                ),
            ));
        }
        let graph = self.parameters.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::Restoration(
                crate::RestorationRejection::SignatureParametersAbsent,
            ),
        ))?;
        if !graph.unchanged()
            || self
                .fragment
                .as_ref()
                .is_some_and(|input| !input.unchanged())
            || self
                .signature
                .as_ref()
                .is_some_and(|input| !input.unchanged())
        {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::ChangedSignatureSnapshotInput,
                ),
            ));
        }
        Ok(Shape {
            graph_bytes: graph.snapshot_bytes()?,
            graph_storage: graph.snapshot_allocation_bytes()?,
            fragment: self.fragment.as_ref().map(|value| value.bytes().len()),
            signature: self.signature.as_ref().map(|value| value.bytes().len()),
            output_capacity: self.output.as_ref().map(Buffer::capacity),
            output_length: self
                .output
                .as_ref()
                .map_or(0, |value| value.as_slice().len()),
        })
    }
}

impl Shape {
    fn packet_bytes(self) -> Result<usize> {
        self.graph_bytes
            .checked_add(self.fragment.unwrap_or(0))
            .and_then(|n| n.checked_add(self.signature.unwrap_or(0)))
            .and_then(|n| n.checked_add(self.output_length))
            .ok_or_else(overflow)
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> Result<usize> {
        self.fragment
            .unwrap_or(0)
            .checked_add(self.signature.unwrap_or(0))
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(self.graph_storage))
            .and_then(|n| n.checked_add(self.output_capacity.unwrap_or(0)))
            .and_then(|n| n.checked_add(preparation::metadata_bytes()))
            .and_then(|n| n.checked_add(self.packet_bytes().ok()?))
            .ok_or_else(overflow)
    }
    pub(in crate::advanced) fn allocate_packet(self) -> Result<UnboundBuffer> {
        UnboundBuffer::allocate(self.packet_bytes()?)
    }
    pub(in crate::advanced) fn packet_overhead(self, storage: &UnboundBuffer) -> Result<usize> {
        storage
            .allocated()
            .checked_sub(self.packet_bytes()?)
            .ok_or_else(overflow)
    }
    pub(in crate::advanced) fn bind_packet(
        self,
        storage: UnboundBuffer,
        prepaid: &mut Credit,
    ) -> Result<Packet> {
        Ok(Packet {
            shape: self,
            bytes: storage.bind(prepaid)?,
            metadata: None,
        })
    }
}

impl Packet {
    /// Called while the source is possessed; performs bounded copies only.
    pub(in crate::advanced) fn copy_from(
        &mut self,
        source: &SignatureOperation,
        entry: &crate::module::SessionEntry,
    ) -> Result<()> {
        if source.snapshot_shape(entry)? != self.shape {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureSnapshotShapeChanged,
                ),
            ));
        }
        let mut offset = 0usize;
        let mut write = |bytes: &[u8]| -> Result<()> {
            let end = offset.checked_add(bytes.len()).ok_or_else(overflow)?;
            self.bytes
                .as_mut()
                .get_mut(offset..end)
                .ok_or_else(overflow)?
                .copy_from_slice(bytes);
            offset = end;
            Ok(())
        };
        source
            .parameters
            .as_ref()
            .expect("checked parameters")
            .write_snapshot(&mut write)?;
        for value in [&source.fragment, &source.signature].into_iter().flatten() {
            write(value.bytes())?;
        }
        if let Some(output) = &source.output {
            write(output.as_slice())?;
        }
        self.bytes.set_length(offset)?;
        self.metadata = Some(Metadata {
            key: source.key.clone(),
            authentication: source.authentication,
            roles: source._roles.clone(),
            own_revocation: source.own_revocation,
            contract: source.contract.clone(),
            kind: source.kind,
            route: source.route,
            plan: source.plan,
            maximum_output: source.maximum_output,
            input: source.input,
            stage: source.stage,
            activity: source.activity,
            length: *source.length,
        });
        Ok(())
    }

    /// No guards survive here. A retry reports the complete requirement;
    /// callers discard this packet and its credit before waiting again.
    pub(in crate::advanced) fn materialize(
        mut self,
        prepaid: &mut Credit,
        admitted: usize,
    ) -> Result<Materialized> {
        let recipe = SnapshotRecipe::decode(&self.bytes.as_slice()[..self.shape.graph_bytes])?;
        let graph = GraphStorage::allocate_input(recipe::Input::Generated(&recipe))?;
        let fragment = self
            .shape
            .fragment
            .map(InputBytesStorage::allocate)
            .transpose()?;
        let signature = self
            .shape
            .signature
            .map(InputBytesStorage::allocate)
            .transpose()?;
        let output = self
            .shape
            .output_capacity
            .map(UnboundBuffer::allocate)
            .transpose()?;
        let signature_bytes = signature
            .as_ref()
            .map(InputBytesStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        let actual = graph
            .allocated_bytes()?
            .checked_add(
                fragment
                    .as_ref()
                    .map(InputBytesStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            )
            .and_then(|n| n.checked_add(signature_bytes))
            .and_then(|n| n.checked_add(output.as_ref().map_or(0, UnboundBuffer::allocated)))
            .and_then(|n| n.checked_add(preparation::metadata_bytes()))
            .and_then(|n| n.checked_add(self.bytes.capacity()))
            .ok_or_else(overflow)?;
        if actual > admitted {
            return Ok(Materialized::Retry(actual));
        }
        prepaid.release(admitted - actual);
        let mut graph = graph.bind(prepaid)?;
        let mut offset = self.shape.graph_bytes;
        let mut operand =
            |storage: Option<InputBytesStorage>, length: Option<usize>, credit: &mut Credit| {
                storage
                    .zip(length)
                    .map(|(storage, length)| {
                        let end = offset.checked_add(length).ok_or_else(overflow)?;
                        let input = storage.bind(&self.bytes.as_slice()[offset..end], credit)?;
                        offset = end;
                        Ok(input)
                    })
                    .transpose()
            };
        let fragment = operand(fragment, self.shape.fragment, prepaid)?;
        let signature = operand(signature, self.shape.signature, prepaid)?;
        let mut output = output
            .map(|storage| -> Result<_> {
                let mut buffer = storage.bind(prepaid)?;
                buffer.as_mut()[..self.shape.output_length]
                    .copy_from_slice(&self.bytes.as_slice()[offset..]);
                buffer.set_length(self.shape.output_length)?;
                Ok(buffer)
            })
            .transpose()?;
        let metadata = self.metadata.take().ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::UncopiedSignatureSnapshot,
            ),
        ))?;
        let output_offset = output
            .as_mut()
            .map(|buffer| super::output_offset(metadata.contract.mechanism_number(), buffer))
            .transpose()?
            .unwrap_or(0);
        let (pointer, length) = graph.projection();
        let mechanism = Box::new(CK_MECHANISM {
            mechanism: metadata.contract.native_mechanism(),
            pParameter: pointer,
            ulParameterLen: length,
        });
        Ok(Materialized::Ready(SignatureOperation {
            key: metadata.key,
            authentication: metadata.authentication,
            _roles: metadata.roles,
            own_revocation: metadata.own_revocation,
            revocation: None,
            contract: metadata.contract,
            kind: metadata.kind,
            route: metadata.route,
            mechanism,
            parameters: Some(graph),
            fragment,
            signature,
            output,
            output_offset,
            returned: super::ReturnedOperands::default(),
            length: Box::new(metadata.length),
            plan: metadata.plan,
            maximum_output: metadata.maximum_output,
            input: metadata.input,
            stage: metadata.stage,
            observer: super::Observer::Ticket,
            activity: metadata.activity,
            completion_diagnostic: Some(crate::error::CompletionStorage::allocate()?),
            _credit: prepaid.split(preparation::metadata_bytes())?,
        }))
    }
}
