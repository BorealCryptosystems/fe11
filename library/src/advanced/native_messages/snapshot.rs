// SPDX-License-Identifier: Apache-2.0
//! Private copies of generic message continuations, before destination binding.
//!
//! Discovery returns counts only. Storage is allocated outside session guards;
//! guarded copying writes into that storage without allocating or following a
//! native pointer. A packet retains source exclusions but cannot execute C.
//! The enclosing capture transaction must recheck its ledger revision before
//! publication. Serialized handles never substitute for destination references.
use super::{
    preparation, CapacityStorage, DataCall, DataKind, Execution, InputState, Message,
    MessageOutput, NativeActivity, NativeMessageOperation, Observer, Parameters, Phase,
};
use crate::advanced::{key_roles::Roles, SignatureBufferRequest};
use crate::managed::NativeIdentity;
use crate::mechanism_extension::{parameter_keys::RetainedParameterKeys, OwnedGraph};
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{Error, MechanismExtension, MessageRoute, Result};
use fe11_sys::{CK_RV, CK_ULONG};
use std::{mem::size_of, ops::Range, sync::Arc};

mod materialize;
pub(in crate::advanced) use materialize::Materialized;

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageSnapshotShape,
    ))
}

fn add(total: &mut usize, amount: usize) -> Result<()> {
    *total = total.checked_add(amount).ok_or_else(invalid)?;
    Ok(())
}

fn slots<T>(count: usize) -> Result<usize> {
    count.checked_mul(size_of::<T>()).ok_or_else(invalid)
}

fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| invalid())?;
    Ok(values)
}

/// Fixed-size discovery; no reference, guard or heap allocation escapes it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    bytes: usize,
    rows: usize,
    graphs: usize,
    restoration_bytes: usize,
}

/// Source ownership is deliberately distinct from an executable Binding.
/// A future writer may still have unarmed revocation targets after Init. The
/// copy retains that fact without cloning or discarding an executable target:
/// destination admission must prepare its own targets before native restore.
struct SourceBinding {
    key: Arc<NativeIdentity>,
    authentication: u64,
    roles: Roles,
    contract: MechanismExtension,
    own_revocation: bool,
    writer: bool,
    primary_mode: crate::session::activity::AccessMode,
    auxiliary: [Option<super::binding::Auxiliary>; 4],
}

struct Metadata {
    binding: SourceBinding,
    keys: RetainedParameterKeys,
    route: MessageRoute,
    verify: bool,
    phase: Boundary,
    activity: NativeActivity,
    input: InputState,
    invalid_seen: bool,
}

struct Call {
    message: usize,
    part: usize,
    kind: DataKind,
    bytes: Range<usize>,
    signature: Option<Range<usize>>,
}

enum Boundary {
    Ready,
    Begin(usize),
    Receive(usize),
    Data(Call),
    Capacity {
        call: Call,
        request: SignatureBufferRequest,
        prepared: bool,
    },
    Final,
}

struct Graph {
    bytes: Range<usize>,
    // Initialization uses the parent contract; every subsequent graph retains
    // its own declaration. None denotes the existing null-parameter contract.
    contract: Option<MechanismExtension>,
}

enum Output {
    Sign(Option<Signature>),
    Verify(Option<CK_RV>),
}

struct Signature {
    // None means the previous native buffer has been returned and removed
    // after BUFFER_TOO_SMALL. Its stale offset is intentionally not copied.
    bytes: Option<Range<usize>>,
    capacity: usize,
    length: CK_ULONG,
    produced: Option<usize>,
}

struct Row {
    begin: Option<usize>,
    parts: Range<usize>,
    output: Output,
    rejection: Option<super::NativeMessageRejection>,
}

pub(in crate::advanced) struct PacketStorage {
    bytes: UnboundBuffer,
    rows: Vec<Row>,
    graphs: Vec<Graph>,
}

/// Owns erased-on-drop bytes and retained role leases. It has no mechanism
/// descriptor, dispatch method or authority to install a destination operation.
pub(in crate::advanced) struct Packet {
    shape: Shape,
    bytes: Buffer,
    rows: Vec<Row>,
    graphs: Vec<Graph>,
    metadata: Option<Metadata>,
    allocated_bytes: usize,
    _metadata: Credit,
}

impl NativeMessageOperation {
    /// Freeze the original continuation when any declared call can mutate its
    /// primary key. This includes effects not yet reached at the capture boundary.
    pub(in crate::advanced) fn exclusive_continuation(&self) -> bool {
        self.binding.writer
    }

    pub(in crate::advanced) fn snapshot_shape(
        &self,
        entry: &crate::module::SessionEntry,
    ) -> Result<Shape> {
        self.check_key(entry)?;
        if !matches!(self.execution, Execution::Running)
            || self.observer != Observer::Ticket
            || self.pending()
            || self.native_inactive()
            || self.initialization.is_none()
            || self.released.call.is_some()
            || self.released.output.is_some()
            || matches!(self.phase, Phase::Init | Phase::Complete)
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageNotAtACapturableBoundary,
            )));
        }
        if !self.unchanged() {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::ChangedGenericMessageSnapshotInput,
            )));
        }
        let mut shape = Shape {
            bytes: 0,
            rows: self.messages.len(),
            graphs: 0,
            restoration_bytes: preparation::fixed_bytes()?,
        };
        add(&mut shape.restoration_bytes, slots::<Message>(shape.rows)?)?;
        let (initialization, keys) = self.initialization().snapshot_parts();
        add(&mut shape.bytes, keys.locations()?.encoded_len()?)?;
        shape.graph(initialization)?;
        for (index, row) in self.messages.iter().enumerate() {
            add(
                &mut shape.restoration_bytes,
                slots::<Parameters>(row.parts.len())?,
            )?;
            for parameters in row.begin.iter().chain(row.parts.iter()) {
                shape.graph(&parameters.graph)?;
            }
            match &row.output {
                MessageOutput::Sign(Some(output)) => {
                    add(&mut shape.restoration_bytes, size_of::<CK_ULONG>())?;
                    if self.missing_output(index) {
                        if output.bytes.capacity() != 0 || output.produced.is_some() {
                            return Err(invalid());
                        }
                    } else {
                        let capacity = output.capacity()?;
                        if output.produced.is_some_and(|length| length > capacity) {
                            return Err(invalid());
                        }
                        add(&mut shape.bytes, capacity)?;
                        add(
                            &mut shape.restoration_bytes,
                            self.output_storage_bytes(capacity)?,
                        )?;
                    }
                }
                MessageOutput::Sign(None) | MessageOutput::Verify { .. } => {}
            }
        }
        if let Some(call) = self.data() {
            for input in std::iter::once(&call.bytes).chain(call.signature.iter()) {
                let bytes = input.bytes().len();
                add(&mut shape.bytes, bytes)?;
                add(
                    &mut shape.restoration_bytes,
                    bytes.checked_mul(2).ok_or_else(invalid)?,
                )?;
            }
        }
        Ok(shape)
    }

    fn missing_output(&self, row: usize) -> bool {
        matches!(
            &self.phase,
            Phase::Capacity { call, storage: CapacityStorage::Missing, .. }
                if call.message == row
        )
    }
}

impl Shape {
    fn graph(&mut self, graph: &OwnedGraph) -> Result<()> {
        add(&mut self.bytes, graph.snapshot_bytes()?)?;
        add(
            &mut self.restoration_bytes,
            graph.snapshot_allocation_bytes()?,
        )?;
        add(&mut self.graphs, 1)
    }

    fn packet_metadata(self) -> Result<usize> {
        slots::<Row>(self.rows)?
            .checked_add(slots::<Graph>(self.graphs)?)
            .ok_or_else(invalid)
    }

    /// Minimum aggregate admission, including both the staging copy and its
    /// reconstructed owner. Actual vector and buffer capacities are reconciled
    /// before binding; a larger request requires discarding the whole candidate.
    pub(in crate::advanced) fn allocation_bytes(self) -> Result<usize> {
        self.restoration_bytes
            .checked_add(self.bytes)
            .and_then(|bytes| bytes.checked_add(self.packet_metadata().ok()?))
            .and_then(|bytes| {
                bytes.checked_add(materialize::temporary_bytes(self.graphs, self.rows).ok()?)
            })
            .ok_or_else(invalid)
    }

    pub(in crate::advanced) fn allocate_packet(self) -> Result<PacketStorage> {
        Ok(PacketStorage {
            bytes: UnboundBuffer::allocate(self.bytes)?,
            rows: reserve(self.rows)?,
            graphs: reserve(self.graphs)?,
        })
    }

    pub(in crate::advanced) fn packet_overhead(self, storage: &PacketStorage) -> Result<usize> {
        let actual = storage
            .metadata_bytes()?
            .checked_add(storage.bytes.allocated())
            .ok_or_else(invalid)?;
        let requested = self
            .packet_metadata()?
            .checked_add(self.bytes)
            .ok_or_else(invalid)?;
        actual.checked_sub(requested).ok_or_else(invalid)
    }

    pub(in crate::advanced) fn bind_packet(
        self,
        storage: PacketStorage,
        prepaid: &mut Credit,
    ) -> Result<Packet> {
        if storage.rows.capacity() < self.rows
            || storage.graphs.capacity() < self.graphs
            || storage.bytes.allocated() < self.bytes
        {
            return Err(invalid());
        }
        let metadata = prepaid.split(storage.metadata_bytes()?)?;
        let allocated_bytes = storage
            .metadata_bytes()?
            .checked_add(storage.bytes.allocated())
            .ok_or_else(invalid)?;
        Ok(Packet {
            shape: self,
            bytes: storage.bytes.bind(prepaid)?,
            rows: storage.rows,
            graphs: storage.graphs,
            metadata: None,
            allocated_bytes,
            _metadata: metadata,
        })
    }
}

impl PacketStorage {
    fn metadata_bytes(&self) -> Result<usize> {
        slots::<Row>(self.rows.capacity())?
            .checked_add(slots::<Graph>(self.graphs.capacity())?)
            .ok_or_else(invalid)
    }
}

fn write(bytes: &mut Buffer, cursor: &mut usize, input: &[u8]) -> Result<Range<usize>> {
    let end = cursor.checked_add(input.len()).ok_or_else(invalid)?;
    let range = *cursor..end;
    bytes
        .as_mut()
        .get_mut(range.clone())
        .ok_or_else(invalid)?
        .copy_from_slice(input);
    *cursor = end;
    Ok(range)
}

impl Packet {
    fn graph(
        &mut self,
        cursor: &mut usize,
        graph: &OwnedGraph,
        contract: Option<&MechanismExtension>,
    ) -> Result<usize> {
        let index = self.graphs.len();
        if index >= self.shape.graphs || index >= self.graphs.capacity() {
            return Err(invalid());
        }
        let start = *cursor;
        graph.write_snapshot(&mut |input| write(&mut self.bytes, cursor, input).map(|_| ()))?;
        self.graphs.push(Graph {
            bytes: start..*cursor,
            contract: contract.cloned(),
        });
        Ok(index)
    }

    fn call(&mut self, cursor: &mut usize, call: &DataCall) -> Result<Call> {
        let bytes = write(&mut self.bytes, cursor, call.bytes.bytes())?;
        let signature = call
            .signature
            .as_ref()
            .map(|input| write(&mut self.bytes, cursor, input.bytes()))
            .transpose()?;
        Ok(Call {
            message: call.message,
            part: call.part,
            kind: call.kind,
            bytes,
            signature,
        })
    }

    /// Source possession and established native memory return are required.
    /// No reserve, native call, pointer traversal or native-output publication
    /// occurs here. On failure the caller drops this unpublished packet outside
    /// its guards; an incomplete packet is never reused for a second attempt.
    pub(in crate::advanced) fn copy_from(
        &mut self,
        source: &NativeMessageOperation,
        entry: &crate::module::SessionEntry,
    ) -> Result<()> {
        if self.metadata.is_some()
            || !self.rows.is_empty()
            || !self.graphs.is_empty()
            || source.snapshot_shape(entry)? != self.shape
        {
            return Err(invalid());
        }
        let mut cursor = 0;
        let (initialization, keys) = source.initialization().snapshot_parts();
        keys.locations()?
            .write(|input| write(&mut self.bytes, &mut cursor, input).map(|_| ()))?;
        self.graph(&mut cursor, initialization, None)?;
        for (index, row) in source.messages.iter().enumerate() {
            if self.rows.len() >= self.rows.capacity() {
                return Err(invalid());
            }
            let begin = row
                .begin
                .as_ref()
                .map(|parameters| {
                    self.graph(&mut cursor, &parameters.graph, parameters.contract.as_ref())
                })
                .transpose()?;
            let start = self.graphs.len();
            for parameters in &row.parts {
                self.graph(&mut cursor, &parameters.graph, parameters.contract.as_ref())?;
            }
            let parts = start..self.graphs.len();
            let output = match &row.output {
                MessageOutput::Sign(output) => Output::Sign(
                    output
                        .as_ref()
                        .map(|output| -> Result<Signature> {
                            let bytes = if source.missing_output(index) {
                                None
                            } else {
                                // Copy the payload, never its old alignment padding.
                                // Final can still update the native length cell, so all
                                // initialized capacity survives, not just produced bytes.
                                let end = output
                                    .offset
                                    .checked_add(output.capacity()?)
                                    .ok_or_else(invalid)?;
                                let payload = output
                                    .bytes
                                    .initialized_storage()
                                    .get(output.offset..end)
                                    .ok_or_else(invalid)?;
                                Some(write(&mut self.bytes, &mut cursor, payload)?)
                            };
                            Ok(Signature {
                                bytes,
                                capacity: output.capacity,
                                length: *output.length,
                                produced: output.produced,
                            })
                        })
                        .transpose()?,
                ),
                MessageOutput::Verify { verdict } => Output::Verify(*verdict),
            };
            self.rows.push(Row {
                rejection: row.rejection,
                begin,
                parts,
                output,
            });
        }
        let phase = match &source.phase {
            Phase::Ready => Boundary::Ready,
            Phase::Begin(index) => Boundary::Begin(*index),
            Phase::Receive(index) => Boundary::Receive(*index),
            Phase::Data(call) => Boundary::Data(self.call(&mut cursor, call)?),
            Phase::Capacity {
                call,
                request,
                storage,
            } => Boundary::Capacity {
                call: self.call(&mut cursor, call)?,
                request: *request,
                prepared: matches!(storage, CapacityStorage::Prepared),
            },
            Phase::Final => Boundary::Final,
            Phase::Init | Phase::Complete => return Err(invalid()),
        };
        if cursor != self.shape.bytes
            || self.rows.len() != self.shape.rows
            || self.graphs.len() != self.shape.graphs
        {
            return Err(invalid());
        }
        self.bytes.set_length(cursor)?;
        let primary = &source.binding.primary;
        self.metadata = Some(Metadata {
            binding: SourceBinding {
                key: primary.key.clone(),
                authentication: primary.authentication,
                roles: primary.roles.clone(),
                contract: primary.contract.clone(),
                own_revocation: primary.own_revocation,
                writer: source.binding.writer,
                primary_mode: source.binding.primary_mode,
                auxiliary: source.binding.auxiliary.clone(),
            },
            keys: keys.clone(),
            route: source.route,
            verify: source.verify,
            phase,
            activity: source.activity,
            input: source.input,
            invalid_seen: source.invalid_seen,
        });
        Ok(())
    }
}
