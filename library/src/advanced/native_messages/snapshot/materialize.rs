// SPDX-License-Identifier: Apache-2.0
//! Reconstruct private storage outside guards; never restore native state here.
use super::{add, invalid, reserve, slots, Boundary, Output, Packet};
use crate::advanced::native_messages::{
    binding::Binding, preparation, CapacityStorage, DataCall, Execution, Message, MessageOutput,
    NativeMessageOperation, Observer, Parameters, Phase, ReleasedInput, SignatureOutput,
};
use crate::mechanism_extension::{
    graph::{recipe, snapshot::SnapshotRecipe, GraphStorage},
    message::initialization::Initialization,
    parameter_keys::KeyLocations,
};
use crate::native::derivation::InputBytesStorage;
use crate::symmetric::memory::{Credit, UnboundBuffer};
use crate::Result;
use fe11_sys::CK_ULONG;
use std::{mem::size_of, ops::Range};

pub(in crate::advanced) enum Materialized {
    Ready(NativeMessageOperation),
    /// The caller discards every unpublished allocation and credit before
    /// waiting again with the same absolute admission deadline and revision.
    Retry(usize),
}

struct RowStorage {
    parts: Vec<Parameters>,
    output: Option<UnboundBuffer>,
}

pub(super) fn temporary_bytes(graphs: usize, rows: usize) -> Result<usize> {
    let mut total = slots::<SnapshotRecipe<'_>>(graphs)?;
    add(&mut total, slots::<GraphStorage<'_>>(graphs)?)?;
    add(&mut total, slots::<RowStorage>(rows)?)?;
    Ok(total)
}

impl Boundary {
    fn call(&self) -> Option<&super::Call> {
        match self {
            Self::Data(call) | Self::Capacity { call, .. } => Some(call),
            _ => None,
        }
    }
}

impl Packet {
    pub(in crate::advanced) fn materialize(
        mut self,
        prepaid: &mut Credit,
        admitted: usize,
    ) -> Result<Materialized> {
        // Declared before the temporary vectors so their heap storage is
        // destroyed before its credit, including every error/early-return path.
        let temporary_credit;
        // The parent also pays for the messages vector. Establish its drop
        // scope before that vector, even though the split follows measurement.
        let parent_credit;
        let metadata = self.metadata.take().ok_or_else(invalid)?;
        let prefix = self.graphs.first().ok_or_else(invalid)?.bytes.start;
        let locations =
            KeyLocations::parse(self.bytes.as_slice().get(..prefix).ok_or_else(invalid)?)?;
        if locations != metadata.keys.locations()? {
            return Err(invalid());
        }
        let mut recipes = reserve(self.shape.graphs)?;
        for graph in &self.graphs {
            let bytes = self
                .bytes
                .as_slice()
                .get(graph.bytes.clone())
                .ok_or_else(invalid)?;
            recipes.push(SnapshotRecipe::decode(bytes)?);
        }
        let mut graphs = reserve(self.shape.graphs)?;
        for recipe in &recipes {
            graphs.push(GraphStorage::allocate_input(recipe::Input::Generated(
                recipe,
            ))?);
        }
        let mut rows = reserve(self.shape.rows)?;
        for row in &self.rows {
            let output = match &row.output {
                Output::Sign(Some(signature)) => {
                    let bytes = if signature.bytes.is_some() {
                        crate::advanced::signature::output_storage_bytes(
                            metadata.binding.contract.mechanism_number(),
                            signature.capacity,
                        )?
                    } else {
                        0
                    };
                    Some(UnboundBuffer::allocate(bytes)?)
                }
                _ => None,
            };
            rows.push(RowStorage {
                parts: reserve(row.parts.len())?,
                output,
            });
        }
        let mut messages = reserve::<Message>(self.shape.rows)?;
        let call = metadata.phase.call();
        let input = call
            .map(|call| InputBytesStorage::allocate(call.bytes.len()))
            .transpose()?;
        let signature = call
            .and_then(|call| call.signature.as_ref())
            .map(|range| InputBytesStorage::allocate(range.len()))
            .transpose()?;

        let temporary = slots::<SnapshotRecipe<'_>>(recipes.capacity())?
            .checked_add(slots::<GraphStorage<'_>>(graphs.capacity())?)
            .and_then(|bytes| bytes.checked_add(slots::<RowStorage>(rows.capacity()).ok()?))
            .ok_or_else(invalid)?;
        let parent_bytes = preparation::fixed_bytes()?
            .checked_add(slots::<Message>(messages.capacity())?)
            .ok_or_else(invalid)?;
        let mut actual = self.allocated_bytes;
        add(&mut actual, temporary)?;
        add(&mut actual, parent_bytes)?;
        for graph in &graphs {
            add(&mut actual, graph.allocated_bytes()?)?;
        }
        for row in &rows {
            add(&mut actual, slots::<Parameters>(row.parts.capacity())?)?;
            if let Some(output) = &row.output {
                add(&mut actual, output.allocated())?;
                add(&mut actual, size_of::<CK_ULONG>())?;
            }
        }
        for input in input.iter().chain(signature.iter()) {
            add(&mut actual, input.allocated_bytes()?)?;
        }
        if actual > admitted {
            return Ok(Materialized::Retry(actual));
        }
        prepaid.release(admitted - actual);
        temporary_credit = prepaid.split(temporary)?;
        parent_credit = prepaid.split(parent_bytes)?;

        // Every allocation has been measured. From here onward binding only
        // splits the admitted credit; no reserve or waiting can occur.
        let mut graph_storage = graphs.into_iter();
        let mut declarations = self.graphs.into_iter();
        let first = declarations.next().ok_or_else(invalid)?;
        if first.contract.is_some() {
            return Err(invalid());
        }
        let graph = graph_storage.next().ok_or_else(invalid)?.bind(prepaid)?;
        let initialization = Box::new(Initialization::new(
            metadata.binding.contract.native_mechanism(),
            graph,
            metadata.keys,
        ));
        let expected = initialization.expected();
        let mut next_graph = |prepaid: &mut Credit| -> Result<Parameters> {
            let declaration = declarations.next().ok_or_else(invalid)?;
            let graph = graph_storage.next().ok_or_else(invalid)?.bind(prepaid)?;
            Ok(Parameters {
                graph: Box::new(graph),
                contract: declaration.contract,
            })
        };
        let mut graph_index = 1usize;
        for (row, mut storage) in self.rows.into_iter().zip(rows) {
            let begin = row
                .begin
                .map(|index| {
                    if index != graph_index {
                        return Err(invalid());
                    }
                    graph_index = graph_index.checked_add(1).ok_or_else(invalid)?;
                    next_graph(prepaid)
                })
                .transpose()?;
            if row.parts.start != graph_index {
                return Err(invalid());
            }
            for _ in row.parts.clone() {
                storage.parts.push(next_graph(prepaid)?);
            }
            graph_index = row.parts.end;
            let row_bytes = slots::<Parameters>(storage.parts.capacity())?
                .checked_add(if storage.output.is_some() {
                    size_of::<CK_ULONG>()
                } else {
                    0
                })
                .ok_or_else(invalid)?;
            let output = match row.output {
                Output::Verify(verdict) => MessageOutput::Verify { verdict },
                Output::Sign(None) => MessageOutput::Sign(None),
                Output::Sign(Some(signature)) => {
                    let mut buffer = storage.output.take().ok_or_else(invalid)?.bind(prepaid)?;
                    let offset = if let Some(range) = signature.bytes {
                        let offset = crate::advanced::signature::output_offset(
                            metadata.binding.contract.mechanism_number(),
                            &mut buffer,
                        )?;
                        let payload = self.bytes.as_slice().get(range).ok_or_else(invalid)?;
                        if payload.len() != signature.capacity {
                            return Err(invalid());
                        }
                        let end = offset.checked_add(payload.len()).ok_or_else(invalid)?;
                        buffer
                            .as_mut()
                            .get_mut(offset..end)
                            .ok_or_else(invalid)?
                            .copy_from_slice(payload);
                        let visible = offset
                            .checked_add(signature.produced.unwrap_or(signature.capacity))
                            .ok_or_else(invalid)?;
                        buffer.set_length(visible)?;
                        offset
                    } else {
                        // The missing output retains the exact native request;
                        // attaching a replacement will establish its new offset.
                        if signature.produced.is_some() {
                            return Err(invalid());
                        }
                        0
                    };
                    MessageOutput::Sign(Some(SignatureOutput {
                        bytes: buffer,
                        offset,
                        length: Box::new(signature.length),
                        capacity: signature.capacity,
                        produced: signature.produced,
                    }))
                }
            };
            messages.push(Message {
                rejection: row.rejection,
                begin,
                parts: storage.parts,
                output,
                _metadata: prepaid.split(row_bytes)?,
            });
        }
        // End closure borrows before checking that every graph was consumed.
        drop(next_graph);
        if graph_index != self.shape.graphs
            || graph_storage.next().is_some()
            || declarations.next().is_some()
            || messages.len() != self.shape.rows
        {
            return Err(invalid());
        }
        let mut input = input;
        let mut signature = signature;
        let mut restore_call = |call: super::Call| -> Result<DataCall> {
            let bytes = input.take().ok_or_else(invalid)?.bind(
                self.bytes.as_slice().get(call.bytes).ok_or_else(invalid)?,
                prepaid,
            )?;
            let signature = call
                .signature
                .map(|range: Range<usize>| {
                    signature.take().ok_or_else(invalid)?.bind(
                        self.bytes.as_slice().get(range).ok_or_else(invalid)?,
                        prepaid,
                    )
                })
                .transpose()?;
            Ok(DataCall {
                message: call.message,
                part: call.part,
                kind: call.kind,
                bytes,
                signature,
            })
        };
        let phase = match metadata.phase {
            Boundary::Ready => Phase::Ready,
            Boundary::Begin(index) => Phase::Begin(index),
            Boundary::Receive(index) => Phase::Receive(index),
            Boundary::Data(call) => Phase::Data(restore_call(call)?),
            Boundary::Capacity {
                call,
                request,
                prepared,
            } => Phase::Capacity {
                call: restore_call(call)?,
                request,
                storage: if prepared {
                    CapacityStorage::Prepared
                } else {
                    CapacityStorage::Missing
                },
            },
            Boundary::Final => Phase::Final,
        };
        drop(restore_call);
        if input.is_some() || signature.is_some() {
            return Err(invalid());
        }
        let _ = &temporary_credit;
        let source = metadata.binding;
        Ok(Materialized::Ready(NativeMessageOperation {
            observer: Observer::Ticket,
            binding: Binding {
                primary: crate::advanced::signature::binding::Binding {
                    key: source.key,
                    authentication: source.authentication,
                    roles: source.roles,
                    contract: source.contract,
                    own_revocation: source.own_revocation,
                    revocation: None,
                },
                writer: source.writer,
                primary_mode: source.primary_mode,
                auxiliary: source.auxiliary,
            },
            initialization: Some(initialization),
            expected,
            route: metadata.route,
            verify: metadata.verify,
            phase,
            execution: Execution::Captured,
            activity: metadata.activity,
            input: metadata.input,
            invalid_seen: metadata.invalid_seen,
            messages,
            released: ReleasedInput::default(),
            // materialize runs outside guards; fixed_bytes covers this leaf
            // in both predicted restoration size and actual parent credit.
            diagnostic: Some(crate::advanced::native_messages::prepared_diagnostic()),
            _metadata: parent_credit,
        }))
    }
}
