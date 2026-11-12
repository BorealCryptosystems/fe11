// SPDX-License-Identifier: Apache-2.0
//! Prepaid generic archive reconstruction. No key role or native state is
//! acquired here; the imported owner remains Captured until explicit restore.
use super::{
    binding::Binding, restoration, CapacityStorage, DataCall, DataKind, Execution, Message,
    MessageOutput, NativeMessageOperation, Observer, Parameters, Phase, ReleasedInput,
    SignatureOutput,
};
use crate::advanced::record::native_messages as wire;
use crate::advanced::{record, NativeActivity};
use crate::mechanism_extension::{
    graph::{recipe, snapshot::SnapshotRecipe, GraphStorage, OwnedGraph},
    message::initialization::Initialization,
};
use crate::native::derivation::InputBytesStorage;
use crate::symmetric::memory::{Credit, UnboundBuffer};
use crate::{Error, MechanismExtension, Result, Session};
use std::mem::size_of;

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageReconstruction,
    ))
}
fn add(total: &mut usize, bytes: usize) -> Result<()> {
    *total = total.checked_add(bytes).ok_or_else(invalid)?;
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
fn graph_bytes(parameter: wire::Parameter<'_>) -> Result<usize> {
    OwnedGraph::recipe_bytes(&SnapshotRecipe::decode(parameter.graph.encoded()?)?)
}

pub(in crate::advanced) struct RecordPlan<'a> {
    session: &'a Session,
    descriptor: record::Descriptor,
    record: wire::Record<'a>,
    initialization: restoration::InitializationPlan<'a>,
    declarations: &'a [Option<&'a MechanismExtension>],
}
struct ParameterStorage<'a> {
    graph: GraphStorage<'a>,
    contract: Option<MechanismExtension>,
}
struct RowStorage<'a> {
    begin: Option<ParameterStorage<'a>>,
    parts: Vec<ParameterStorage<'a>>,
    parameters: Vec<Parameters>,
    output: Option<UnboundBuffer>,
    // Partial parameter binding must retain the charge of the destination table.
    metadata: Option<Credit>,
}
pub(in crate::advanced) struct Storage<'a> {
    initialization: restoration::InitializationStorage<'a>,
    rows: Vec<RowStorage<'a>>,
    messages: Vec<Message>,
    input: Option<InputBytesStorage>,
    signature: Option<InputBytesStorage>,
    // Credits follow every payload, including partially populated messages.
    temporary: Option<Credit>,
    metadata: Option<Credit>,
}
pub(in crate::advanced) struct PreparedCheckpoint {
    descriptor: record::Descriptor,
    route: crate::MessageRoute,
    writer: bool,
    invalid_seen: bool,
    initialization: Box<Initialization>,
    diagnostic: Box<Error>,
    messages: Vec<Message>,
    phase: Phase,
    metadata: Credit,
}

impl<'a> RecordPlan<'a> {
    /// The enclosing Recipe validates all archive sections first. This adds the
    /// destination's current input ceilings without reconsidering consumed history.
    pub(in crate::advanced) fn new(
        session: &'a Session,
        descriptor: record::Descriptor,
        record: wire::Record<'a>,
        initialization: restoration::InitializationPlan<'a>,
        declarations: &'a [Option<&'a MechanismExtension>],
        ceilings: crate::CryptoLimits,
    ) -> Result<Self> {
        if let Some(call) = record.header.boundary.call() {
            crate::InputLimits {
                maximum_parts: ceilings.maximum_parts,
                maximum_total_bytes: ceilings.maximum_total_bytes,
            }
            .validate(ceilings, &[call.bytes])?;
        }
        Ok(Self {
            session,
            descriptor,
            record,
            initialization,
            declarations,
        })
    }

    pub(in crate::advanced) fn allocation_bytes(&self) -> Result<usize> {
        let mut total = self.initialization.allocation_bytes()?;
        add(&mut total, size_of::<NativeMessageOperation>())?;
        add(&mut total, super::DIAGNOSTIC_BYTES)?;
        add(&mut total, slots::<Message>(self.record.len())?)?;
        add(&mut total, slots::<RowStorage<'_>>(self.record.len())?)?;
        for row in self.record.iter() {
            let row = row?;
            add(&mut total, slots::<ParameterStorage<'_>>(row.parts.len())?)?;
            add(&mut total, slots::<Parameters>(row.parts.len())?)?;
            for parameter in row.begin.into_iter().map(Ok).chain(row.parts.iter()) {
                add(&mut total, graph_bytes(parameter?)?)?;
            }
            if let wire::Output::Sign(Some(output)) = row.output {
                if output.bytes.is_some() {
                    add(
                        &mut total,
                        crate::advanced::signature::output_storage_bytes(
                            self.descriptor.mechanism,
                            output.capacity,
                        )?,
                    )?;
                }
                add(&mut total, size_of::<fe11_sys::CK_ULONG>())?;
            }
        }
        if let Some(call) = self.record.header.boundary.call() {
            for bytes in std::iter::once(call.bytes).chain(call.signature) {
                add(&mut total, bytes.len().checked_mul(2).ok_or_else(invalid)?)?;
            }
        }
        Ok(total)
    }

    pub(in crate::advanced) fn allocate(&self) -> Result<Storage<'a>> {
        let operation = crate::mechanism_extension::message::operation_kind(
            self.descriptor.profile == 1,
            self.record.header.route == crate::MessageRoute::Multipart,
        );
        let mut index = 0usize;
        let mut parameter = |parameter: wire::Parameter<'a>| -> Result<ParameterStorage<'a>> {
            let supplied = if self.declarations.is_empty() {
                None
            } else {
                self.declarations.get(index).copied().ok_or_else(invalid)?
            };
            index = index.checked_add(1).ok_or_else(invalid)?;
            let contract = match parameter.declaration {
                Some(declaration) => {
                    Some(declaration.resolve(self.session, operation, supplied, true)?)
                }
                None if supplied.is_none() => None,
                None => return Err(invalid()),
            };
            let graph = GraphStorage::allocate_input(recipe::Input::Snapshot(
                SnapshotRecipe::decode(parameter.graph.encoded()?)?,
            ))?;
            Ok(ParameterStorage { graph, contract })
        };
        let initialization = self.initialization.allocate()?;
        let mut rows = reserve(self.record.len())?;
        let messages = reserve(self.record.len())?;
        for row in self.record.iter() {
            let row = row?;
            let begin = row.begin.map(&mut parameter).transpose()?;
            let mut parts = reserve(row.parts.len())?;
            for part in row.parts.iter() {
                parts.push(parameter(part?)?);
            }
            let parameters = reserve(row.parts.len())?;
            let output = match row.output {
                wire::Output::Sign(Some(output)) => {
                    Some(UnboundBuffer::allocate(if output.bytes.is_some() {
                        crate::advanced::signature::output_storage_bytes(
                            self.descriptor.mechanism,
                            output.capacity,
                        )?
                    } else {
                        0
                    })?)
                }
                _ => None,
            };
            rows.push(RowStorage {
                begin,
                parts,
                parameters,
                output,
                metadata: None,
            });
        }
        drop(parameter);
        if !self.declarations.is_empty() && index != self.declarations.len() {
            return Err(invalid());
        }
        let call = self.record.header.boundary.call();
        Ok(Storage {
            initialization,
            rows,
            messages,
            input: call
                .map(|call| InputBytesStorage::allocate(call.bytes.len()))
                .transpose()?,
            signature: call
                .and_then(|call| call.signature)
                .map(|bytes| InputBytesStorage::allocate(bytes.len()))
                .transpose()?,
            temporary: None,
            metadata: None,
        })
    }

    pub(in crate::advanced) fn bind(
        self,
        mut storage: Storage<'a>,
        prepaid: &mut Credit,
    ) -> Result<PreparedCheckpoint> {
        storage.temporary = Some(prepaid.split(storage.temporary_bytes()?)?);
        storage.metadata = Some(
            prepaid.split(
                size_of::<NativeMessageOperation>()
                    .checked_add(slots::<Message>(storage.messages.capacity())?)
                    .and_then(|bytes| bytes.checked_add(super::DIAGNOSTIC_BYTES))
                    .ok_or_else(invalid)?,
            )?,
        );
        let initialization = storage
            .initialization
            .bind(prepaid)?
            .into_initialization(storage.metadata.as_mut().expect("bound parent metadata"))?;
        let mut records = self.record.iter();
        for mut row in storage.rows {
            let original = records.next().ok_or_else(invalid)??;
            let mut row_credit = slots::<Parameters>(row.parameters.capacity())?;
            if row.output.is_some() {
                add(&mut row_credit, size_of::<fe11_sys::CK_ULONG>())?;
            }
            row.metadata = Some(prepaid.split(row_credit)?);
            let begin = row.begin.map(|part| part.bind(prepaid)).transpose()?;
            let mut parts = row.parameters;
            for part in row.parts {
                parts.push(part.bind(prepaid)?);
            }
            let output = match (original.output, row.output) {
                (wire::Output::Sign(None), None) => MessageOutput::Sign(None),
                (wire::Output::Verify(verdict), None) => MessageOutput::Verify {
                    verdict: verdict
                        .map(|code| fe11_sys::CK_RV::try_from(code).map_err(|_| invalid()))
                        .transpose()?,
                },
                (wire::Output::Sign(Some(original)), Some(output)) => {
                    let mut bytes = output.bind(prepaid)?;
                    let offset = if let Some(source) = original.bytes {
                        let offset = crate::advanced::signature::output_offset(
                            self.descriptor.mechanism,
                            &mut bytes,
                        )?;
                        let end = offset.checked_add(source.len()).ok_or_else(invalid)?;
                        bytes
                            .as_mut()
                            .get_mut(offset..end)
                            .ok_or_else(invalid)?
                            .copy_from_slice(source);
                        bytes.set_length(
                            offset
                                .checked_add(original.produced.unwrap_or(0))
                                .ok_or_else(invalid)?,
                        )?;
                        offset
                    } else {
                        0
                    };
                    MessageOutput::Sign(Some(SignatureOutput {
                        bytes,
                        offset,
                        capacity: original.capacity,
                        length: Box::new(crate::bounds::ck_length(original.returned_length)?),
                        produced: original.produced,
                    }))
                }
                _ => return Err(invalid()),
            };
            storage.messages.push(Message {
                rejection: original.rejection,
                begin,
                parts,
                output,
                _metadata: row.metadata.take().expect("bound row metadata"),
            });
        }
        if records.next().is_some() {
            return Err(invalid());
        }
        let mut call = |call: wire::Call<'a>| -> Result<DataCall> {
            let bytes = storage
                .input
                .take()
                .ok_or_else(invalid)?
                .bind(call.bytes, prepaid)?;
            let signature = match (storage.signature.take(), call.signature) {
                (Some(storage), Some(bytes)) => Some(storage.bind(bytes, prepaid)?),
                (None, None) => None,
                _ => return Err(invalid()),
            };
            Ok(DataCall {
                message: call.message,
                part: call.part,
                bytes,
                signature,
                kind: match call.kind {
                    wire::DataKind::Single => DataKind::Single,
                    wire::DataKind::Update => DataKind::Update,
                    wire::DataKind::Last => DataKind::Last,
                },
            })
        };
        let phase = match self.record.header.boundary {
            wire::Boundary::Ready => Phase::Ready,
            wire::Boundary::Begin(index) => Phase::Begin(index),
            wire::Boundary::Receive(index) => Phase::Receive(index),
            wire::Boundary::Data(value) => Phase::Data(call(value)?),
            boundary @ wire::Boundary::Capacity {
                call: value,
                required,
                previous_capacity,
                code,
                prepared,
            } => Phase::Capacity {
                call: call(value)?,
                request: crate::advanced::SignatureBufferRequest {
                    function: boundary.function(false),
                    required,
                    previous_capacity,
                    code,
                },
                storage: if prepared {
                    CapacityStorage::Prepared
                } else {
                    CapacityStorage::Missing
                },
            },
            wire::Boundary::Final => Phase::Final,
        };
        drop(call);
        if storage.input.is_some() || storage.signature.is_some() {
            return Err(invalid());
        }
        Ok(PreparedCheckpoint {
            diagnostic: super::prepared_diagnostic(),
            descriptor: self.descriptor,
            route: self.record.header.route,
            writer: self.record.header.writer,
            invalid_seen: self.record.header.invalid_seen,
            initialization,
            messages: storage.messages,
            phase,
            metadata: storage.metadata.take().expect("bound parent metadata"),
        })
    }
}

impl ParameterStorage<'_> {
    fn bind(self, prepaid: &mut Credit) -> Result<Parameters> {
        Ok(Parameters {
            graph: Box::new(self.graph.bind(prepaid)?),
            contract: self.contract,
        })
    }
}
impl Storage<'_> {
    fn temporary_bytes(&self) -> Result<usize> {
        let mut total = slots::<RowStorage<'_>>(self.rows.capacity())?;
        for row in &self.rows {
            add(
                &mut total,
                slots::<ParameterStorage<'_>>(row.parts.capacity())?,
            )?;
        }
        Ok(total)
    }
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        let mut total = self.initialization.allocated_bytes()?;
        add(&mut total, self.temporary_bytes()?)?;
        add(&mut total, size_of::<NativeMessageOperation>())?;
        add(&mut total, super::DIAGNOSTIC_BYTES)?;
        add(&mut total, slots::<Message>(self.messages.capacity())?)?;
        for row in &self.rows {
            add(&mut total, slots::<Parameters>(row.parameters.capacity())?)?;
            for part in row.begin.iter().chain(row.parts.iter()) {
                add(&mut total, part.graph.allocated_bytes()?)?;
            }
            if let Some(output) = &row.output {
                add(&mut total, output.allocated())?;
                add(&mut total, size_of::<fe11_sys::CK_ULONG>())?;
            }
        }
        for input in self.input.iter().chain(self.signature.iter()) {
            add(&mut total, input.allocated_bytes()?)?;
        }
        Ok(total)
    }
}

impl PreparedCheckpoint {
    /// Validate the destination while the caller still owns both inputs.
    pub(in crate::advanced) fn check_binding(&self, binding: Option<&Binding>) -> Result<()> {
        let binding = binding.ok_or_else(invalid)?;
        if binding.writer != self.writer
            || binding.primary.contract.mechanism_number() != self.descriptor.mechanism
            || self.initialization.kind() != binding.primary.contract.native_mechanism()
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Transfer immediately after check_binding, with the same untouched inputs.
    pub(in crate::advanced) fn bind_checked(self, binding: Binding) -> NativeMessageOperation {
        let expected = self.initialization.expected();
        NativeMessageOperation {
            observer: Observer::Ticket,
            binding,
            initialization: Some(self.initialization),
            expected,
            route: self.route,
            verify: self.descriptor.profile == 2,
            phase: self.phase,
            execution: Execution::Captured,
            activity: NativeActivity::Active,
            input: self.descriptor.input,
            invalid_seen: self.invalid_seen,
            messages: self.messages,
            released: ReleasedInput::default(),
            diagnostic: Some(self.diagnostic),
            _metadata: self.metadata,
        }
    }
}

impl DataCall {
    fn archive(&self) -> wire::Call<'_> {
        wire::Call {
            message: self.message,
            part: self.part,
            kind: match self.kind {
                DataKind::Single => wire::DataKind::Single,
                DataKind::Update => wire::DataKind::Update,
                DataKind::Last => wire::DataKind::Last,
            },
            bytes: self.bytes.bytes(),
            signature: self.signature.as_ref().map(|input| input.bytes()),
        }
    }
}

impl Parameters {
    fn archive(&self) -> wire::Parameter<'_> {
        wire::Parameter {
            graph: record::signature::Graph::Live(&self.graph),
            declaration: self.contract.as_ref().map(wire::Declaration::from_contract),
        }
    }
}

impl NativeMessageOperation {
    /// Borrow an established boundary without making a captured owner runnable.
    /// This is also used by export, where next_function deliberately returns
    /// None for Captured: a serialized phase is not permission to execute it.
    fn archive_boundary(&self) -> Result<wire::Boundary<'_>> {
        if !matches!(self.execution, Execution::Running | Execution::Captured)
            || self.observer != Observer::Ticket
            || self.pending()
            || self.native_inactive()
            || self.initialization.is_none()
            || self.released.call.is_some()
            || self.released.output.is_some()
            || !self.unchanged()
        {
            return Err(invalid());
        }
        Ok(match &self.phase {
            Phase::Ready => wire::Boundary::Ready,
            Phase::Begin(index) => wire::Boundary::Begin(*index),
            Phase::Receive(index) => wire::Boundary::Receive(*index),
            Phase::Data(call) => wire::Boundary::Data(call.archive()),
            Phase::Capacity {
                call,
                request,
                storage,
            } => wire::Boundary::Capacity {
                call: call.archive(),
                required: request.required,
                previous_capacity: request.previous_capacity,
                code: request.code,
                prepared: matches!(storage, CapacityStorage::Prepared),
            },
            Phase::Final => wire::Boundary::Final,
            Phase::Init | Phase::Complete => return Err(invalid()),
        })
    }

    pub(in crate::advanced) fn checkpoint_header(
        &self,
    ) -> Result<(record::Descriptor, record::KeyBindings<'_>)> {
        let boundary = self.archive_boundary()?;
        Ok((
            record::Descriptor {
                input: self.input,
                family: record::Family::NativeMessages,
                profile: if self.verify { 2 } else { 1 },
                phase: record::Function::from_name(boundary.function(self.verify))?,
                mechanism: self.binding.primary.contract.mechanism_number(),
                size: 0,
                active_flags: 0,
                validation_requested: false,
                carried_messages: 0,
                cipher_options: None,
                digest_bits: None,
            },
            record::KeyBindings {
                cipher: None,
                authentication: Some(record::KeyBinding {
                    role: record::KeyRole::Authentication,
                    class: None,
                    key_type: None,
                    id: None,
                }),
            },
        ))
    }

    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        let boundary = self.archive_boundary()?;
        let (initialization, keys) = self.initialization().snapshot_parts();
        if self.messages.len() > limits.messages {
            return Err(invalid());
        }
        // Tag 5 adds per-row operational refusals. The decoder still accepts
        // historical tag 2, whose rows had no representation for such refusals.
        writer.u8(5)?;
        wire::Header {
            route: self.route,
            writer: self.binding.writer,
            invalid_seen: self.invalid_seen,
            initialization: wire::Parameter {
                graph: record::signature::Graph::Live(initialization),
                declaration: Some(wire::Declaration::from_contract(
                    &self.binding.primary.contract,
                )),
            },
            locations: keys.locations()?,
            boundary,
        }
        .write(writer)?;
        writer.u32(u32::try_from(self.messages.len()).map_err(|_| invalid())?)?;
        let mut fragments = 0usize;
        for (index, row) in self.messages.iter().enumerate() {
            fragments = fragments
                .checked_add(row.parts.len())
                .filter(|count| *count <= limits.fragments)
                .ok_or_else(invalid)?;
            let output = match &row.output {
                MessageOutput::Sign(None) => wire::Output::Sign(None),
                MessageOutput::Verify { verdict } => {
                    wire::Output::Verify(verdict.map(|code| code as u64))
                }
                MessageOutput::Sign(Some(output)) => {
                    let missing = matches!(&self.phase,
                        Phase::Capacity { call, storage: CapacityStorage::Missing, .. }
                            if call.message == index);
                    let bytes = if missing {
                        if output.bytes.capacity() != 0 || output.produced.is_some() {
                            return Err(invalid());
                        }
                        None
                    } else {
                        let capacity = output.capacity()?;
                        if output.produced.is_some_and(|length| length > capacity) {
                            return Err(invalid());
                        }
                        // Retained native output cells may still be written by
                        // parent Final. Preserve initialized capacity separately
                        // from the established result extent and current length.
                        Some(
                            output
                                .bytes
                                .initialized_storage()
                                .get(
                                    output.offset
                                        ..output
                                            .offset
                                            .checked_add(capacity)
                                            .ok_or_else(invalid)?,
                                )
                                .ok_or_else(invalid)?,
                        )
                    };
                    wire::Output::Sign(Some(wire::Signature {
                        bytes,
                        capacity: output.capacity,
                        returned_length: usize::try_from(*output.length).map_err(|_| invalid())?,
                        produced: output.produced,
                    }))
                }
            };
            wire::write_row(
                writer,
                limits,
                row.begin.as_ref().map(Parameters::archive),
                row.parts.len(),
                |part| {
                    row.parts
                        .get(part)
                        .map(Parameters::archive)
                        .ok_or_else(invalid)
                },
                output,
                row.rejection,
            )?;
        }
        Ok(())
    }
}
