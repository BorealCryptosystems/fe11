// SPDX-License-Identifier: Apache-2.0
//! Borrowed generic-message archive sections. Decoding establishes representation,
//! not authenticity, destination key authority or permission to resume native work.
use super::{signature::Graph, Function, Limits, Reader, Writer};
use crate::mechanism_extension::parameter_keys::KeyLocations;
use crate::NativeMessageRejection;
use crate::{bounds, Error, MechanismExtension, MechanismLayoutProvenance, MessageRoute, Result};
mod validation;

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::MessageRecord(
        crate::MessageRecordRejection::GenericMessageArchiveRepresentation,
    ))
}

fn width(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| invalid())
}

fn native_length(value: u64) -> Result<usize> {
    let value = width(value)?;
    bounds::ck_length(value)?;
    Ok(value)
}

/// Serialized declaration metadata is compared with a live destination contract.
/// Neither a standard provenance bit nor an old module identity creates that contract.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Declaration {
    pub mechanism: u64,
    pub edition: (u8, u8),
    pub caller_asserted: bool,
    pub mutates_key: bool,
}

impl Declaration {
    pub(in crate::advanced) fn from_contract(contract: &MechanismExtension) -> Self {
        Self {
            mechanism: contract.mechanism_number(),
            edition: contract.constants_edition(),
            caller_asserted: contract.provenance()
                == MechanismLayoutProvenance::CallerAssertedLayout,
            mutates_key: contract.mutates_key(),
        }
    }

    /// Init is never reissued from an archive. Its standard declaration can
    /// therefore be retained as metadata; callable per-message graphs require
    /// an explicit destination ABI assertion, irrespective of an archive bit.
    pub(in crate::advanced) fn resolve(
        self,
        session: &crate::Session,
        operation: crate::ExtensionOperation,
        supplied: Option<&MechanismExtension>,
        callable: bool,
    ) -> Result<MechanismExtension> {
        let contract = if callable || self.caller_asserted {
            let supplied =
                supplied.ok_or(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::ImportRequiresADestinationAbiDeclaration,
                )))?;
            if callable && supplied.provenance() != MechanismLayoutProvenance::CallerAssertedLayout
            {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::ImportedCallableGraphRequiresAnAssertedAbi,
                )));
            }
            supplied.check(&session.inner, operation)?;
            supplied.clone()
        } else if let Some(supplied) = supplied {
            supplied.check(&session.inner, operation)?;
            supplied.clone()
        } else {
            MechanismExtension::standard(
                &session.inner,
                fe11_sys::CK_MECHANISM_TYPE::try_from(self.mechanism).map_err(|_| invalid())?,
                operation,
            )
        };
        if contract.mechanism_number() != self.mechanism
            || contract.constants_edition() != self.edition
            || contract.mutates_key() != self.mutates_key
        {
            return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::GenericMessageImportDeclarationMismatch,
            )));
        }
        Ok(contract)
    }

    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u64(self.mechanism)?;
        writer.u8(self.edition.0)?;
        writer.u8(self.edition.1)?;
        writer.u8(u8::from(self.caller_asserted))?;
        writer.u8(u8::from(self.mutates_key))
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let mechanism = reader.u64()?;
        fe11_sys::CK_MECHANISM_TYPE::try_from(mechanism).map_err(|_| invalid())?;
        Ok(Self {
            mechanism,
            edition: (reader.u8()?, reader.u8()?),
            caller_asserted: reader.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::GenericMessageLayoutProvenance,
            ))?,
            mutates_key: reader.boolean(crate::RejectionReason::MessageRecord(
                crate::MessageRecordRejection::GenericMessageKeyEffect,
            ))?,
        })
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Parameter<'a> {
    pub graph: Graph<'a>,
    pub declaration: Option<Declaration>,
}

impl<'a> Parameter<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        self.graph.write(writer)?;
        writer.u8(u8::from(self.declaration.is_some()))?;
        if let Some(declaration) = self.declaration {
            declaration.write(writer)?;
        }
        Ok(())
    }

    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let bytes = reader.bytes(limits.bytes)?;
        reader.inspect_graph(bytes)?;
        let declaration = if reader.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::GenericMessageDeclarationPresence,
        ))? {
            Some(Declaration::read(reader)?)
        } else {
            None
        };
        Ok(Self {
            graph: Graph::Encoded(bytes),
            declaration,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum DataKind {
    Single,
    Update,
    Last,
}

impl DataKind {
    pub(in crate::advanced) fn terminal(self) -> bool {
        !matches!(self, Self::Update)
    }

    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(match self {
            Self::Single => 0,
            Self::Update => 1,
            Self::Last => 2,
        })
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.u8()? {
            0 => Ok(Self::Single),
            1 => Ok(Self::Update),
            2 => Ok(Self::Last),
            _ => Err(invalid()),
        }
    }
}

/// Only the still-retained call is serialized. Consumed input is represented by
/// the descriptor's counters, never by reconstructed or repeated message bytes.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Call<'a> {
    pub message: usize,
    pub part: usize,
    pub kind: DataKind,
    pub bytes: &'a [u8],
    pub signature: Option<&'a [u8]>,
}

impl<'a> Call<'a> {
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u64(self.message as u64)?;
        writer.u64(self.part as u64)?;
        self.kind.write(writer)?;
        writer.bytes(self.bytes)?;
        writer.optional_bytes(self.signature)
    }

    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let value = Self {
            message: width(reader.u64()?)?,
            part: width(reader.u64()?)?,
            kind: DataKind::read(reader)?,
            bytes: reader.bytes(limits.bytes)?,
            signature: reader.optional_bytes(limits.bytes)?,
        };
        bounds::ck_length(value.bytes.len())?;
        if let Some(signature) = value.signature {
            bounds::ck_length(signature.len())?;
        }
        Ok(value)
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) enum Boundary<'a> {
    Ready,
    Begin(usize),
    Receive(usize),
    Data(Call<'a>),
    Capacity {
        call: Call<'a>,
        required: usize,
        previous_capacity: usize,
        code: u64,
        prepared: bool,
    },
    Final,
}

impl<'a> Boundary<'a> {
    pub(in crate::advanced) fn call(self) -> Option<Call<'a>> {
        match self {
            Self::Data(call) | Self::Capacity { call, .. } => Some(call),
            _ => None,
        }
    }

    pub(in crate::advanced) fn function(self, verify: bool) -> &'static str {
        match self {
            Self::Ready => {
                if verify {
                    "C_MessageVerifyInit"
                } else {
                    "C_MessageSignInit"
                }
            }
            Self::Begin(_) | Self::Receive(_) => {
                if verify {
                    "C_VerifyMessageBegin"
                } else {
                    "C_SignMessageBegin"
                }
            }
            Self::Data(call) | Self::Capacity { call, .. } => match (verify, call.kind) {
                (false, DataKind::Single) => "C_SignMessage",
                (true, DataKind::Single) => "C_VerifyMessage",
                (false, _) => "C_SignMessageNext",
                (true, _) => "C_VerifyMessageNext",
            },
            Self::Final => {
                if verify {
                    "C_MessageVerifyFinal"
                } else {
                    "C_MessageSignFinal"
                }
            }
        }
    }

    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::Ready => writer.u8(0),
            Self::Begin(index) | Self::Receive(index) => {
                writer.u8(if matches!(self, Self::Begin(_)) { 1 } else { 2 })?;
                writer.u64(index as u64)
            }
            Self::Data(call) => {
                writer.u8(3)?;
                call.write(writer)
            }
            Self::Capacity {
                call,
                required,
                previous_capacity,
                code,
                prepared,
            } => {
                writer.u8(4)?;
                call.write(writer)?;
                writer.u64(required as u64)?;
                writer.u64(previous_capacity as u64)?;
                writer.u64(code)?;
                writer.u8(u8::from(prepared))
            }
            Self::Final => writer.u8(5),
        }
    }

    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        match reader.u8()? {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Begin(width(reader.u64()?)?)),
            2 => Ok(Self::Receive(width(reader.u64()?)?)),
            3 => Ok(Self::Data(Call::read(reader, limits)?)),
            4 => {
                let call = Call::read(reader, limits)?;
                let required = native_length(reader.u64()?)?;
                let previous_capacity = native_length(reader.u64()?)?;
                let code = reader.u64()?;
                fe11_sys::CK_RV::try_from(code).map_err(|_| invalid())?;
                Ok(Self::Capacity {
                    call,
                    required,
                    previous_capacity,
                    code,
                    prepared: reader.boolean(crate::RejectionReason::MessageRecord(
                        crate::MessageRecordRejection::GenericMessageCapacityPrepared,
                    ))?,
                })
            }
            5 => Ok(Self::Final),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Header<'a> {
    pub route: MessageRoute,
    pub writer: bool,
    pub invalid_seen: bool,
    pub initialization: Parameter<'a>,
    pub locations: KeyLocations,
    pub boundary: Boundary<'a>,
}

impl<'a> Header<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(match self.route {
            MessageRoute::Single => 0,
            MessageRoute::Multipart => 1,
        })?;
        writer.u8(u8::from(self.writer))?;
        writer.u8(u8::from(self.invalid_seen))?;
        self.initialization.write(writer)?;
        writer.generated_bytes(self.locations.encoded_len()?, |emit| {
            self.locations.write(emit)
        })?;
        self.boundary.write(writer)
    }

    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let route = match reader.u8()? {
            0 => MessageRoute::Single,
            1 => MessageRoute::Multipart,
            _ => return Err(invalid()),
        };
        let writer = reader.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::GenericMessageWriterDeclaration,
        ))?;
        let invalid_seen = reader.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::GenericMessageInvalidVerdict,
        ))?;
        let initialization = Parameter::read(reader, limits)?;
        if initialization.declaration.is_none() {
            return Err(invalid());
        }
        let locations = KeyLocations::parse(reader.bytes(limits.bytes)?)?;
        let boundary = Boundary::read(reader, limits)?;
        Ok(Self {
            route,
            writer,
            invalid_seen,
            initialization,
            locations,
            boundary,
        })
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Signature<'a> {
    /// None denotes the explicitly returned buffer after BUFFER_TOO_SMALL.
    pub bytes: Option<&'a [u8]>,
    pub capacity: usize,
    pub returned_length: usize,
    pub produced: Option<usize>,
}

#[derive(Clone, Copy)]
pub(in crate::advanced) enum Output<'a> {
    Sign(Option<Signature<'a>>),
    Verify(Option<u64>),
}

impl<'a> Output<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::Sign(None) => writer.u8(0),
            Self::Sign(Some(signature)) => {
                writer.u8(1)?;
                writer.optional_bytes(signature.bytes)?;
                writer.u64(signature.capacity as u64)?;
                writer.u64(signature.returned_length as u64)?;
                writer.optional_u64(signature.produced.map(|n| n as u64))
            }
            Self::Verify(verdict) => {
                writer.u8(2)?;
                writer.optional_u64(verdict)
            }
        }
    }

    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        match reader.u8()? {
            0 => Ok(Self::Sign(None)),
            1 => {
                let bytes = reader.optional_bytes(limits.bytes)?;
                let capacity = native_length(reader.u64()?)?;
                let returned_length = native_length(reader.u64()?)?;
                let produced = reader.optional_u64()?.map(native_length).transpose()?;
                if bytes.is_some_and(|bytes| bytes.len() != capacity)
                    || produced.is_some_and(|n| n > capacity || bytes.is_none())
                {
                    return Err(invalid());
                }
                Ok(Self::Sign(Some(Signature {
                    bytes,
                    capacity,
                    returned_length,
                    produced,
                })))
            }
            2 => {
                let verdict = reader.optional_u64()?;
                if let Some(code) = verdict {
                    fe11_sys::CK_RV::try_from(code).map_err(|_| invalid())?;
                }
                Ok(Self::Verify(verdict))
            }
            _ => Err(invalid()),
        }
    }
}

/// Each iterator reparses bounded immutable ranges and owns no allocated rows.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Parts<'a> {
    bytes: &'a [u8],
    count: usize,
    limits: Limits,
}
impl<'a> Parts<'a> {
    pub(in crate::advanced) fn len(self) -> usize {
        self.count
    }
    pub(in crate::advanced) fn iter(self) -> PartIter<'a> {
        PartIter {
            reader: Reader {
                graph_observer: None,
                bytes: self.bytes,
                position: 0,
            },
            remaining: self.count,
            limits: self.limits,
        }
    }
    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let count = reader.count(limits.fragments)?;
        let start = reader.position;
        for _ in 0..count {
            Parameter::read(reader, limits)?;
        }
        Ok(Self {
            bytes: &reader.bytes[start..reader.position],
            count,
            limits,
        })
    }
}
pub(in crate::advanced) struct PartIter<'a> {
    reader: Reader<'a>,
    remaining: usize,
    limits: Limits,
}
impl<'a> Iterator for PartIter<'a> {
    type Item = Result<Parameter<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = Parameter::read(&mut self.reader, self.limits);
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Row<'a> {
    pub begin: Option<Parameter<'a>>,
    pub parts: Parts<'a>,
    pub output: Output<'a>,
    pub rejection: Option<NativeMessageRejection>,
}
impl<'a> Row<'a> {
    fn read(reader: &mut Reader<'a>, limits: Limits, refusals: bool) -> Result<Self> {
        let begin = if reader.boolean(crate::RejectionReason::MessageRecord(
            crate::MessageRecordRejection::GenericMessageBeginPresence,
        ))? {
            Some(Parameter::read(reader, limits)?)
        } else {
            None
        };
        Ok(Self {
            begin,
            parts: Parts::read(reader, limits)?,
            output: Output::read(reader, limits)?,
            rejection: if refusals
                && reader.boolean(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::GenericMessageRefusal,
                ))? {
                let function = Function::read(reader)?.name();
                let code = reader.u64()?;
                fe11_sys::CK_RV::try_from(code).map_err(|_| invalid())?;
                Some(NativeMessageRejection { function, code })
            } else {
                None
            },
        })
    }
}

/// Emit one live row without building a second array of borrowed graph views.
pub(in crate::advanced) fn write_row<'a>(
    writer: &mut Writer<'_>,
    limits: Limits,
    begin: Option<Parameter<'a>>,
    parts: usize,
    mut parameter: impl FnMut(usize) -> Result<Parameter<'a>>,
    output: Output<'a>,
    rejection: Option<NativeMessageRejection>,
) -> Result<()> {
    if parts > limits.fragments {
        return Err(invalid());
    }
    writer.u8(u8::from(begin.is_some()))?;
    if let Some(begin) = begin {
        begin.write(writer)?;
    }
    writer.u32(u32::try_from(parts).map_err(|_| invalid())?)?;
    for index in 0..parts {
        parameter(index)?.write(writer)?;
    }
    output.write(writer)?;
    writer.u8(u8::from(rejection.is_some()))?;
    if let Some(rejection) = rejection {
        Function::from_name(rejection.function)?.write(writer)?;
        writer.u64(rejection.code)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Record<'a> {
    pub header: Header<'a>,
    bytes: &'a [u8],
    count: usize,
    limits: Limits,
    refusals: bool,
}
impl<'a> Record<'a> {
    pub(in crate::advanced) fn read(
        reader: &mut Reader<'a>,
        limits: Limits,
        refusals: bool,
    ) -> Result<Self> {
        let header = Header::read(reader, limits)?;
        let count = reader.count(limits.messages)?;
        let start = reader.position;
        let mut fragments = 0usize;
        for _ in 0..count {
            let row = Row::read(reader, limits, refusals)?;
            fragments = fragments
                .checked_add(row.parts.len())
                .filter(|n| *n <= limits.fragments)
                .ok_or_else(invalid)?;
        }
        Ok(Self {
            header,
            bytes: &reader.bytes[start..reader.position],
            count,
            limits,
            refusals,
        })
    }
    pub(in crate::advanced) fn len(self) -> usize {
        self.count
    }
    pub(in crate::advanced) fn iter(self) -> RowIter<'a> {
        RowIter {
            reader: Reader {
                graph_observer: None,
                bytes: self.bytes,
                position: 0,
            },
            remaining: self.count,
            limits: self.limits,
            refusals: self.refusals,
        }
    }
}
pub(in crate::advanced) struct RowIter<'a> {
    reader: Reader<'a>,
    remaining: usize,
    limits: Limits,
    refusals: bool,
}
impl<'a> Iterator for RowIter<'a> {
    type Item = Result<Row<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = Row::read(&mut self.reader, self.limits, self.refusals);
        if result.is_err() {
            self.remaining = 0;
        }
        Some(result)
    }
}
