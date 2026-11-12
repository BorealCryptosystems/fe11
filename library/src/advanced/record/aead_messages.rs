// SPDX-License-Identifier: Apache-2.0
//! Borrowed caller-fed AEAD state. Decoding never authenticates native state.
use super::{Function, Limits, Reader, Writer};
use crate::advanced::aead_parameters::{CipherKind, RecordSelection};
use crate::advanced::gcm::result::{Disposition, MessageAeadRejection};
use crate::{bounds, Error, MessageRoute, Result};
mod validation;

// Local capture uses the same payload without an external-record envelope.
// The packet remains private, erased on drop, and contains no native state.
pub(in crate::advanced) fn packet_size<'a>(
    limits: Limits,
    header: Header<'a>,
    count: usize,
    row: impl FnMut(usize) -> Result<Row<'a>>,
) -> Result<usize> {
    let mut writer = Writer {
        target: None,
        position: 0,
        maximum: limits.bytes,
    };
    write(&mut writer, limits, header, count, row)?;
    Ok(writer.position)
}

pub(in crate::advanced) fn write_packet<'a>(
    target: &mut [u8],
    limits: Limits,
    header: Header<'a>,
    count: usize,
    row: impl FnMut(usize) -> Result<Row<'a>>,
) -> Result<()> {
    let maximum = target.len();
    let mut writer = Writer {
        target: Some(target),
        position: 0,
        maximum,
    };
    write(&mut writer, limits, header, count, row)?;
    if writer.position != maximum {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::MessageRecord(
        crate::MessageRecordRejection::AeadStreamArchiveRepresentation,
    ))
}
fn width(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| invalid())
}
fn native_width(value: u64) -> Result<usize> {
    let value = width(value)?;
    bounds::ck_length(value)?;
    Ok(value)
}

/// Original selection, distinct from the current native nonce output.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Selection<'a> {
    pub nonce: &'a [u8],
    pub generator: u64,
    pub fixed_bits: u64,
    pub tag_bits: u64,
}
impl<'a> Selection<'a> {
    pub(in crate::advanced) fn from_live(
        value: &'a crate::advanced::aead_parameters::Selection,
    ) -> Result<Self> {
        Ok(Self {
            nonce: value.iv(),
            generator: value.generator()? as u64,
            fixed_bits: value.fixed_bits(),
            tag_bits: value.tag_bits(),
        })
    }
    pub(in crate::advanced) fn plan(self, kind: CipherKind) -> Result<RecordSelection<'a>> {
        RecordSelection::new(
            kind,
            &super::Parameters {
                digest_output: None,
                cipher_extension: None,
                digest_extension: None,
                signature: None,
                message_init: None,
                counter_bits: None,
                nonce: None,
                aad: None,
                digest_oid: None,
                tag_bits: u32::try_from(self.tag_bits).map_err(|_| invalid())?,
                iv_generator: Some(self.generator),
                iv_fixed_bits: Some(self.fixed_bits),
                iv_initial: Some(self.nonce),
                hash: None,
                mgf: None,
                salt: None,
            },
        )
    }
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.bytes(self.nonce)?;
        writer.u64(self.generator)?;
        writer.u64(self.fixed_bits)?;
        writer.u64(self.tag_bits)
    }
    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        Ok(Self {
            nonce: reader.bytes(limits.bytes)?,
            generator: reader.u64()?,
            fixed_bits: reader.u64()?,
            tag_bits: reader.u64()?,
        })
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Seed<'a> {
    pub selection: Selection<'a>,
    pub declared_length: usize,
    pub expected_tag: Option<&'a [u8]>,
}
impl<'a> Seed<'a> {
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        self.selection.write(writer)?;
        writer.u64(self.declared_length as u64)?;
        writer.optional_bytes(self.expected_tag)
    }
    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        Ok(Self {
            selection: Selection::read(reader, limits)?,
            declared_length: width(reader.u64()?)?,
            expected_tag: reader.optional_bytes(limits.bytes)?,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum Target {
    Seed,
    Message(usize),
}

#[derive(Clone, Copy)]
pub(in crate::advanced) enum Initial<'a> {
    None,
    Shared {
        target: Target,
        seed: Option<Seed<'a>>,
        nonce: &'a [u8],
        tag: &'a [u8],
    },
}
impl<'a> Initial<'a> {
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::None => writer.u8(0),
            Self::Shared {
                target,
                seed,
                nonce,
                tag,
            } => {
                writer.u8(1)?;
                match target {
                    Target::Seed => writer.u8(0)?,
                    Target::Message(index) => {
                        writer.u8(1)?;
                        writer.u64(index as u64)?;
                    }
                }
                writer.u8(u8::from(seed.is_some()))?;
                if let Some(seed) = seed {
                    seed.write(writer)?;
                }
                writer.bytes(nonce)?;
                writer.bytes(tag)
            }
        }
    }
    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        match reader.u8()? {
            0 => Ok(Self::None),
            1 => {
                let target = match reader.u8()? {
                    0 => Target::Seed,
                    1 => Target::Message(width(reader.u64()?)?),
                    _ => return Err(invalid()),
                };
                let seed = if reader.boolean(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::AeadInitSeed,
                ))? {
                    Some(Seed::read(reader, limits)?)
                } else {
                    None
                };
                Ok(Self::Shared {
                    target,
                    seed,
                    nonce: reader.bytes(limits.bytes)?,
                    tag: reader.bytes(limits.bytes)?,
                })
            }
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum Call {
    Single(usize),
    Update(usize),
    Last(usize),
}
impl Call {
    pub(in crate::advanced) fn index(self) -> usize {
        match self {
            Self::Single(index) | Self::Update(index) | Self::Last(index) => index,
        }
    }
    pub(in crate::advanced) fn function(self, decrypt: bool) -> &'static str {
        match (self, decrypt) {
            (Self::Single(_), false) => "C_EncryptMessage",
            (Self::Single(_), true) => "C_DecryptMessage",
            (_, false) => "C_EncryptMessageNext",
            (_, true) => "C_DecryptMessageNext",
        }
    }
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(match self {
            Self::Single(_) => 0,
            Self::Update(_) => 1,
            Self::Last(_) => 2,
        })?;
        writer.u64(self.index() as u64)
    }
    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let tag = reader.u8()?;
        let index = width(reader.u64()?)?;
        match tag {
            0 => Ok(Self::Single(index)),
            1 => Ok(Self::Update(index)),
            2 => Ok(Self::Last(index)),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) enum Boundary {
    Ready,
    Begin(usize),
    Receive(usize),
    Data(Call),
    Capacity {
        call: Call,
        required: usize,
        previous: usize,
        prepared: bool,
    },
    Finish,
}
impl Boundary {
    pub(in crate::advanced) fn index(self) -> Option<usize> {
        match self {
            Self::Begin(index) | Self::Receive(index) => Some(index),
            Self::Data(call) | Self::Capacity { call, .. } => Some(call.index()),
            Self::Ready | Self::Finish => None,
        }
    }
    pub(in crate::advanced) fn call(self) -> Option<Call> {
        match self {
            Self::Data(call) | Self::Capacity { call, .. } => Some(call),
            _ => None,
        }
    }
    pub(in crate::advanced) fn function(self, decrypt: bool) -> &'static str {
        match (self, decrypt) {
            (Self::Ready, false) => "C_MessageEncryptInit",
            (Self::Ready, true) => "C_MessageDecryptInit",
            (Self::Begin(_) | Self::Receive(_), false) => "C_EncryptMessageBegin",
            (Self::Begin(_) | Self::Receive(_), true) => "C_DecryptMessageBegin",
            (Self::Data(call) | Self::Capacity { call, .. }, _) => call.function(decrypt),
            (Self::Finish, false) => "C_MessageEncryptFinal",
            (Self::Finish, true) => "C_MessageDecryptFinal",
        }
    }
    fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        match self {
            Self::Ready => writer.u8(0),
            Self::Begin(index) => {
                writer.u8(1)?;
                writer.u64(index as u64)
            }
            Self::Receive(index) => {
                writer.u8(2)?;
                writer.u64(index as u64)
            }
            Self::Data(call) => {
                writer.u8(3)?;
                call.write(writer)
            }
            Self::Capacity {
                call,
                required,
                previous,
                prepared,
            } => {
                writer.u8(4)?;
                call.write(writer)?;
                writer.u64(required as u64)?;
                writer.u64(previous as u64)?;
                writer.u8(u8::from(prepared))
            }
            Self::Finish => writer.u8(5),
        }
    }
    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        match reader.u8()? {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Begin(width(reader.u64()?)?)),
            2 => Ok(Self::Receive(width(reader.u64()?)?)),
            3 => Ok(Self::Data(Call::read(reader)?)),
            4 => Ok(Self::Capacity {
                call: Call::read(reader)?,
                required: native_width(reader.u64()?)?,
                previous: native_width(reader.u64()?)?,
                prepared: reader.boolean(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::AeadPreparedOutput,
                ))?,
            }),
            5 => Ok(Self::Finish),
            _ => Err(invalid()),
        }
    }
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Header<'a> {
    pub route: MessageRoute,
    pub boundary: Boundary,
    pub initial: Initial<'a>,
    pub fragment: Option<&'a [u8]>,
}
impl<'a> Header<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u8(match self.route {
            MessageRoute::Single => 1,
            MessageRoute::Multipart => 2,
        })?;
        self.boundary.write(writer)?;
        self.initial.write(writer)?;
        writer.optional_bytes(self.fragment)
    }
    fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let route = match reader.u8()? {
            1 => MessageRoute::Single,
            2 => MessageRoute::Multipart,
            _ => return Err(invalid()),
        };
        let result = Self {
            route,
            boundary: Boundary::read(reader)?,
            initial: Initial::read(reader, limits)?,
            fragment: reader.optional_bytes(limits.bytes)?,
        };
        if usize::from(result.fragment.is_some()) > limits.fragments {
            return Err(invalid());
        }
        Ok(result)
    }
}

/// Native length is deliberately independent of produced bytes and capacity:
/// an insufficient-buffer return may contain a larger required length.
#[derive(Clone, Copy)]
pub(in crate::advanced) struct Row<'a> {
    pub disposition: Disposition,
    /// None means an imported layout did not retain this history.
    pub accepted_input: Option<u128>,
    pub selection: Selection<'a>,
    pub declared_length: usize,
    pub aad: &'a [u8],
    pub nonce: &'a [u8],
    pub tag: &'a [u8],
    pub expected_tag: Option<&'a [u8]>,
    pub observed_nonce: Option<&'a [u8]>,
    pub output: &'a [u8],
    pub capacity: usize,
    pub native_length: usize,
}
impl<'a> Row<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        if self.output.len() > self.capacity {
            return Err(invalid());
        }
        self.selection.write(writer)?;
        writer.u64(self.declared_length as u64)?;
        writer.bytes(self.aad)?;
        writer.bytes(self.nonce)?;
        writer.bytes(self.tag)?;
        writer.optional_bytes(self.expected_tag)?;
        writer.optional_bytes(self.observed_nonce)?;
        writer.bytes(self.output)?;
        writer.u64(self.capacity as u64)?;
        writer.u64(self.native_length as u64)?;
        match self.disposition {
            Disposition::Candidate => writer.u8(0),
            Disposition::Rejected {
                rejection,
                discarded_output,
            } => {
                writer.u8(1)?;
                Function::from_name(rejection.function)?.write(writer)?;
                writer.u64(rejection.code)?;
                writer.u64(discarded_output as u64)
            }
        }?;
        match self.accepted_input {
            None => writer.u8(0),
            Some(bytes) => {
                writer.u8(1)?;
                writer.u64(bytes as u64)?;
                writer.u64((bytes >> 64) as u64)
            }
        }
    }
    fn read(
        reader: &mut Reader<'a>,
        limits: Limits,
        dispositions: bool,
        counters: bool,
    ) -> Result<Self> {
        let mut result = Self {
            disposition: Disposition::Candidate,
            accepted_input: None,
            selection: Selection::read(reader, limits)?,
            declared_length: width(reader.u64()?)?,
            aad: reader.bytes(limits.bytes)?,
            nonce: reader.bytes(limits.bytes)?,
            tag: reader.bytes(limits.bytes)?,
            expected_tag: reader.optional_bytes(limits.bytes)?,
            observed_nonce: reader.optional_bytes(limits.bytes)?,
            output: reader.bytes(limits.bytes)?,
            capacity: width(reader.u64()?)?,
            native_length: native_width(reader.u64()?)?,
        };
        if dispositions {
            result.disposition = match reader.u8()? {
                0 => Disposition::Candidate,
                1 => Disposition::Rejected {
                    rejection: MessageAeadRejection {
                        function: Function::read(reader)?.name(),
                        code: reader.u64()?,
                    },
                    discarded_output: width(reader.u64()?)?,
                },
                _ => return Err(invalid()),
            };
        }
        if counters {
            result.accepted_input = match reader.u8()? {
                0 => None,
                1 => {
                    let low = reader.u64()? as u128;
                    let high = reader.u64()? as u128;
                    Some(low | (high << 64))
                }
                _ => return Err(invalid()),
            };
        }
        if result.output.len() > result.capacity || result.capacity > limits.bytes {
            return Err(invalid());
        }
        Ok(result)
    }
}

pub(in crate::advanced) fn write<'a>(
    writer: &mut Writer<'_>,
    limits: Limits,
    header: Header<'a>,
    count: usize,
    mut row: impl FnMut(usize) -> Result<Row<'a>>,
) -> Result<()> {
    if count > limits.messages || usize::from(header.fragment.is_some()) > limits.fragments {
        return Err(invalid());
    }
    // Tag9 preserves accepted input independently of output and declared CCM
    // length. Tags3/4 remain readable with explicitly unavailable history.
    writer.u8(9)?;
    header.write(writer)?;
    writer.u32(u32::try_from(count).map_err(|_| invalid())?)?;
    for index in 0..count {
        row(index)?.write(writer)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(in crate::advanced) struct Record<'a> {
    pub header: Header<'a>,
    bytes: &'a [u8],
    count: usize,
    limits: Limits,
    dispositions: bool,
    counters: bool,
}
impl<'a> Record<'a> {
    pub(in crate::advanced) fn from_packet(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        if bytes.len() > limits.bytes {
            return Err(invalid());
        }
        let mut reader = Reader {
            graph_observer: None,
            bytes,
            position: 0,
        };
        let (dispositions, counters) = match reader.u8()? {
            3 => (false, false),
            4 => (true, false),
            9 => (true, true),
            _ => return Err(invalid()),
        };
        let record = Self::read(&mut reader, limits, dispositions, counters)?;
        reader.finish()?;
        Ok(record)
    }
    pub(in crate::advanced) fn read(
        reader: &mut Reader<'a>,
        limits: Limits,
        dispositions: bool,
        counters: bool,
    ) -> Result<Self> {
        let header = Header::read(reader, limits)?;
        let count = reader.count(limits.messages)?;
        let start = reader.position;
        for _ in 0..count {
            Row::read(reader, limits, dispositions, counters)?;
        }
        Ok(Self {
            header,
            bytes: &reader.bytes[start..reader.position],
            count,
            limits,
            dispositions,
            counters,
        })
    }
    pub(in crate::advanced) fn len(self) -> usize {
        self.count
    }
    pub(in crate::advanced) fn iter(self) -> Rows<'a> {
        Rows {
            reader: Reader {
                graph_observer: None,
                bytes: self.bytes,
                position: 0,
            },
            remaining: self.count,
            limits: self.limits,
            dispositions: self.dispositions,
            counters: self.counters,
        }
    }
}
pub(in crate::advanced) struct Rows<'a> {
    reader: Reader<'a>,
    remaining: usize,
    limits: Limits,
    dispositions: bool,
    counters: bool,
}
impl<'a> Iterator for Rows<'a> {
    type Item = Result<Row<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let row = Row::read(
            &mut self.reader,
            self.limits,
            self.dispositions,
            self.counters,
        );
        if row.is_err() {
            self.remaining = 0;
        }
        Some(row)
    }
}
