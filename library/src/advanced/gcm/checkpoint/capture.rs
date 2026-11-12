// SPDX-License-Identifier: Apache-2.0
//! Private local snapshot packet. Source guards cover only sizing and copying;
//! allocation, pointer binding and erasure occur outside those guards.
use super::super::{storage_sum, AeadMessageOperation};
use super::{reconstruction, RecordPlan};
use crate::advanced::record::aead_messages as wire;
use crate::advanced::{keys::KeyLease, record};
use crate::module::SessionEntry;
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{Error, Result};

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::AeadMessages(
        crate::AeadMessagesRejection::AeadStreamSnapshotShapeChanged,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    packet: usize,
    reconstruction: usize,
    rows: usize,
}
impl Shape {
    fn limits(self) -> record::Limits {
        // These are representation bounds, not a new application policy.
        record::Limits {
            bytes: isize::MAX as usize,
            messages: self.rows,
            fragments: 1,
        }
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> Result<usize> {
        storage_sum(&[self.packet, self.reconstruction])
    }
    pub(in crate::advanced) fn allocate_packet(self) -> Result<UnboundBuffer> {
        UnboundBuffer::allocate(self.packet)
    }
    pub(in crate::advanced) fn packet_overhead(self, storage: &UnboundBuffer) -> Result<usize> {
        storage
            .allocated()
            .checked_sub(self.packet)
            .ok_or_else(invalid)
    }
    pub(in crate::advanced) fn bind_packet(
        self,
        storage: UnboundBuffer,
        credit: &mut Credit,
    ) -> Result<Packet> {
        let allocated = storage.allocated();
        Ok(Packet {
            shape: self,
            bytes: storage.bind(credit)?,
            allocated,
            source: None,
        })
    }
}
pub(in crate::advanced) struct Packet {
    shape: Shape,
    bytes: Buffer,
    allocated: usize,
    source: Option<(record::Descriptor, KeyLease)>,
}
pub(in crate::advanced) enum Materialized {
    Ready(AeadMessageOperation),
    Retry(usize),
}

impl AeadMessageOperation {
    pub(in crate::advanced) fn caller_fed(&self) -> bool {
        self.input.is_some()
    }

    pub(in crate::advanced) fn stream_snapshot_shape(&self, entry: &SessionEntry) -> Result<Shape> {
        self.key.check(entry)?;
        let header = self.stream_header()?;
        let limits = record::Limits {
            bytes: isize::MAX as usize,
            messages: self.frames.len(),
            fragments: 1,
        };
        let packet = wire::packet_size(limits, header, self.frames.len(), |i| self.stream_row(i))?;
        let reconstruction = reconstruction::allocation_from_rows(
            self.kind,
            self.decrypt,
            header,
            self.frames.len(),
            (0..self.frames.len()).map(|i| self.stream_row(i)),
        )?;
        Ok(Shape {
            packet,
            reconstruction,
            rows: self.frames.len(),
        })
    }
}

impl Packet {
    pub(in crate::advanced) fn copy_from(
        &mut self,
        source: &AeadMessageOperation,
        entry: &SessionEntry,
    ) -> Result<()> {
        if self.source.is_some() || source.stream_snapshot_shape(entry)? != self.shape {
            return Err(invalid());
        }
        wire::write_packet(
            self.bytes.as_mut(),
            self.shape.limits(),
            source.stream_header()?,
            source.frames.len(),
            |i| source.stream_row(i),
        )?;
        self.source = Some((source.checkpoint_header()?.0, source.key.duplicate()?));
        Ok(())
    }

    pub(in crate::advanced) fn materialize(
        mut self,
        credit: &mut Credit,
        admitted: usize,
        ceilings: crate::CryptoLimits,
    ) -> Result<Materialized> {
        let (descriptor, key) = self.source.as_ref().ok_or_else(invalid)?;
        let record = wire::Record::from_packet(self.bytes.as_slice(), self.shape.limits())?;
        record.validate_sections(
            *descriptor,
            &record::KeyBindings {
                cipher: Some(key.checkpoint_key(record::KeyRole::Cipher)?),
                authentication: None,
            },
            None,
            self.shape.limits(),
        )?;
        let plan = RecordPlan::new(*descriptor, record, ceilings, false)?;
        let storage = plan.allocate()?;
        let actual = storage_sum(&[self.allocated, storage.allocated_bytes()?])?;
        if actual > admitted {
            return Ok(Materialized::Retry(actual));
        }
        let prepared = storage.bind(credit)?;
        let (_, key) = self.source.take().ok_or_else(invalid)?;
        Ok(Materialized::Ready(prepared.bind(key)))
    }
}
