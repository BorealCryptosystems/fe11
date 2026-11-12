// SPDX-License-Identifier: Apache-2.0
//! Copy an extension digest under possession, then relocate its graph outside it.
use super::{
    extension::Parameters, snapshot::Storage, DigestFrame, DigestOperation, DigestSelection, Step,
};
use crate::advanced::{input::InputState, NativeActivity};
use crate::mechanism_extension::graph::{recipe, snapshot::SnapshotRecipe, GraphStorage};
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{Error, MechanismExtension, Result};

fn overflow() -> Error {
    Error::Rejected(crate::RejectionReason::DigestContinuation(
        crate::DigestContinuationRejection::DigestExtensionSnapshotAccounting,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    selection: DigestSelection,
    graph_bytes: usize,
    graph_storage: usize,
    count: usize,
    input_bytes: usize,
    output_capacity: usize,
    output_length: usize,
}
struct Metadata {
    contract: MechanismExtension,
    input: InputState,
    step: Step,
    activity: NativeActivity,
    validation_requested: bool,
    length: fe11_sys::CK_ULONG,
}
pub(in crate::advanced) struct Packet {
    shape: Shape,
    bytes: Buffer,
    metadata: Option<Metadata>,
}
pub(in crate::advanced) enum Materialized {
    Ready(DigestOperation),
    Retry(usize),
}
impl DigestOperation {
    pub(in crate::advanced) fn extension_snapshot_shape(&self) -> Result<Shape> {
        let extension = self.frame.extension.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestExtensionParametersAbsent,
            ),
        ))?;
        if !matches!(
            self.step,
            Step::Single | Step::Update(_) | Step::Final | Step::OutputRequired { .. }
        ) || self.activity.pending()
            || self.activity.inactive()
            || !self.frame.unchanged()
        {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestExtensionNotCapturable,
            )));
        }
        Ok(Shape {
            selection: self.frame.selection,
            graph_bytes: extension.graph.snapshot_bytes()?,
            graph_storage: extension.graph.snapshot_allocation_bytes()?,
            count: self.frame.parts.len(),
            input_bytes: self.frame.parts.iter().try_fold(0usize, |n, part| {
                n.checked_add(part.as_slice().len()).ok_or_else(overflow)
            })?,
            output_capacity: self.frame.output.capacity(),
            output_length: self.frame.output.as_slice().len(),
        })
    }
}
impl Shape {
    fn packet_bytes(self) -> Result<usize> {
        self.count
            .checked_mul(8)
            .and_then(|n| n.checked_add(self.input_bytes))
            .and_then(|n| n.checked_add(self.graph_bytes))
            .and_then(|n| n.checked_add(self.output_length))
            .ok_or_else(overflow)
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> Result<usize> {
        DigestFrame::metadata_bytes_for_count(self.count, self.selection)?
            .checked_add(Storage::temporary_bytes(self.count)?)
            .and_then(|n| n.checked_add(self.graph_storage))
            .and_then(|n| n.checked_add(self.input_bytes))
            .and_then(|n| n.checked_add(self.output_capacity))
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
    pub(in crate::advanced) fn copy_from(&mut self, source: &DigestOperation) -> Result<()> {
        if source.extension_snapshot_shape()? != self.shape {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestExtensionSnapshotChanged,
            )));
        }
        let extension = source
            .frame
            .extension
            .as_ref()
            .expect("checked digest graph");
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
        extension.graph.write_snapshot(&mut write)?;
        for input in &source.frame.parts {
            write(&(input.as_slice().len() as u64).to_le_bytes())?;
            write(input.as_slice())?;
        }
        write(source.frame.output.as_slice())?;
        self.bytes.set_length(offset)?;
        self.metadata = Some(Metadata {
            contract: extension.contract.clone(),
            input: source.input,
            step: source.step,
            activity: source.activity,
            validation_requested: source.validation_requested,
            length: *source.frame.length,
        });
        Ok(())
    }
    /// The packet has no native pointers. All allocations and relocations here
    /// occur after releasing source guards; the caller checks its revision again.
    pub(in crate::advanced) fn materialize(
        mut self,
        prepaid: &mut Credit,
        admitted: usize,
    ) -> Result<Materialized> {
        let recipe = SnapshotRecipe::decode(&self.bytes.as_slice()[..self.shape.graph_bytes])?;
        let graph = GraphStorage::allocate_input(recipe::Input::Generated(&recipe))?;
        let encoded = &self.bytes.as_slice()[self.shape.graph_bytes..];
        let mut parts = Parts {
            bytes: encoded,
            remaining: self.shape.count,
        };
        let storage = Storage::allocate_with_output(
            self.shape.selection,
            self.shape.count,
            parts.by_ref().map(|part| part.map(<[u8]>::len)),
            None,
            self.shape.output_capacity,
        )?;
        if parts.bytes.len() != self.shape.output_length {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestExtensionSnapshotTrailingBytes,
            )));
        }
        let actual = graph
            .allocated_bytes()?
            .checked_add(storage.allocated_bytes()?)
            .and_then(|n| n.checked_add(self.bytes.capacity()))
            .ok_or_else(overflow)?;
        if actual > admitted {
            return Ok(Materialized::Retry(actual));
        }
        prepaid.release(admitted - actual);
        let metadata = self.metadata.take().ok_or(Error::Rejected(
            crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::UncopiedDigestSnapshot,
            ),
        ))?;
        let mut frame = storage.bind(prepaid)?;
        let mut parameters = Parameters::new(metadata.contract, graph.bind(prepaid)?);
        parameters.attach(&mut frame.mechanism);
        frame.extension = Some(parameters);
        let mut parts = Parts {
            bytes: encoded,
            remaining: self.shape.count,
        };
        for destination in &mut frame.parts {
            let source = parts.next().ok_or_else(overflow)??;
            if source.len() != destination.as_slice().len() {
                return Err(overflow());
            }
            destination.as_mut().copy_from_slice(source);
        }
        frame
            .output
            .as_mut()
            .get_mut(..parts.bytes.len())
            .ok_or_else(overflow)?
            .copy_from_slice(parts.bytes);
        frame.output.set_length(parts.bytes.len())?;
        *frame.length = metadata.length;
        Ok(Materialized::Ready(DigestOperation {
            observer: crate::advanced::digest::Observer::Ticket,
            frame,
            input: metadata.input,
            step: metadata.step,
            activity: metadata.activity,
            validation_requested: metadata.validation_requested,
        }))
    }
}

/// Borrowed private packet traversal: no vector of fragment references is needed.
struct Parts<'a> {
    bytes: &'a [u8],
    remaining: usize,
}
impl<'a> Iterator for Parts<'a> {
    type Item = Result<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some((|| {
            let length = self.bytes.get(..8).ok_or_else(overflow)?;
            let length = usize::try_from(u64::from_le_bytes(
                length.try_into().map_err(|_| overflow())?,
            ))
            .map_err(|_| overflow())?;
            let end = 8usize.checked_add(length).ok_or_else(overflow)?;
            let part = self.bytes.get(8..end).ok_or_else(overflow)?;
            self.bytes = self.bytes.get(end..).ok_or_else(overflow)?;
            Ok(part)
        })())
    }
}
