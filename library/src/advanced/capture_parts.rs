// SPDX-License-Identifier: Apache-2.0
//! One unpublished fragment graph shared by classic and dual snapshots.
use super::continuation::InputLayout;
use crate::{
    symmetric::memory::{Buffer, Credit, UnboundBuffer},
    Error, Result,
};

pub(super) struct Storage {
    parts: Vec<UnboundBuffer>,
    destination: Vec<Buffer>,
    fragments: Vec<usize>,
    output: UnboundBuffer,
}
pub(super) struct Bound {
    pub inputs: Vec<Buffer>,
    pub layout: InputLayout,
    pub output: Buffer,
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::CheckpointCapture(
            crate::CheckpointCaptureRejection::SnapshotFragmentAllocation,
        ))
    })?;
    Ok(values)
}
impl Storage {
    pub(super) fn temporary_bytes(count: usize) -> Result<usize> {
        count
            .checked_mul(std::mem::size_of::<UnboundBuffer>())
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
            )))
    }
    pub(super) fn allocate(sizes: &[usize], fragments: &[usize], output: usize) -> Result<Self> {
        Self::allocate_lengths(sizes.iter().copied(), fragments.iter().copied(), output)
    }
    pub(super) fn allocate_lengths(
        sizes: impl ExactSizeIterator<Item = usize>,
        fragments: impl ExactSizeIterator<Item = usize>,
        output: usize,
    ) -> Result<Self> {
        Self::allocate_fallible(
            sizes.len(),
            sizes.map(Ok),
            fragments.len(),
            fragments.map(Ok),
            output,
        )
    }
    pub(super) fn allocate_fallible(
        count: usize,
        sizes: impl Iterator<Item = Result<usize>>,
        fragment_count: usize,
        fragments: impl Iterator<Item = Result<usize>>,
        output: usize,
    ) -> Result<Self> {
        let mut parts = reserve(count)?;
        for size in sizes {
            if parts.len() == count {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::SnapshotInputCountChanged,
                )));
            }
            parts.push(UnboundBuffer::allocate(size?)?);
        }
        if parts.len() != count {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotInputCountChanged,
            )));
        }
        let mut owned_fragments = reserve(fragment_count)?;
        for length in fragments {
            if owned_fragments.len() == fragment_count {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::SnapshotFragmentCountChanged,
                )));
            }
            owned_fragments.push(length?);
        }
        if owned_fragments.len() != fragment_count {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotFragmentCountChanged,
            )));
        }
        Ok(Self {
            parts,
            destination: reserve(count)?,
            fragments: owned_fragments,
            output: UnboundBuffer::allocate(output)?,
        })
    }
    pub(super) fn input_metadata_bytes(&self) -> Result<usize> {
        self.destination
            .capacity()
            .checked_mul(std::mem::size_of::<Buffer>())
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
            )))
    }
    /// Input-vector metadata belongs to the enclosing frame's metadata credit;
    /// this count covers its byte allocations and temporary shape metadata only.
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        let fragments = self
            .fragments
            .capacity()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
            )))?;
        let mut total = Self::temporary_bytes(self.parts.capacity())?
            .checked_add(fragments)
            .and_then(|n| n.checked_add(self.output.allocated()))
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
            )))?;
        for part in &self.parts {
            total = total.checked_add(part.allocated()).ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
                ),
            ))?;
        }
        Ok(total)
    }
    pub(super) fn bind(mut self, prepaid: &mut Credit) -> Result<Bound> {
        let temporary = prepaid.split(Self::temporary_bytes(self.parts.capacity())?)?;
        for part in self.parts.drain(..) {
            self.destination.push(part.bind(prepaid)?);
        }
        drop(self.parts);
        drop(temporary);
        Ok(Bound {
            inputs: self.destination,
            layout: InputLayout::from_owned_lengths(prepaid, self.fragments)?,
            output: self.output.bind(prepaid)?,
        })
    }
}
