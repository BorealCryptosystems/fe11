// SPDX-License-Identifier: Apache-2.0
//! Non-secret snapshot shapes. Allocate first, describe under the source guard,
//! then allocate destination buffers after releasing that guard.
use super::continuation::InputLayout;
use crate::{
    symmetric::memory::{Buffer, Credit},
    Error, Result,
};

#[derive(Clone, Copy, Default)]
struct Row {
    start: usize,
    inputs: usize,
    fragments: usize,
    output: usize,
}
pub(super) struct Layouts {
    rows: Vec<Row>,
    lengths: Vec<usize>,
    next_row: usize,
    next_length: usize,
    _credit: Credit,
}
/// Unbound shape vectors. Their actual capacities are admitted together with
/// the containing snapshot before a guarded source can fill them.
pub(super) struct Storage {
    rows: Vec<Row>,
    lengths: Vec<usize>,
}
impl Storage {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        Layouts::allocation_bytes(self.rows.capacity(), self.lengths.capacity())
    }
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<Layouts> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(Layouts {
            rows: self.rows,
            lengths: self.lengths,
            next_row: 0,
            next_length: 0,
            _credit: credit,
        })
    }
}
impl Layouts {
    pub(super) fn allocation_bytes(rows: usize, lengths: usize) -> Result<usize> {
        rows.checked_mul(std::mem::size_of::<Row>())
            .and_then(|bytes| {
                lengths
                    .checked_mul(std::mem::size_of::<usize>())
                    .and_then(|lengths| bytes.checked_add(lengths))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotShapeAccounting,
            )))
    }
    pub(super) fn allocate(row_count: usize, length_count: usize) -> Result<Storage> {
        Self::allocation_bytes(row_count, length_count)?;
        let mut rows = Vec::new();
        let mut lengths = Vec::new();
        rows.try_reserve_exact(row_count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotShapeAllocation,
            ))
        })?;
        lengths.try_reserve_exact(length_count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotShapeAllocation,
            ))
        })?;
        rows.resize(row_count, Row::default());
        lengths.resize(length_count, 0);
        Ok(Storage { rows, lengths })
    }

    /// Filling a preallocated row copies only lengths. A candidate is never
    /// interpreted until all rows and all slots have been filled exactly once.
    pub(super) fn push(
        &mut self,
        inputs: &[Buffer],
        layout: &InputLayout,
        output: usize,
    ) -> Result<()> {
        self.push_lengths(
            inputs.iter().map(Buffer::capacity),
            layout.lengths().iter().copied(),
            output,
        )
    }
    pub(super) fn push_lengths(
        &mut self,
        inputs: impl ExactSizeIterator<Item = usize>,
        fragments: impl ExactSizeIterator<Item = usize>,
        output: usize,
    ) -> Result<()> {
        let input_count = inputs.len();
        let fragment_count = fragments.len();
        let row = self.rows.get_mut(self.next_row).ok_or(Error::Rejected(
            crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotRowCountChanged,
            ),
        ))?;
        let count = input_count
            .checked_add(fragment_count)
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotShapeAccounting,
            )))?;
        let end = self.next_length.checked_add(count).ok_or(Error::Rejected(
            crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotShapeAccounting,
            ),
        ))?;
        let target = self
            .lengths
            .get_mut(self.next_length..end)
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotFragmentCountChanged,
            )))?;
        for (target, source) in target[..input_count].iter_mut().zip(inputs) {
            *target = source;
        }
        for (target, source) in target[input_count..].iter_mut().zip(fragments) {
            *target = source;
        }
        *row = Row {
            start: self.next_length,
            inputs: input_count,
            fragments: fragment_count,
            output,
        };
        self.next_row += 1;
        self.next_length = end;
        Ok(())
    }
    pub(super) fn complete(&self) -> Result<()> {
        if self.next_row != self.rows.len() || self.next_length != self.lengths.len() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotShapeIncomplete,
            )));
        }
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }
    pub(super) fn row(&self, index: usize) -> Result<(&[usize], &[usize], usize)> {
        self.complete()?;
        let row = self.rows.get(index).ok_or(Error::Rejected(
            crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::SnapshotRowAbsent,
            ),
        ))?;
        // push validated the range before recording the row; these indices
        // describe owned metadata, never provider-controlled pointers.
        let split = row.start + row.inputs;
        Ok((
            &self.lengths[row.start..split],
            &self.lengths[split..split + row.fragments],
            row.output,
        ))
    }
}


