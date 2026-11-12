// SPDX-License-Identifier: Apache-2.0
//! Unbound coordination vectors, charged by their measured allocated capacity.
use super::{Activity, Credit, Destination, PreparedRetention, Reservation, WritePermit};
use crate::{Error, Result};
use std::sync::Arc;

pub(super) struct RetentionStorage {
    keys: Vec<Destination>,
    activities: Vec<Arc<Activity>>,
    writers: Vec<WritePermit>,
}

fn bytes(keys: usize, activities: usize, writers: usize) -> Result<usize> {
    keys.checked_mul(std::mem::size_of::<Destination>())
        .and_then(|n| {
            activities
                .checked_mul(std::mem::size_of::<Arc<Activity>>())
                .and_then(|v| n.checked_add(v))
        })
        .and_then(|n| {
            writers
                .checked_mul(std::mem::size_of::<WritePermit>())
                .and_then(|v| n.checked_add(v))
        })
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
            crate::ObjectCleanupRejection::CoordinationVectorStorageAccounting,
        )))
}

/// One key and activity per destination; no live reservation is required to size
/// the final retention vectors. Allocator rounding is checked after allocation.
pub(super) fn retention_requested(count: usize) -> Result<usize> {
    bytes(count, count, count)
}

impl Reservation {
    pub(super) fn retention_bytes(&self) -> Result<usize> {
        bytes(
            self.keys.len(),
            self.activities.len(),
            self.activities.len(),
        )
    }

    pub(super) fn allocate_retention(&self) -> Result<RetentionStorage> {
        let mut keys = Vec::new();
        keys.try_reserve_exact(self.keys.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::OperationDestinationAllocation,
            ))
        })?;
        let mut activities = Vec::new();
        activities
            .try_reserve_exact(self.activities.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::OperationActivityAllocation,
                ))
            })?;
        let mut writers = Vec::new();
        writers
            .try_reserve_exact(self.activities.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::OperationActivityAllocation,
                ))
            })?;
        keys.extend(self.keys.iter().cloned());
        activities.extend(self.activities.iter().cloned());
        Ok(RetentionStorage {
            keys,
            activities,
            writers,
        })
    }
}

impl RetentionStorage {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        bytes(
            self.keys.capacity(),
            self.activities.capacity(),
            self.writers.capacity(),
        )
    }

    pub(super) fn bind(self, credit: &mut Credit) -> Result<PreparedRetention> {
        let metadata = credit.split(self.allocated_bytes()?)?;
        Ok(PreparedRetention {
            keys: self.keys,
            activities: self.activities,
            writers: self.writers,
            metadata,
        })
    }
}
