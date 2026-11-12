// SPDX-License-Identifier: Apache-2.0
//! Complete empty first/second-call graph, measured before binding any value.
use super::{Phase, ReadCall, Slot};
use crate::{
    attribute_values::{
        batch::BatchStorage, storage::AttributeBytesStorage, AttributeBytes, FlatAttributeBatch,
        FlatAttributeReadPlan, FlatAttributeRequest,
    },
    symmetric::memory::Credit,
    Error, Result,
};
use fe11_sys::CK_ATTRIBUTE;
use std::mem::size_of;

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::AttributeValues(
        crate::AttributeValuesRejection::AttributeInitialAllocationAccounting,
    ))
}
fn add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or_else(invalid)
}
fn capacity<T>(values: &Vec<T>) -> Result<usize> {
    values
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or_else(invalid)
}
fn entries<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataAllocation,
        ))
    })?;
    Ok(values)
}
struct CallStorage {
    slots: Vec<Slot>,
    descriptors: Vec<CK_ATTRIBUTE>,
}
impl CallStorage {
    fn allocate(count: usize) -> Result<Self> {
        Ok(Self {
            slots: entries(count)?,
            descriptors: entries(count)?,
        })
    }
    fn allocated_bytes(&self) -> Result<usize> {
        add(capacity(&self.slots)?, capacity(&self.descriptors)?)
    }
    fn bind(self, credit: &mut Credit) -> Result<ReadCall> {
        let slots_credit = credit.split(capacity(&self.slots)?)?;
        let descriptors_credit = credit.split(capacity(&self.descriptors)?)?;
        Ok(ReadCall {
            slots: self.slots,
            descriptors: self.descriptors,
            _slots_credit: slots_credit,
            _descriptors_credit: descriptors_credit,
        })
    }
}

pub(super) struct Plan<'a> {
    requests: &'a [FlatAttributeRequest],
    values: usize,
    direct: usize,
    requested: usize,
}
pub(super) struct Storage {
    results: BatchStorage,
    first: CallStorage,
    second: CallStorage,
    buffers: Vec<AttributeBytesStorage>,
}
impl<'a> Plan<'a> {
    pub(super) fn new(requests: &'a [FlatAttributeRequest]) -> Result<Self> {
        let values = requests
            .iter()
            .filter(|request| matches!(request.plan, FlatAttributeReadPlan::Value { .. }))
            .count();
        let direct = requests
            .iter()
            .filter(|request| matches!(request.plan, FlatAttributeReadPlan::Buffer { .. }))
            .count();
        let transient = direct
            .checked_mul(size_of::<AttributeBytesStorage>())
            .ok_or_else(invalid)?;
        let mut requested = add(
            FlatAttributeBatch::metadata_bytes(requests.len())?,
            ReadCall::metadata_bytes(requests.len())?,
        )?;
        requested = add(requested, ReadCall::metadata_bytes(values)?)?;
        requested = add(requested, transient)?;
        for request in requests {
            if let FlatAttributeReadPlan::Buffer { capacity } = request.plan {
                requested = add(requested, AttributeBytes::allocation_bytes(capacity)?)?;
            }
        }
        Ok(Self {
            requests,
            values,
            direct,
            requested,
        })
    }
    pub(super) fn requested_bytes(&self) -> usize {
        self.requested
    }
    pub(super) fn allocate(&self) -> Result<Storage> {
        let results = BatchStorage::allocate(self.requests.len())?;
        let first = CallStorage::allocate(self.requests.len())?;
        let second = CallStorage::allocate(self.values)?;
        let mut buffers = entries(self.direct)?;
        for request in self.requests {
            if let FlatAttributeReadPlan::Buffer { capacity } = request.plan {
                buffers.push(AttributeBytesStorage::allocate(capacity)?);
            }
        }
        Ok(Storage {
            results,
            first,
            second,
            buffers,
        })
    }
    pub(super) fn bind(
        self,
        storage: Storage,
        credit: &mut Credit,
    ) -> Result<(FlatAttributeBatch, ReadCall, ReadCall)> {
        let transient = capacity(&storage.buffers)?;
        let results = storage.results.bind(credit)?;
        let mut first = storage.first.bind(credit)?;
        let second = storage.second.bind(credit)?;
        let mut buffers = storage.buffers.into_iter();
        for (index, request) in self.requests.iter().enumerate() {
            let phase = if matches!(request.plan, FlatAttributeReadPlan::Buffer { .. }) {
                Phase::Value(buffers.next().ok_or_else(invalid)?.bind(credit)?)
            } else {
                Phase::Size
            };
            first.push(index, request.attribute, phase)?;
        }
        drop(buffers);
        credit.release(transient);
        Ok((results, first, second))
    }
}
impl Storage {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        let mut actual = add(
            self.results.allocated_bytes()?,
            self.first.allocated_bytes()?,
        )?;
        actual = add(actual, self.second.allocated_bytes()?)?;
        actual = add(actual, capacity(&self.buffers)?)?;
        for buffer in &self.buffers {
            actual = add(actual, buffer.allocated_bytes()?)?;
        }
        Ok(actual)
    }
}
