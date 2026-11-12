// SPDX-License-Identifier: Apache-2.0
//! Aggregate initial owner and guard-free value candidates after a size reply.
use super::{State, ValueNeed};
use crate::{
    attribute_values::{
        read::{preparation as graph, ReadCall},
        storage::AttributeBytesStorage,
        AttributeBatchCalls, AttributeBytes, FlatAttributeBatch, FlatAttributeRequest,
    },
    native::frame::SessionFrame,
    symmetric::memory::{Budget, ControlledReservation, Credit},
    Error, ResourceAdmission, Result, Session,
};
use std::{mem::size_of, sync::Arc};

pub(crate) struct Prepared {
    pub(super) state: State,
    pub(super) results: FlatAttributeBatch,
    pub(super) requests: Vec<FlatAttributeRequest>,
    pub(super) calls: AttributeBatchCalls,
    pub(super) allocated: usize,
    pub(super) maximum: usize,
    _credit: Credit,
}
pub(crate) struct Plan<'a> {
    requests: &'a [FlatAttributeRequest],
    graph: graph::Plan<'a>,
    maximum: usize,
    allocated: usize,
}
pub(crate) struct Storage {
    graph: graph::Storage,
    requests: Vec<FlatAttributeRequest>,
}
fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::AttributeValues(
        crate::AttributeValuesRejection::AttributeObservationOwnerAccounting,
    ))
}
fn fixed() -> usize {
    // The registry credits its complete slot allocation, including FlatOwner.
    // NativeFrame additionally owns these two stable allocations.
    size_of::<ReadCall>() + SessionFrame::<'static, ReadCall>::allocation_bytes()
}
impl<'a> Plan<'a> {
    pub(crate) fn new(
        session: &Session,
        requests: &'a [FlatAttributeRequest],
        maximum: usize,
    ) -> Result<Self> {
        let allocated = super::super::validate_requests(session, requests, maximum)?;
        Ok(Self {
            requests,
            graph: graph::Plan::new(requests)?,
            maximum,
            allocated,
        })
    }
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        self.requests
            .len()
            .checked_mul(size_of::<FlatAttributeRequest>())
            .and_then(|bytes| bytes.checked_add(fixed()))
            .and_then(|bytes| bytes.checked_add(self.graph.requested_bytes()))
            .ok_or_else(invalid)
    }
    pub(crate) fn allocate(&self) -> Result<Storage> {
        let graph = self.graph.allocate()?;
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(self.requests.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeRequestMetadataAllocation,
                ))
            })?;
        requests.extend_from_slice(self.requests);
        Ok(Storage { graph, requests })
    }
    pub(crate) fn bind(self, storage: Storage, credit: &mut Credit) -> Result<Prepared> {
        let metadata = storage.metadata_bytes()?;
        let (results, call, second) = self.graph.bind(storage.graph, credit)?;
        Ok(Prepared {
            state: State::First { call, second },
            results,
            requests: storage.requests,
            calls: AttributeBatchCalls::None,
            allocated: self.allocated,
            maximum: self.maximum,
            _credit: credit.split(metadata)?,
        })
    }
}
impl Storage {
    fn metadata_bytes(&self) -> Result<usize> {
        self.requests
            .capacity()
            .checked_mul(size_of::<FlatAttributeRequest>())
            .and_then(|bytes| bytes.checked_add(fixed()))
            .ok_or_else(invalid)
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.metadata_bytes()?
            .checked_add(self.graph.allocated_bytes()?)
            .ok_or_else(invalid)
    }
}

pub(crate) enum ValuePreparation<T> {
    Ready(AttributeBytes),
    Redirect(T),
}
pub(crate) fn prepare_value<T>(
    need: ValueNeed,
    budget: &Arc<Budget>,
    admission: &ResourceAdmission,
    mut before: impl FnMut() -> Result<Option<T>>,
) -> Result<ValuePreparation<T>> {
    let mut required = AttributeBytes::allocation_bytes(need.length)?;
    loop {
        let mut credit = match budget.reserve_controlled_retaining(
            required,
            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
            admission,
            &mut before,
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(route) => return Ok(ValuePreparation::Redirect(route)),
        };
        let storage = AttributeBytesStorage::allocate(need.length)?;
        let actual = storage.allocated_bytes()?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        return Ok(ValuePreparation::Ready(storage.bind(&mut credit)?));
    }
}
