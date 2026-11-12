// SPDX-License-Identifier: Apache-2.0
//! Empty replacement storage for accepting an already returned search batch.
//! Native results stay with their operation while admission waits outside guards.
use super::{CollectionError, SearchCollection};
use crate::{
    symmetric::memory::{Budget, ControlledReservation, Credit},
    Error, ResourceAdmission, Result,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Handles,
    Index,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchNeed {
    target: Target,
    capacity: usize,
    retained: usize,
}

pub(crate) struct SearchCandidate {
    need: SearchNeed,
    storage: Vec<CK_OBJECT_HANDLE>,
    credit: Credit,
}
pub(crate) enum SearchPreparation<T> {
    Ready(SearchCandidate),
    Redirect(T),
}
impl SearchCandidate {
    pub(crate) fn need(&self) -> SearchNeed {
        self.need
    }
    pub(crate) fn prepare<T>(
        need: SearchNeed,
        budget: &Arc<Budget>,
        admission: &ResourceAdmission,
        before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<SearchPreparation<T>> {
        Self::prepare_retaining(need, budget, 0, admission, before)
    }

    pub(crate) fn prepare_retaining<T>(
        need: SearchNeed,
        budget: &Arc<Budget>,
        retained_bytes: usize,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<SearchPreparation<T>> {
        let width = std::mem::size_of::<CK_OBJECT_HANDLE>();
        let mut bytes = need.capacity.checked_mul(width).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchCapacityOverflow,
            ),
        ))?;
        loop {
            let mut credit = match budget.reserve_controlled_retaining(
                bytes,
                crate::session::lifecycle_diagnostics::Store::including(retained_bytes)?,
                admission,
                &mut before,
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(route) => {
                    return Ok(SearchPreparation::Redirect(route))
                }
            };
            let mut storage = Vec::new();
            storage.try_reserve_exact(need.capacity).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchResultAllocation,
                ))
            })?;
            let actual = storage
                .capacity()
                .checked_mul(width)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchCapacityOverflow,
                )))?;
            if actual > bytes {
                drop(storage);
                drop(credit);
                bytes = actual;
                continue;
            }
            // A retry after allocator excess may return a smaller capacity.
            // The accepted candidate owns only its actual allocation charge.
            credit.release(bytes - actual);
            return Ok(SearchPreparation::Ready(Self {
                need,
                storage,
                credit,
            }));
        }
    }
}

impl SearchCollection {
    /// Check returned data and policy before reporting a local storage need.
    /// Each growth prepares the exact required allocation while the previous
    /// prefix is still owned; attach then copies that prefix. Many small batches
    /// can therefore incur quadratic copying. This path does not use append's
    /// amortized spare capacity: keeping that surplus could prevent admission of
    /// the terminal index or another owner under the caller's shared budget.
    /// Error precedence remains the same as append, including malformed output
    /// discovered when the caller's maximum object count has been exceeded.
    pub(crate) fn preparation_need(
        &mut self,
        batch: &mut [CK_OBJECT_HANDLE],
    ) -> std::result::Result<Option<SearchNeed>, CollectionError> {
        if batch.contains(&CK_INVALID_HANDLE) {
            self.clear();
            return Err(CollectionError::Malformed);
        }
        let (target, capacity, available) = if batch.is_empty() {
            (Target::Index, self.handles.len(), self.index.capacity())
        } else {
            let Some(total) = self.handles.len().checked_add(batch.len()) else {
                return Err(self.refuse(
                    batch,
                    Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::ObjectSearchCountOverflow,
                    )),
                ));
            };
            if self
                .plan
                .maximum_objects
                .is_some_and(|maximum| total > maximum)
            {
                return Err(self.refuse(
                    batch,
                    Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::ObjectSearchLimitExceeded,
                    )),
                ));
            }
            (Target::Handles, total, self.handles.capacity())
        };
        Ok((capacity > available).then_some(SearchNeed {
            target,
            capacity,
            retained: self.handles.len(),
        }))
    }

    pub(crate) fn attach(&mut self, mut prepared: SearchCandidate) -> Result<()> {
        if prepared.need.retained != self.handles.len()
            || prepared.storage.capacity() < prepared.need.capacity
            || !prepared.storage.is_empty()
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::SearchPreparationChanged,
            )));
        }
        let current = match prepared.need.target {
            Target::Handles => &mut self.handles,
            Target::Index => &mut self.index,
        };
        if current.capacity() >= prepared.need.capacity {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::SearchPreparationChanged,
            )));
        }
        // Credit is transferred before replacing the old allocation. Neither
        // transition waits. The source remains in the operation until this point.
        let credit =
            self.credit
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchPreparationWithoutByteOwner,
                )))?;
        credit.merge(prepared.credit)?;
        prepared.storage.extend_from_slice(current);
        let old = std::mem::replace(current, prepared.storage);
        let old_bytes = old
            .capacity()
            .checked_mul(std::mem::size_of::<CK_OBJECT_HANDLE>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchCapacityOverflow,
            )))?;
        drop(old);
        credit.release(old_bytes);
        Ok(())
    }

    /// The preparation frontier has already provided both possible allocations.
    /// append's existing validation may now run without acquiring byte credit.
    pub(crate) fn append_prepared(
        &mut self,
        batch: &mut [CK_OBJECT_HANDLE],
    ) -> std::result::Result<(), CollectionError> {
        if self.preparation_need(batch)?.is_some() {
            return Err(CollectionError::Local(Error::Rejected(
                crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchPreparationAbsent,
                ),
            )));
        }
        self.append(batch)
    }
}
