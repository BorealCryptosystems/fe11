// SPDX-License-Identifier: Apache-2.0
//! Complete native-order collection shared by synchronous and advanced searches.
use super::*;

use crate::symmetric::memory::Credit;

pub(super) mod owned;
pub(crate) use owned::resident::{SearchOwner, SearchWithdrawal, Storage as SearchStorage};
mod preparation;
mod recovery;
pub(crate) use preparation::{SearchCandidate, SearchNeed, SearchPreparation};
pub(crate) use recovery::finish_failed_search;

pub(crate) enum CollectionError {
    Malformed,
    Local(Error),
}

// Credit covers vector capacity, excluding allocator bookkeeping. On allocation
// failure the tentative reservation is returned. If the allocator grants excess
// capacity that cannot be credited, the caller must release the rejected vector
// before yielding or making a native call.
pub(crate) fn reserve_handles(
    values: &mut Vec<CK_OBJECT_HANDLE>,
    additional: usize,
    mut credit: Option<&mut Credit>,
) -> Result<()> {
    let required = values.len().checked_add(additional).ok_or(Error::Rejected(
        crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::ObjectSearchCountOverflow,
        ),
    ))?;
    let expected = values.capacity().max(required);
    let growth = expected - values.capacity();
    let width = std::mem::size_of::<CK_OBJECT_HANDLE>();
    let bytes =
        growth
            .checked_mul(width)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchCapacityOverflow,
            )))?;
    if let Some(credit) = credit.as_deref_mut() {
        credit.extend(bytes)?;
    }
    if values.try_reserve_exact(additional).is_err() {
        if let Some(credit) = credit.as_deref_mut() {
            credit.release(bytes);
        }
        return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
            crate::ObjectSearchRejection::SearchResultAllocation,
        )));
    }
    if let Some(credit) = credit {
        let extra = (values.capacity() - expected)
            .checked_mul(width)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchCapacityOverflow,
            )))?;
        credit.cover_allocated(extra)?;
    }
    Ok(())
}

pub(crate) struct SearchCollection {
    plan: SearchPlan,
    handles: Vec<CK_OBJECT_HANDLE>,
    // Scratch exists only during terminal validation. Field order frees both
    // vectors before their dedicated credit, including unwinding.
    index: Vec<CK_OBJECT_HANDLE>,
    credit: Option<Credit>,
}
impl std::ops::Deref for SearchCollection {
    type Target = [CK_OBJECT_HANDLE];
    fn deref(&self) -> &Self::Target {
        &self.handles
    }
}
impl SearchCollection {
    /// Empty collection metadata is part of its enclosing admitted owner.
    /// Later native result sizes use the existing SearchNeed preparation path.
    pub(crate) fn from_prepaid(plan: SearchPlan, prepaid: &mut Credit) -> Result<Self> {
        Ok(Self::from_credit(plan, prepaid.split(0)?))
    }

    /// The caller supplies the zero-byte share of its grouped preparation.
    pub(super) fn from_credit(plan: SearchPlan, credit: Credit) -> Self {
        Self {
            plan,
            handles: Vec::new(),
            index: Vec::new(),
            credit: Some(credit),
        }
    }

    pub(crate) fn reset(&mut self, plan: SearchPlan) {
        self.clear();
        self.plan = plan;
    }
    pub(crate) fn clear(&mut self) {
        self.handles = Vec::new();
        self.index = Vec::new();
        if let Some(credit) = &mut self.credit {
            credit.release_all();
        }
    }
    pub(crate) fn handles(&self) -> &[CK_OBJECT_HANDLE] {
        &self.handles
    }

    // Used only after an outcome already prevents publication. Sorting these
    // buffers needs no allocation and preserves malformed-output precedence.
    fn refuse(&mut self, batch: &mut [CK_OBJECT_HANDLE], cause: Error) -> CollectionError {
        self.handles.sort_unstable();
        batch.sort_unstable();
        let malformed = self
            .handles
            .iter()
            .chain(batch.iter())
            .any(|h| *h == CK_INVALID_HANDLE)
            || self.handles.windows(2).any(|w| w[0] == w[1])
            || batch.windows(2).any(|w| w[0] == w[1])
            || batch.iter().any(|h| self.handles.binary_search(h).is_ok());
        self.clear();
        if malformed {
            CollectionError::Malformed
        } else {
            CollectionError::Local(cause)
        }
    }
    fn validate_complete(&mut self) -> std::result::Result<(), CollectionError> {
        if let Err(cause) =
            reserve_handles(&mut self.index, self.handles.len(), self.credit.as_mut())
        {
            return Err(self.refuse(&mut [], cause));
        }
        self.index.extend_from_slice(&self.handles);
        self.index.sort_unstable();
        if self.index.windows(2).any(|w| w[0] == w[1]) {
            self.clear();
            return Err(CollectionError::Malformed);
        }
        let bytes = self.index.capacity() * std::mem::size_of::<CK_OBJECT_HANDLE>();
        self.index = Vec::new();
        if let Some(credit) = &mut self.credit {
            credit.release(bytes);
        }
        Ok(())
    }
    pub(crate) fn append(
        &mut self,
        batch: &mut [CK_OBJECT_HANDLE],
    ) -> std::result::Result<(), CollectionError> {
        if batch.contains(&CK_INVALID_HANDLE) {
            self.clear();
            return Err(CollectionError::Malformed);
        }
        if batch.is_empty() {
            return self.validate_complete();
        }
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
        if total > self.handles.capacity() {
            // Amortized growth is an allocation strategy, not an extra policy
            // requirement: if spare capacity cannot be reserved, try the exact
            // required size while the previous allocation is still intact.
            let old_capacity = self.handles.capacity();
            let target = old_capacity
                .saturating_mul(2)
                .max(total)
                .min(self.plan.maximum_objects.unwrap_or(usize::MAX));
            let additional = target - self.handles.len();
            if let Err(cause) = reserve_handles(&mut self.handles, additional, self.credit.as_mut())
            {
                if self.handles.capacity() != old_capacity || target == total {
                    return Err(self.refuse(batch, cause));
                }
                if let Err(cause) =
                    reserve_handles(&mut self.handles, batch.len(), self.credit.as_mut())
                {
                    return Err(self.refuse(batch, cause));
                }
            }
        }
        self.handles.extend_from_slice(batch);
        Ok(())
    }
}
