// SPDX-License-Identifier: Apache-2.0
//! Ordered results retain their allocation credit, including during iteration.
use super::{AttributeType, FlatAttributeObservation, FlatAttributeReadPlan};
use crate::symmetric::memory::{Budget, Credit};
use crate::{Error, Result};
use std::sync::Arc;

/// One independently selected attribute and retrieval strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatAttributeRequest {
    /// Standard attribute to read; duplicates remain distinct requests.
    pub attribute: AttributeType,
    /// Explicit size or value retrieval strategy.
    pub plan: FlatAttributeReadPlan,
}

/// One completed C_GetAttributeValue call, with no attribute contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeBatchCall {
    /// Exact native return code.
    pub code: u64,
    /// Number of descriptors actually submitted in this call.
    pub attribute_count: usize,
}

/// Native call provenance for a grouped read, including an empty request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeBatchCalls {
    /// An empty request made no native call.
    None,
    /// The first call sufficed or no queried value could be prepared.
    One(AttributeBatchCall),
    /// A first mixed call and a second value-only call completed.
    Two {
        /// Initial direct reads and size queries.
        first: AttributeBatchCall,
        /// Admitted queried values only; never repeats a direct buffer read.
        second: AttributeBatchCall,
    },
}

/// Protected results in caller order. This owner does not expose a movable Vec:
/// its metadata allocation must not outlive the corresponding resource credit.
pub struct FlatAttributeBatch {
    calls: AttributeBatchCalls,
    entries: Vec<Option<FlatAttributeObservation>>,
    _credit: Credit,
}

pub(super) struct BatchStorage {
    entries: Vec<Option<FlatAttributeObservation>>,
}
impl BatchStorage {
    pub(super) fn allocate(count: usize) -> Result<Self> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeMetadataAllocation,
            ))
        })?;
        entries.resize_with(count, || None);
        Ok(Self { entries })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        FlatAttributeBatch::metadata_bytes(self.entries.capacity())
    }
    pub(super) fn bind(self, credit: &mut Credit) -> Result<FlatAttributeBatch> {
        let credit = credit.split(self.allocated_bytes()?)?;
        Ok(FlatAttributeBatch {
            calls: AttributeBatchCalls::None,
            entries: self.entries,
            _credit: credit,
        })
    }
}
impl FlatAttributeBatch {
    pub(super) fn metadata_bytes(count: usize) -> Result<usize> {
        count
            .checked_mul(std::mem::size_of::<Option<FlatAttributeObservation>>())
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeResultMetadataAccounting,
            )))
    }
    pub(super) fn prepare(budget: &Arc<Budget>, count: usize) -> Result<Self> {
        let mut entries = reserve_entries(budget, count)?;
        entries.0.resize_with(count, || None);
        Ok(Self {
            calls: AttributeBatchCalls::None,
            entries: entries.0,
            _credit: entries.1,
        })
    }

    pub(super) fn put(&mut self, index: usize, value: FlatAttributeObservation) {
        // Each request is assigned once, either after pass one or pass two.
        assert!(
            self.entries[index].is_none(),
            "attribute result already assigned"
        );
        self.entries[index] = Some(value);
    }

    pub(super) fn finish(mut self, calls: AttributeBatchCalls) -> Result<Self> {
        if self.entries.iter().any(Option::is_none) {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeBatchHasUnfinishedResults,
            )));
        }
        self.calls = calls;
        Ok(self)
    }

    /// Exact return code and descriptor count for each completed native call.
    pub fn calls(&self) -> AttributeBatchCalls {
        self.calls
    }

    /// Number of results, including unavailable and allocation-limited entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the caller supplied no requests.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow observations without copying their protected value storage.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &FlatAttributeObservation> {
        self.entries.iter().map(|entry| {
            entry
                .as_ref()
                .expect("only completed attribute batches are published")
        })
    }
}

/// Consuming iterator retaining metadata credit until its allocation is freed.
pub struct FlatAttributeIntoIter {
    entries: std::vec::IntoIter<Option<FlatAttributeObservation>>,
    _credit: Credit,
}
impl Iterator for FlatAttributeIntoIter {
    type Item = FlatAttributeObservation;
    fn next(&mut self) -> Option<Self::Item> {
        self.entries
            .next()
            .map(|entry| entry.expect("only completed attribute batches are published"))
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}
impl ExactSizeIterator for FlatAttributeIntoIter {}
impl IntoIterator for FlatAttributeBatch {
    type Item = FlatAttributeObservation;
    type IntoIter = FlatAttributeIntoIter;
    fn into_iter(self) -> Self::IntoIter {
        FlatAttributeIntoIter {
            entries: self.entries.into_iter(),
            _credit: self._credit,
        }
    }
}

/// Reserve before allocating and account for any extra capacity immediately.
/// Keep the tuple intact across fallible steps: tuple fields drop in order.
/// The final owner must likewise declare its Vec field before its Credit field.
pub(super) fn reserve_entries<T>(budget: &Arc<Budget>, count: usize) -> Result<(Vec<T>, Credit)> {
    let width = std::mem::size_of::<T>();
    let bytes = count.checked_mul(width).ok_or(Error::Rejected(
        crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataSize,
        ),
    ))?;
    let mut credit = budget.reserve(bytes)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataAllocation,
        ))
    })?;
    let additional = (entries.capacity() - count)
        .checked_mul(width)
        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeMetadataCapacity,
        )))?;
    credit.cover_allocated(additional)?;
    Ok((entries, credit))
}
