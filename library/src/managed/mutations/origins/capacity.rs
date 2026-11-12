// SPDX-License-Identifier: Apache-2.0
//! Reserve publication slots before native creation, independently of its effect.
//!
//! A live reservation contributes to both catalogue capacities. Other insertions
//! preserve that spare capacity. Consuming a slot publishes an actual handle;
//! dropping unused slots releases capacity accounting without deleting objects.
use super::super::{Catalog, Inner};
use crate::{Error, Result};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Weak,
};

pub(super) struct PublicationSlots {
    inner: Weak<Inner>,
    remaining: AtomicUsize,
}

impl PublicationSlots {
    pub(super) fn new(inner: &Arc<Inner>, count: usize) -> Result<Self> {
        let mut catalog = inner.reservations.lock().map_err(|_| Error::Poisoned)?;
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        let reserved = catalog
            .publication_reserved
            .checked_add(count)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationPublicationCapacity,
            )))?;
        catalog.origins.try_reserve(reserved).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ObjectCreatorAllocation,
            ))
        })?;
        catalog
            .resource_activities
            .try_reserve(reserved)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::ResourceActivityAllocation,
                ))
            })?;
        catalog.publication_reserved = reserved;
        Ok(Self {
            inner: Arc::downgrade(inner),
            remaining: AtomicUsize::new(count),
        })
    }

    /// Called under the catalogue lock before the first handle is inserted.
    pub(super) fn check(&self, catalog: &Catalog, count: usize) -> Result<()> {
        if count > self.remaining.load(Ordering::Relaxed)
            || count > catalog.publication_reserved
            || catalog
                .origins
                .capacity()
                .saturating_sub(catalog.origins.len())
                < count
            || catalog
                .resource_activities
                .capacity()
                .saturating_sub(catalog.resource_activities.len())
                < count
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationPublicationCapacityChanged,
            )));
        }
        Ok(())
    }

    /// Record one completed insertion. The catalogue lock serializes consumers;
    /// the atomic also permits Drop to inspect the unused count without a borrow.
    pub(super) fn consume(&self, catalog: &mut Catalog) -> Result<()> {
        let remaining = self.remaining.load(Ordering::Relaxed);
        let next = remaining.checked_sub(1).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationPublicationSlotExhausted,
            ),
        ))?;
        catalog.publication_reserved =
            catalog
                .publication_reserved
                .checked_sub(1)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
                    crate::ObjectCreationRejection::CreationPublicationAccounting,
                )))?;
        self.remaining.store(next, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for PublicationSlots {
    fn drop(&mut self) {
        let remaining = *self.remaining.get_mut();
        if remaining == 0 {
            return;
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut catalog = inner
                .reservations
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            match catalog.publication_reserved.checked_sub(remaining) {
                Some(next) => catalog.publication_reserved = next,
                None => catalog.broken = true,
            }
        }
    }
}
