// SPDX-License-Identifier: Apache-2.0
//! Track destination reservations, catalog scans and resource activities.
//! Prepared selection and creation slots keep publication capacity separate from native effects.

use super::*;

impl Catalog {
    pub(crate) fn new_with_budget(
        maximum_destinations: Option<usize>,
        _budget: Arc<crate::symmetric::memory::Budget>,
    ) -> Self {
        Self {
            scan_wake: Arc::new(crate::admission_wait::Wake::default()),

            maximum_destinations,
            occupied: std::collections::HashSet::new(),
            owned: std::collections::HashMap::new(),
            scans: std::collections::HashMap::new(),
            owned_scans: Vec::new(),
            selected: std::collections::HashMap::new(),
            owned_selections: Vec::new(),
            destination_activities: std::collections::HashMap::new(),
            resource_activities: std::collections::HashMap::new(),
            origins: std::collections::HashMap::new(),
            pending_creations: std::collections::HashMap::new(),
            pending_reserved: 0,
            publication_reserved: 0,
            unknown_closing: std::collections::HashMap::new(),
            broken: false,
        }
    }

    pub(super) fn resource_activity_prepared(
        &mut self,
        key: ResourceIdentity,
        visibility: crate::Observation<bool>,
        credit: impl FnOnce() -> Result<crate::symmetric::memory::Credit>,
    ) -> Result<Arc<crate::registry::Activity>> {
        if self.broken {
            return Err(Error::Poisoned);
        }
        let key = key.native();
        if let Some(entry) = self.resource_activities.get_mut(&key) {
            if let Some(live) = entry.activity.upgrade() {
                remember_visibility(&mut entry.visibility, visibility);
                return Ok(live);
            }
        }
        self.resource_activities
            .retain(|_, entry| entry.activity.strong_count() > 0);
        // An unrelated observation must not consume slots prepaid for a
        // creation whose native call has not returned yet.
        let additional = self
            .publication_reserved
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ResourcePublicationCapacity,
            )))?;
        self.resource_activities
            .try_reserve(additional)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::ResourceActivityAllocation,
                ))
            })?;
        let value = Arc::new(crate::registry::Activity::from_credit(credit()?));
        self.resource_activities.insert(
            key,
            ResourceActivity {
                activity: Arc::downgrade(&value),
                visibility: Some(visibility),
                creation: None,
            },
        );
        Ok(value)
    }

    pub(super) fn reserve(&mut self, keys: &[Destination]) -> Result<()> {
        self.reserve_admitted(keys, false, None)
    }

    pub(super) fn reserve_admitted(
        &mut self,
        keys: &[Destination],
        cleanup: bool,
        closing: Option<u64>,
    ) -> Result<()> {
        self.reserve_admitted_owners(keys, cleanup, |uid| closing == Some(uid))
    }

    pub(super) fn reserve_admitted_owners(
        &mut self,
        keys: &[Destination],
        cleanup: bool,
        closing: impl Fn(u64) -> bool,
    ) -> Result<()> {
        let additional = self.check_admitted_owners(keys.iter(), cleanup, closing)?;
        // Clones share credited immutable bytes. No private staging allocation
        // or fallible step is needed after the shared table has been reserved.
        self.occupied.try_reserve(additional).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationAllocation,
            ))
        })?;
        self.occupied.extend(keys.iter().cloned());
        Ok(())
    }

    /// Validate a repeatable borrowed view without changing the catalogue.
    /// Closing can supply its resident keys directly instead of copying them.
    pub(super) fn check_admitted_owners<'a>(
        &self,
        keys: impl Iterator<Item = &'a Destination> + Clone,
        cleanup: bool,
        closing: impl Fn(u64) -> bool,
    ) -> Result<usize> {
        if self.broken {
            return Err(Error::Poisoned);
        }
        for (key, count) in &self.scans {
            if keys
                .clone()
                .any(|destination| (destination.slot, destination.generation) == *key)
            {
                // Recovery may close the owning session without releasing its
                // observation buffers first. Other sessions' inventories still
                // exclude mutation and closure of objects they may be reading.
                let owned = self
                    .owned_scans
                    .iter()
                    .filter(|record| {
                        record.owner.strong_count() != 0
                            && closing(record.session)
                            && record.key == *key
                    })
                    .count();
                if *count != owned {
                    return Err(Error::Busy(crate::BusyReason::ObjectMutation(
                        crate::ObjectMutationBusy::TokenInventory,
                    )));
                }
            }
        }
        for (selected, count) in &self.selected {
            if keys.clone().any(|key| key.overlaps(selected)) {
                let allowed = self
                    .owned_selections
                    .iter()
                    .filter_map(std::sync::Weak::upgrade)
                    .filter(|owner| closing(owner.session) && owner.keys.contains(selected))
                    .count();
                if *count != allowed {
                    return Err(Error::Busy(crate::BusyReason::ObjectMutation(
                        crate::ObjectMutationBusy::ObjectSelection,
                    )));
                }
            }
        }
        let additional = keys.clone().try_fold(0usize, |count, _| {
            count
                .checked_add(1)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::DestinationCount,
                )))
        })?;
        let count = self
            .occupied
            .len()
            .checked_add(additional)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationCount,
            )))?;
        if !cleanup
            && self
                .maximum_destinations
                .is_some_and(|maximum| count > maximum)
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationQuotaExceeded,
            )));
        }
        if keys.clone().enumerate().any(|(i, key)| {
            self.occupied.iter().any(|occupied| key.overlaps(occupied))
                || keys.clone().take(i).any(|prior| prior == key)
        }) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ObjectDestinationReserved,
            )));
        }
        Ok(additional)
    }

    pub(super) fn begin_select(&mut self, keys: &[Destination]) -> Result<()> {
        if self.broken {
            return Err(Error::Poisoned);
        }
        if keys
            .iter()
            .any(|k| self.occupied.iter().any(|o| k.overlaps(o)))
        {
            return Err(Error::Busy(crate::BusyReason::ReferenceRegistry(
                crate::ReferenceRegistryBusy::ObjectMutation,
            )));
        }
        for (i, k) in keys.iter().enumerate() {
            if keys[..i].contains(k) {
                return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::DuplicateSelection,
                )));
            }
            self.selected
                .get(k)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::SelectionCount,
                )))?;
        }
        self.selected.try_reserve(keys.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::SelectionAllocation,
            ))
        })?;
        for k in keys {
            *self.selected.entry(k.clone()).or_default() += 1;
        }
        Ok(())
    }

    pub(super) fn end_select(&mut self, keys: &[Destination]) {
        for k in keys {
            match self.selected.get_mut(k) {
                Some(n) if *n > 1 => *n -= 1,
                Some(1) => {
                    self.selected.remove(k);
                }
                _ => self.broken = true,
            }
        }
    }

    pub(super) fn release(&mut self, keys: &[Destination]) {
        for k in keys {
            if let Some((_, count)) = self.owned.get_mut(k) {
                if *count > 1 {
                    *count -= 1;
                    continue;
                }
            }
            self.owned.remove(k);
            if !self.occupied.remove(k) {
                self.broken = true;
            }
        }
    }

    pub(super) fn begin_scan(&mut self, key: (CK_SLOT_ID, u64)) -> Result<()> {
        if self.broken {
            return Err(Error::Poisoned);
        }
        if self.occupied.iter().any(|k| (k.slot, k.generation) == key) {
            return Err(Error::Busy(crate::BusyReason::ObjectMutation(
                crate::ObjectMutationBusy::TokenMutation,
            )));
        }
        let n = self
            .scans
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::InventoryCount,
            )))?;
        self.scans
            .try_reserve(usize::from(!self.scans.contains_key(&key)))
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::InventoryAllocation,
                ))
            })?;
        self.scans.insert(key, n);
        Ok(())
    }

    pub(crate) fn scan_wake(&self) -> Arc<crate::admission_wait::Wake> {
        self.scan_wake.clone()
    }

    pub(super) fn end_scan(&mut self, key: (CK_SLOT_ID, u64)) {
        match self.scans.get_mut(&key) {
            Some(n) if *n > 1 => *n -= 1,
            Some(1) => {
                self.scans.remove(&key);
            }
            _ => self.broken = true,
        }
    }
}

impl InventoryRecord {
    pub(super) fn new(owner: &Arc<InventoryOwner>) -> Self {
        Self {
            owner: Arc::downgrade(owner),
            key: owner.key,
            session: owner.session,
        }
    }
}

impl PreparedInventory {
    /// Wait only for catalog readiness, with no private preparation or session
    /// possession retained. Publication must still recheck after this wakeup.
    pub(crate) fn wait_available(session: &Session, epoch: u64) -> Result<()> {
        let wake = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?
            .scan_wake();
        wake.acquire(&crate::admission_wait::current(), || {
            crate::session::recovery::observations::context(session, Some(epoch), epoch)?;
            let catalog = session
                .inner
                .reservations
                .lock()
                .map_err(|_| Error::Poisoned)?;
            if catalog.broken {
                return Err(Error::Poisoned);
            }
            let key = (session.entry.slot, session.snapshot.generation);
            if catalog
                .occupied
                .iter()
                .any(|item| (item.slot, item.generation) == key)
            {
                Ok(crate::admission_wait::Attempt::Occupied(
                    crate::BusyReason::ObjectMutation(crate::ObjectMutationBusy::TokenMutation),
                ))
            } else {
                Ok(crate::admission_wait::Attempt::Acquired(()))
            }
        })
    }

    pub(crate) fn allocation_bytes() -> Result<usize> {
        // Planned peak payload: shared owner and counters, one catalogue
        // identity and one scan counter. Catalogue allocator overhead is not
        // part of the owned-payload credit ceiling.
        std::mem::size_of::<InventoryOwner>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<InventoryRecord>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<((CK_SLOT_ID, u64), usize)>()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::InventoryOwnerSize,
            )))
    }

    pub(crate) fn from_prepaid(
        session: &Session,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes()?)?;
        Ok(Self {
            owner: Arc::new(InventoryOwner {
                inner: Arc::downgrade(&session.inner),
                key: (session.entry.slot, session.snapshot.generation),
                session: session.uid,
                registered: false,
                _credit: credit,
            }),
        })
    }

    pub(crate) fn publish(mut self, session: &Session) -> Result<InventoryGuard> {
        self.publish_retained(session)
    }

    /// Keep the private allocation in its caller's early local on refusal.
    /// Streaming callers release possession before dropping that preparation.
    pub(crate) fn publish_retained(&mut self, session: &Session) -> Result<InventoryGuard> {
        let owner = &mut self.owner;
        session.snapshot.check()?;
        if !owner.inner.ptr_eq(&Arc::downgrade(&session.inner))
            || owner.key != (session.entry.slot, session.snapshot.generation)
            || owner.session != session.uid
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ForeignInventoryPreparation,
            )));
        }
        let prepared =
            Arc::get_mut(owner).ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::InventoryPreparationAlreadyShared,
            )))?;
        if prepared.registered {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::InventoryPreparationAlreadyPublished,
            )));
        }
        let mut catalog = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?;
        catalog.owned_scans.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::InventoryOwnerAllocation,
            ))
        })?;
        catalog.begin_scan(prepared.key)?;
        prepared.registered = true;
        // Capacity and identity were checked before the exclusion was acquired.
        catalog.owned_scans.push(InventoryRecord::new(owner));
        drop(catalog);
        Ok(InventoryGuard {
            owner: owner.clone(),
        })
    }
}

impl InventoryGuard {
    pub(crate) fn belongs_to(&self, inner: &Arc<Inner>, session: u64) -> bool {
        self.owner.inner.ptr_eq(&Arc::downgrade(inner)) && self.owner.session == session
    }
}

impl Drop for InventoryOwner {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut catalog = inner.reservations.lock().unwrap_or_else(|p| p.into_inner());
            // Exactly the final shared owner releases the original scan. A
            // cloned observation creates neither a scan nor an extra permit.
            catalog.end_scan(self.key);
            let owner = self as *const Self;
            catalog
                .owned_scans
                .retain(|entry| entry.owner.as_ptr() != owner);
        }
    }
}
