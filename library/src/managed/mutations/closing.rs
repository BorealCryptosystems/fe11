// SPDX-License-Identifier: Apache-2.0
//! Close coordination borrows resident vectors and merges them without a new
//! aggregate allocation. O(N*K) head comparisons for N entries and K residents.
use super::{close_storage::CloseLoan, Catalog, Inner, ObjectCreator};
use crate::{
    module::{SessionEntry, State},
    registry::Activity,
    Error, Result,
};
use std::sync::{atomic::Ordering, Arc, Weak};

/// Declared outside all closing guards by its caller, including preparation
/// failures. No strong Entry is stored in an Entry's retained CloseState.
pub(crate) struct CloseReservation {
    inner: Weak<Inner>,
    loans: Vec<CloseLoan>,
    unknown: Option<UnknownCreatorClose>,
    unknown_loan: bool,
}
struct UnknownCreatorClose {
    slot: Option<crate::module::SlotClose>,
    abandoned: Vec<u64>,
    key: (fe11_sys::CK_SLOT_ID, u64),
    objects: Vec<Arc<crate::managed::NativeIdentity>>,
    managed: Vec<Arc<crate::managed::NativeIdentity>>,
    registered: bool,
}

enum Scope<'a> {
    Single(&'a Arc<SessionEntry>),
    Batch(&'a crate::session_budget::RecoveryBatch),
}
impl Scope<'_> {
    fn owns_uid(&self, uid: u64) -> bool {
        match self {
            Self::Single(entry) => entry.credit.uid() == uid,
            Self::Batch(batch) => batch.owns_uid(uid),
        }
    }
}

impl CloseReservation {
    fn empty(inner: &Arc<Inner>) -> Self {
        Self {
            inner: Arc::downgrade(inner),
            loans: Vec::new(),
            unknown: None,
            unknown_loan: false,
        }
    }
    fn prepare_entry(&mut self, entry: &Arc<SessionEntry>, catalog: &Catalog) -> Result<()> {
        // The caller's outer vector was prepared before borrowing any resident.
        if self.loans.len() == self.loans.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorSnapshotAllocation,
            )));
        }
        self.loans.push(entry.creator_close.borrow()?);
        let buffers = self
            .loans
            .last_mut()
            .expect("inserted close loan")
            .buffers_mut();
        for origin in catalog
            .origins
            .values()
            .filter(|origin| Arc::ptr_eq(&origin.creator, entry))
        {
            buffers.destination(&origin.destination, &origin.destination_activity)?;
            buffers.resource(&origin.resource_activity)?;
        }
        for (destination, pending) in catalog
            .pending_creations
            .iter()
            .filter(|(_, pending)| Arc::ptr_eq(&pending.creator, entry))
        {
            buffers.destination(destination, &pending.destination_activity)?;
            buffers.resource(&pending.resource_activity)?;
        }
        buffers.sort();
        Ok(())
    }
    fn reset_cursors(&mut self) {
        for loan in &mut self.loans {
            loan.buffers_mut().destination_cursor = 0;
            loan.buffers_mut().resource_cursor = 0;
        }
    }
    /// Select one anchored head and advance all equal heads. The selected
    /// resident owns the unique permit and counted catalogue reservation.
    fn next_destination(&mut self) -> Option<(usize, usize)> {
        let mut selected: Option<(usize, usize)> = None;
        for (i, loan) in self.loans.iter().enumerate() {
            let b = loan.buffers();
            let Some(head) = b.destinations.get(b.destination_cursor) else {
                continue;
            };
            if selected.map_or(true, |(s, j)| {
                head.key < self.loans[s].buffers().destinations[j].key
            }) {
                selected = Some((i, b.destination_cursor));
            }
        }
        let (selected, position) = selected?;
        let key = self.loans[selected].buffers().destinations[position]
            .key
            .clone();
        for loan in &mut self.loans {
            let b = loan.buffers_mut();
            if b.destinations
                .get(b.destination_cursor)
                .is_some_and(|head| head.key == key)
            {
                b.destination_cursor += 1;
            }
        }
        Some((selected, position))
    }
    fn next_resource(&mut self) -> Option<(usize, usize)> {
        let mut selected: Option<(usize, usize)> = None;
        for (i, loan) in self.loans.iter().enumerate() {
            let b = loan.buffers();
            let Some(head) = b.resources.get(b.resource_cursor) else {
                continue;
            };
            if selected.map_or(true, |(s, j)| {
                (Arc::as_ptr(head) as usize)
                    < Arc::as_ptr(&self.loans[s].buffers().resources[j]) as usize
            }) {
                selected = Some((i, b.resource_cursor));
            }
        }
        let (selected, position) = selected?;
        let anchor = self.loans[selected].buffers().resources[position].clone();
        for loan in &mut self.loans {
            let b = loan.buffers_mut();
            if b.resources
                .get(b.resource_cursor)
                .is_some_and(|head| Arc::ptr_eq(head, &anchor))
            {
                b.resource_cursor += 1;
            }
        }
        Some((selected, position))
    }
    /// Each loan is sorted and deduplicated by prepare_entry. Keep the first
    /// occurrence across loans, borrowing the resident key without a new Vec.
    /// Membership searches visit earlier loans and use their existing sort order.
    /// The mutation/held-flag passes still use the ordered head merge below.
    fn unique_destinations(&self) -> impl Iterator<Item = &super::Destination> + Clone {
        self.loans
            .iter()
            .enumerate()
            .flat_map(move |(index, loan)| {
                let earlier = &self.loans[..index];
                loan.buffers()
                    .destinations
                    .iter()
                    .filter(move |destination| {
                        !earlier.iter().any(|loan| {
                            loan.buffers()
                                .destinations
                                .binary_search_by(|other| other.key.cmp(&destination.key))
                                .is_ok()
                        })
                    })
                    .map(|destination| &destination.key)
            })
    }

    fn reserve_catalog(&mut self, catalog: &mut Catalog, scope: Scope<'_>) -> Result<()> {
        if catalog.broken {
            return Err(Error::Poisoned);
        }
        self.reset_cursors();
        while let Some((i, j)) = self.next_destination() {
            let key = &self.loans[i].buffers().destinations[j].key;
            if catalog.occupied.contains(key) {
                match catalog.owned.get(key) {
                    Some((uid, count)) if scope.owns_uid(*uid) => {
                        count.checked_add(1).ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectCleanup(
                                crate::ObjectCleanupRejection::CreatorReservationCount,
                            ),
                        ))?;
                    }
                    _ => {
                        return Err(Error::Busy(crate::BusyReason::ObjectCleanup(
                            crate::ObjectCleanupBusy::CreatorMutation,
                        )))
                    }
                }
            }
        }
        let vacant = self
            .unique_destinations()
            .filter(|key| !catalog.occupied.contains(*key));
        let additional = catalog.check_admitted_owners(vacant, true, |uid| scope.owns_uid(uid))?;
        catalog.occupied.try_reserve(additional).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DestinationAllocation,
            ))
        })?;
        // Existing entries keep their stored keys. Every new key was validated
        // above; all clones share resident bytes, so publication cannot allocate
        // a private copy or partially fail after the first insertion.
        for key in self.unique_destinations() {
            if !catalog.occupied.contains(key) {
                catalog.occupied.insert(key.clone());
            }
        }
        self.reset_cursors();
        while let Some((i, j)) = self.next_destination() {
            let destination = &mut self.loans[i].buffers_mut().destinations[j];
            if let Some((_, count)) = catalog.owned.get_mut(&destination.key) {
                *count += 1;
            }
            destination.held = true;
        }
        Ok(())
    }
    fn protect(
        &mut self,
        mut acquire: impl FnMut(&Arc<Activity>) -> Result<crate::registry::WritePermit>,
        mut after_acquire: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.reset_cursors();
        // Global ordering applies to the complete batch, not Entry by Entry.
        while let Some((i, j)) = self.next_destination() {
            let buffers = self.loans[i].buffers_mut();
            if buffers.permits.len() == buffers.permits.capacity() {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorCloseCapacityNotPrepared,
                )));
            }
            buffers
                .permits
                .push(acquire(&buffers.destinations[j].activity)?);
            after_acquire()?;
        }
        while let Some((i, j)) = self.next_resource() {
            let buffers = self.loans[i].buffers_mut();
            if buffers.permits.len() == buffers.permits.capacity() {
                return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorCloseCapacityNotPrepared,
                )));
            }
            buffers.permits.push(acquire(&buffers.resources[j])?);
            after_acquire()?;
        }
        Ok(())
    }
    pub(crate) fn protect_for_close(&mut self, uid: u64) -> Result<()> {
        // Move the general snapshot out temporarily to avoid borrowing self
        // across permit insertion. It is returned on every ordinary outcome.
        let abandoned = std::mem::take(
            &mut self
                .unknown
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::UnknownCreatorCloseAbsent,
                )))?
                .abandoned,
        );
        let result = self.protect(
            |a| a.write_for_close_with_abandoned(uid, &abandoned),
            || Ok(()),
        );
        self.unknown
            .as_mut()
            .expect("close barrier retained")
            .abandoned = abandoned;
        result
    }
    pub(crate) fn protect_for_recovery(
        &mut self,
        batch: &crate::session_budget::RecoveryBatch,
        admission: &crate::ResourceAdmission,
    ) -> Result<Option<Arc<Activity>>> {
        let mut blocked = None;
        let result = self.protect(
            |activity| {
                admission.check_available()?;
                match activity.try_write_for_recovery(batch, &crate::ResourceAdmission::Immediate) {
                    Err(error @ Error::Busy(_)) => {
                        blocked = Some(activity.clone());
                        Err(error)
                    }
                    result => result,
                }
            },
            // The new writer is already in the retained close reservation.
            // A final deadline refusal must not destroy it under the slot gate.
            || admission.check_available(),
        );
        match (result, blocked) {
            (Ok(()), _) => Ok(None),
            (Err(Error::Busy(_)), Some(activity)) => Ok(Some(activity)),
            (Err(error), _) => Err(error),
        }
    }
    pub(crate) fn revoke_unknown(&self) {
        if let Some(unknown) = &self.unknown {
            for alias in &unknown.objects {
                alias.revoked.store(true, Ordering::Release);
            }
            for alias in &unknown.managed {
                alias.revoked.store(true, Ordering::Release);
            }
        }
    }
}

impl Drop for CloseReservation {
    fn drop(&mut self) {
        // Explicit order: permits, counted destinations, Entry loans, unknown
        // loan plus catalogue barrier, finally SlotClose. No native release is
        // inferred by this local coordination owner.
        for loan in &mut self.loans {
            loan.buffers_mut().permits.clear();
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut catalog = inner.reservations.lock().unwrap_or_else(|p| p.into_inner());
            for loan in &self.loans {
                for destination in &loan.buffers().destinations {
                    if destination.held {
                        catalog.release(std::slice::from_ref(&destination.key));
                    }
                }
            }
            let wake = catalog.scan_wake();
            drop(catalog);
            wake.notify();
        }
        for loan in &mut self.loans {
            loan.clear();
        }
        let mut unknown_loan = if self.unknown_loan {
            self.loans.pop()
        } else {
            None
        };
        self.loans.clear();
        if let Some(mut unknown) = self.unknown.take() {
            unknown.objects.clear();
            unknown.managed.clear();
            if let Some(inner) = self.inner.upgrade() {
                let mut catalog = inner.reservations.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(loan) = &mut unknown_loan {
                    loan.return_empty();
                }
                if unknown.registered {
                    match catalog.unknown_closing.get_mut(&unknown.key) {
                        Some(count) if *count > 1 => *count -= 1,
                        Some(1) => {
                            catalog.unknown_closing.remove(&unknown.key);
                        }
                        _ => catalog.broken = true,
                    }
                }
                drop(catalog);
            }
            drop(unknown_loan);
            drop(unknown.slot.take());
        }
    }
}

pub(crate) fn reserve_session_close(
    inner: &Arc<Inner>,
    state: &State,
    entry: &Arc<SessionEntry>,
    outer: &mut Option<CloseReservation>,
) -> Result<()> {
    if outer.is_some() {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
            crate::ObjectCleanupRejection::CreatorClosePreparationAlreadyPresent,
        )));
    }
    *outer = Some(CloseReservation::empty(inner));
    let owner = outer.as_mut().expect("outer close owner installed");
    owner.loans.try_reserve_exact(2).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ObjectCleanup(
            crate::ObjectCleanupRejection::CreatorSnapshotAllocation,
        ))
    })?;
    owner.unknown = Some(UnknownCreatorClose {
        slot: Some(crate::module::SlotClose::new(&entry.snapshot.domain)?),
        key: (entry.slot, entry.snapshot.generation),
        abandoned: Vec::new(),
        objects: Vec::new(),
        managed: Vec::new(),
        registered: false,
    });
    let unknown = owner.unknown.as_mut().expect("barrier installed");
    if !state.native.is_uncertain() {
        let deferred = state
            .session_ledger
            .deferred(usize::MAX, Some(&entry.snapshot))?;
        unknown
            .abandoned
            .try_reserve_exact(deferred.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::AbandonedReaderSnapshotAllocation,
                ))
            })?;
        for other in deferred {
            if other.mode == crate::AdvancedSessionMode::Synchronous
                && other.deferred_close.load(Ordering::Acquire)
                && !other.closed.load(Ordering::Acquire)
                && !other.close_attempted.load(Ordering::Acquire)
                && state
                    .operations
                    .abandoned_reader_quiescent(other.credit.uid())
                    .unwrap_or(false)
            {
                unknown.abandoned.push(other.credit.uid());
            }
        }
    }
    let unknown_creator = |creator: &ObjectCreator| {
        matches!(
            creator,
            ObjectCreator::UnknownSessionCreator | ObjectCreator::UnknownPersistence
        )
    };
    unknown.objects = state.objects.live()?;
    unknown.objects.retain(|a| {
        (a.slot, a.generation) == unknown.key
            && !a.revoked.load(Ordering::Acquire)
            && unknown_creator(a.creator())
    });
    unknown.managed = state.managed.live()?;
    unknown.managed.retain(|a| {
        (a.slot, a.generation) == unknown.key
            && !a.revoked.load(Ordering::Acquire)
            && unknown_creator(a.creator())
    });
    let mut catalog = inner.reservations.try_lock().map_err(|e| match e {
        std::sync::TryLockError::WouldBlock => Error::Busy(crate::BusyReason::ObjectCleanup(
            crate::ObjectCleanupBusy::ObjectCatalogue,
        )),
        _ => Error::Poisoned,
    })?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    owner.prepare_entry(entry, &catalog)?;
    let unknown = owner.unknown.as_mut().expect("barrier installed");
    let count = catalog
        .unknown_closing
        .get(&unknown.key)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
            crate::ObjectCleanupRejection::UnknownCreatorCloseCount,
        )))?;
    catalog.unknown_closing.try_reserve(1).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ObjectCleanup(
            crate::ObjectCleanupRejection::UnknownCreatorCloseAllocation,
        ))
    })?;
    // A prior pending close already revoked its unknowns. An empty live set
    // never borrows the occupied unknown workspace or introduces a new Busy.
    if !unknown.objects.is_empty() || !unknown.managed.is_empty() {
        owner.loans.push(entry.snapshot.unknown_close.borrow()?);
        owner.unknown_loan = true;
        let buffers = owner
            .loans
            .last_mut()
            .expect("unknown loan inserted")
            .buffers_mut();
        for alias in &unknown.objects {
            buffers.resource(alias.activity()?)?;
        }
        for alias in &unknown.managed {
            buffers.resource(alias.activity()?)?;
        }
        buffers.sort();
    }
    catalog.unknown_closing.insert(unknown.key, count);
    unknown.registered = true;
    owner.reserve_catalog(&mut catalog, Scope::Single(entry))
}

pub(crate) fn reserve_recovery_batch(
    inner: &Arc<Inner>,
    batch: &crate::session_budget::RecoveryBatch,
    outer: &mut Option<CloseReservation>,
) -> Result<()> {
    if outer.is_some() {
        return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
            crate::ObjectCleanupRejection::CreatorClosePreparationAlreadyPresent,
        )));
    }
    *outer = Some(CloseReservation::empty(inner));
    let owner = outer.as_mut().expect("outer close owner installed");
    owner
        .loans
        .try_reserve_exact(batch.entries_for_close().count())
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorSnapshotAllocation,
            ))
        })?;
    let mut catalog = inner.reservations.try_lock().map_err(|e| match e {
        std::sync::TryLockError::WouldBlock => Error::Busy(crate::BusyReason::ObjectCleanup(
            crate::ObjectCleanupBusy::ObjectCatalogue,
        )),
        _ => Error::Poisoned,
    })?;
    if catalog.broken {
        return Err(Error::Poisoned);
    }
    for entry in batch.entries_for_close() {
        owner.prepare_entry(entry, &catalog)?;
    }
    owner.reserve_catalog(&mut catalog, Scope::Batch(batch))
}
