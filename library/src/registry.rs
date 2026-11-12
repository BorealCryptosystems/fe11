// SPDX-License-Identifier: Apache-2.0
use crate::{
    admission_wait::{Attempt, Wake},
    Error, Result,
};
use std::sync::{Arc, Mutex, TryLockError, Weak};

mod visit;

/// Per-identity activity. The short state lock is never held across native calls.
/// Owned permits can retain key activity between explicit async completions.
#[derive(Default)]
pub(crate) struct Activity(Arc<Mutex<ActivityState>>, Arc<Wake>);
#[derive(Default)]
struct ActivityState {
    readers: usize,
    owned: Vec<ReaderOwner>,
    writer: bool,
    base_writer: bool,
    owned_writer: Option<(u64, usize)>,
    poisoned: bool,
    // Publication may wait on the catalog/context domain as well as writers.
    // A weak link keeps this coordination from retaining the module owner.
    context_wake: Option<Weak<Wake>>,
    // Every permit retains the exact outer Activity registered by the catalogue.
    // Activity retains this state, its Wake, and their resident storage credits.
    // Drop vectors before their credits; no uncredited capacity survives.
    owned_credit: Option<crate::symmetric::memory::Credit>,
    allocation_credit: Option<crate::symmetric::memory::Credit>,
}

#[derive(Clone, Copy)]
struct ReaderOwner {
    uid: u64,
    readers: usize,
    transferred_writers: usize,
    preparations: usize,
}

/// A prepaid attribution slot, without access to the object. The slot survives
/// concurrent permit drops until this preparation is released. It normally
/// admits a reader; a live writer capability can instead transfer an exclusion.
pub(crate) struct PreparedReader {
    activity: Arc<Activity>,
    uid: u64,
}

pub(crate) struct ReadPermit {
    activity: Arc<Activity>,
    owner: Option<u64>,
}
pub(crate) struct WritePermit {
    activity: Arc<Activity>,
    was_panicking: bool,
}

impl PreparedReader {
    pub(crate) fn acquire_once(&self, admission: &crate::ResourceAdmission) -> Result<ReadPermit> {
        admission.try_once(|| self.acquire_ready())
    }
    /// Store possession before checking cancellation/deadline again. On a
    /// post-acquisition refusal the caller still owns the permit and must drop
    /// its session access before clearing this slot.
    pub(crate) fn acquire_into(
        &self,
        admission: &crate::ResourceAdmission,
        retained: &mut Option<ReadPermit>,
    ) -> Result<()> {
        if retained.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectReaderSlotAlreadyOccupied,
            )));
        }
        admission.try_once(|| {
            *retained = Some(self.acquire_ready()?);
            Ok(())
        })
    }
    fn acquire_ready(&self) -> Result<ReadPermit> {
        self.activity
            .1
            .acquire(&crate::ResourceAdmission::Immediate, || {
                let mut state = self.activity.0.lock().map_err(|_| Error::Poisoned)?;
                if state.poisoned {
                    return Err(Error::Poisoned);
                }
                if state.writer {
                    return Ok(Attempt::Occupied(crate::BusyReason::ReferenceRegistry(
                        crate::ReferenceRegistryBusy::ObjectMutation,
                    )));
                }
                let readers = state.readers.checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::ObjectActivityCount,
                    ),
                ))?;
                let owner = state
                    .owned
                    .iter_mut()
                    .find(|owner| owner.uid == self.uid && owner.preparations != 0)
                    .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::ObjectActivityOwner,
                    )))?;
                owner.readers = owner.readers.checked_add(1).ok_or(Error::Rejected(
                    crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::ObjectActivityCount,
                    ),
                ))?;
                state.readers = readers;
                Ok(Attempt::Acquired(ReadPermit {
                    activity: self.activity.clone(),
                    owner: Some(self.uid),
                }))
            })
    }
    pub(crate) fn wait_available_checked(
        &self,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        self.wait_on(&self.activity.1, admission, before)
    }

    /// Publication must also stop when its enclosing context is withdrawn.
    /// Context publication notifies this domain; writer drops also notify
    /// it after releasing ActivityState. No polling interval replaces WaitUntil.
    pub(crate) fn wait_available_in_context(
        &self,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        let wake = {
            let state = self.activity.0.lock().map_err(|_| Error::Poisoned)?;
            state
                .context_wake
                .as_ref()
                .and_then(Weak::upgrade)
                .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ActivityContextNotifierAbsent,
                )))?
        };
        self.wait_on(&wake, admission, before)
    }

    fn wait_on(
        &self,
        wake: &Arc<Wake>,
        admission: &crate::ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        wake.acquire(admission, || {
            before()?;
            let state = self.activity.0.lock().map_err(|_| Error::Poisoned)?;
            if state.poisoned {
                return Err(Error::Poisoned);
            }
            if state.writer {
                return Ok(Attempt::Occupied(crate::BusyReason::ReferenceRegistry(
                    crate::ReferenceRegistryBusy::ObjectMutation,
                )));
            }
            Ok(Attempt::Acquired(()))
        })
    }
}
impl Drop for PreparedReader {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(index) = state.owned.iter().position(|owner| owner.uid == self.uid) {
            if let Some(count) = state.owned[index].preparations.checked_sub(1) {
                state.owned[index].preparations = count;
                if count == 0
                    && state.owned[index].readers == 0
                    && state.owned[index].transferred_writers == 0
                {
                    state.owned.swap_remove(index);
                }
            } else {
                state.poisoned = true;
            }
        } else {
            state.poisoned = true;
        }
        let storage_wake = state.reader_storage_wake();
        drop(state);
        self.activity.1.notify();
        if let Some(wake) = storage_wake {
            wake.notify();
        }
    }
}

/// Additional attribution for an already-held exclusive writer. Only a live
/// writer capability may grant this permit; an object handle alone cannot.
pub(crate) struct TransferredWritePermit {
    activity: Arc<Activity>,
    owner: u64,
    was_panicking: bool,
}
impl PreparedReader {
    fn transfer_writer(&self, activity: &Arc<Activity>) -> Result<TransferredWritePermit> {
        if !Arc::ptr_eq(&self.activity, activity) {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ForeignWriterTransferActivity,
            )));
        }
        let mut state = activity.0.lock().map_err(|_| Error::Poisoned)?;
        if state.poisoned || !state.writer || state.readers != 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::WriterTransferState,
            )));
        }
        let owner = state
            .owned
            .iter_mut()
            .find(|owner| owner.uid == self.uid && owner.preparations != 0)
            .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::WriterTransferAttributionAbsent,
            )))?;
        owner.transferred_writers =
            owner
                .transferred_writers
                .checked_add(1)
                .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::WriterTransferCount,
                )))?;
        Ok(TransferredWritePermit {
            activity: activity.clone(),
            owner: self.uid,
            was_panicking: std::thread::panicking(),
        })
    }
}
impl TransferredWritePermit {
    pub(crate) fn share_for(&self, destination: &PreparedReader) -> Result<Self> {
        destination.transfer_writer(&self.activity)
    }
}
impl Drop for TransferredWritePermit {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !state.writer || (!self.was_panicking && std::thread::panicking()) {
            state.poisoned = true;
        }
        if let Some(index) = state.owned.iter().position(|owner| owner.uid == self.owner) {
            if let Some(count) = state.owned[index].transferred_writers.checked_sub(1) {
                state.owned[index].transferred_writers = count;
                if count == 0
                    && state.owned[index].readers == 0
                    && state.owned[index].preparations == 0
                {
                    state.owned.swap_remove(index);
                }
            } else {
                state.poisoned = true;
            }
        } else {
            state.poisoned = true;
        }
        state.writer = state.base_writer
            || state
                .owned
                .iter()
                .any(|owner| owner.transferred_writers != 0);
        let context_wake = state.context_wake.as_ref().and_then(Weak::upgrade);
        let storage_wake = state.reader_storage_wake();
        drop(state);
        self.activity.1.notify();
        if let Some(wake) = storage_wake {
            wake.notify();
        }
        if let Some(wake) = context_wake {
            wake.notify();
        }
    }
}
impl WritePermit {
    pub(crate) fn share_for(&self, destination: &PreparedReader) -> Result<TransferredWritePermit> {
        destination.transfer_writer(&self.activity)
    }
    pub(crate) fn owns_activity(&self, activity: &Arc<Activity>) -> bool {
        Arc::ptr_eq(&self.activity, activity)
    }

    pub(crate) fn bind_owner(&mut self, uid: u64) -> Result<()> {
        if uid == 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectActivityOwner,
            )));
        }
        let mut state = self.activity.0.lock().map_err(|_| Error::Poisoned)?;
        if state.poisoned || !state.writer || state.readers != 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectWriteOwnershipState,
            )));
        }
        match state.owned_writer {
            None => state.owned_writer = Some((uid, 1)),
            Some((owner, 1)) if owner == uid => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ForeignOrBorrowedObjectWriter,
                )))
            }
        }
        Ok(())
    }
}
impl ReadPermit {
    /// Transfer an already granted reader for this exact Activity and session.
    /// This checks the live attribution without allocating, reserving capacity,
    /// increasing a counter or waiting for resource availability. A different
    /// role/UID cannot substitute for the prepared permission.
    pub(crate) fn take_prepared(
        permits: &mut [Option<Self>],
        activity: &Arc<Activity>,
        uid: u64,
    ) -> Result<Self> {
        let slot = permits
            .iter_mut()
            .find(|slot| {
                slot.as_ref().is_some_and(|permit| {
                    permit.owner == Some(uid) && Arc::ptr_eq(&permit.activity, activity)
                })
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::PreparedKeyReaderAbsent,
            )))?;
        {
            let state = activity.0.lock().map_err(|_| Error::Poisoned)?;
            if state.poisoned {
                return Err(Error::Poisoned);
            }
            if state.writer
                || state.readers == 0
                || !state
                    .owned
                    .iter()
                    .any(|owner| owner.uid == uid && owner.readers != 0)
            {
                return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::PreparedKeyReaderAttributionLost,
                )));
            }
        }
        Ok(slot.take().expect("validated prepared reader"))
    }

    /// Duplicate an existing attribution, not a new admission. Its live permit
    /// already pins the slot; checked counters are the only possible growth.
    /// Never wait or allocate while an operation duplicates its owned key.
    pub(crate) fn duplicate(&self) -> Result<Self> {
        let mut state = self.activity.0.lock().map_err(|_| Error::Poisoned)?;
        if state.poisoned {
            return Err(Error::Poisoned);
        }
        if state.writer {
            return Err(Error::Busy(crate::BusyReason::ReferenceRegistry(
                crate::ReferenceRegistryBusy::ObjectMutation,
            )));
        }
        let readers = state.readers.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ObjectActivityCount,
            ),
        ))?;
        if let Some(uid) = self.owner {
            let owner = state
                .owned
                .iter_mut()
                .find(|owner| owner.uid == uid && owner.readers != 0)
                .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ObjectActivityOwner,
                )))?;
            owner.readers = owner.readers.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ObjectActivityCount,
                ),
            ))?;
        }
        state.readers = readers;
        Ok(Self {
            activity: self.activity.clone(),
            owner: self.owner,
        })
    }
}

impl Drop for ReadPermit {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(uid) = self.owner {
            if let Some(i) = state.owned.iter().position(|owner| owner.uid == uid) {
                if let Some(n) = state.owned[i].readers.checked_sub(1) {
                    if n == 0
                        && state.owned[i].preparations == 0
                        && state.owned[i].transferred_writers == 0
                    {
                        state.owned.swap_remove(i);
                    } else {
                        state.owned[i].readers = n;
                    }
                } else {
                    state.poisoned = true;
                }
            } else {
                state.poisoned = true;
            }
        }
        if let Some(n) = state.readers.checked_sub(1) {
            state.readers = n;
        } else {
            state.poisoned = true;
        }
        let context_wake = state.context_wake.as_ref().and_then(Weak::upgrade);
        let storage_wake = state.reader_storage_wake();
        drop(state);
        self.activity.1.notify();
        if let Some(wake) = storage_wake {
            wake.notify();
        }
        if let Some(wake) = context_wake {
            wake.notify();
        }
    }
}
impl Drop for WritePermit {
    fn drop(&mut self) {
        let mut state = self
            .activity
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !state.writer || (!self.was_panicking && std::thread::panicking()) {
            state.poisoned = true;
        }
        match state.owned_writer {
            Some((owner, count)) if count > 1 => state.owned_writer = Some((owner, count - 1)),
            _ => {
                state.owned_writer = None;
                state.base_writer = false;
                state.writer = state
                    .owned
                    .iter()
                    .any(|owner| owner.transferred_writers != 0);
            }
        }
        let context_wake = state.context_wake.as_ref().and_then(Weak::upgrade);
        let storage_wake = state.reader_storage_wake();
        drop(state);
        self.activity.1.notify();
        if let Some(wake) = storage_wake {
            wake.notify();
        }
        if let Some(wake) = context_wake {
            wake.notify();
        }
    }
}

struct Entries<T> {
    maximum: Option<usize>,
    items: Vec<Weak<T>>,
    reserved: usize,
    broken: bool,
}
/// Short-lived registry lock; no native call or session wait is allowed while held.
pub(crate) struct Registry<T>(Arc<Mutex<Entries<T>>>, Arc<Wake>);
pub(crate) enum ControlledReference<T, R> {
    Acquired(Reservation<T>),
    Redirect(R),
}
impl<T> Clone for Registry<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}
/// Credits and vector capacity acquired before a native effect. The permit owns
/// the ledger, so it does not borrow State across native error classification.
#[must_use = "hold the reservation until references have been published"]
pub(crate) struct Reservation<T> {
    close: Option<crate::managed::CloseParticipants>,
    registry: Arc<Mutex<Entries<T>>>,
    remaining: usize,
    wake: Arc<Wake>,
    activity_credit: Option<crate::symmetric::memory::Credit>,
}
/// Attached to the registered identity, not to each alias of that identity.
/// The last Arc has already become non-upgradeable when its fields are dropped.
#[derive(Default)]
pub(crate) struct ReferenceLifetime {
    wake: Arc<Wake>,
    _close: Option<crate::managed::CloseParticipant>,
}
impl Drop for ReferenceLifetime {
    fn drop(&mut self) {
        self.wake.notify();
    }
}
impl<T> Registry<T> {
    pub(crate) fn same_registry(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) && Arc::ptr_eq(&self.1, &other.1)
    }

    /// Validate an unpublished permit without acquiring another quota or
    /// consuming its prepared close participants and Activity credit.
    pub(crate) fn matches_reservation(&self, permit: &Reservation<T>, count: usize) -> bool {
        Arc::ptr_eq(&self.0, &permit.registry)
            && Arc::ptr_eq(&self.1, &permit.wake)
            && permit.remaining == count
    }

    pub fn new(maximum: Option<usize>) -> Self {
        Self(
            Arc::new(Mutex::new(Entries {
                maximum,
                items: Vec::new(),
                reserved: 0,
                broken: false,
            })),
            Arc::new(Wake::default()),
        )
    }
    /// Share only the wake channel, without keeping the registry lock alive.
    /// Operation installation publishes its occupation before notifying it.
    pub(crate) fn admission_wake(&self) -> Arc<Wake> {
        Arc::clone(&self.1)
    }

    /// The logical predicate is pure and precedes the ordinary registry
    /// attempt. A private redirect leaves Wake before any local maintenance.
    pub(crate) fn reserve_controlled<R>(
        &self,
        n: usize,
        admission: &crate::ResourceAdmission,
        mut validate: impl FnMut() -> Result<Option<R>>,
    ) -> Result<ControlledReference<T, R>> {
        {
            let state = self.0.lock().map_err(|_| Error::Poisoned)?;
            if state.broken {
                return Err(Error::Poisoned);
            }
            // No other owner's release can satisfy an intrinsically larger request.
            if state.maximum.is_some_and(|maximum| n > maximum) {
                return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::ReferenceQuotaExceeded,
                )));
            }
        }
        self.1.acquire(admission, || {
            if let Some(route) = validate()? {
                return Ok(Attempt::Acquired(ControlledReference::Redirect(route)));
            }
            Ok(match self.try_reserve(n)? {
                Attempt::Acquired(reservation) => {
                    Attempt::Acquired(ControlledReference::Acquired(reservation))
                }
                Attempt::Occupied(reason) => Attempt::Occupied(reason),
            })
        })
    }
    fn try_reserve(&self, n: usize) -> Result<Attempt<Reservation<T>>> {
        let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
        if state.broken {
            return Err(Error::Poisoned);
        }
        state.items.retain(|w| w.strong_count() > 0);
        let reserved = state.reserved.checked_add(n).ok_or(Error::Rejected(
            crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ReferenceCountOverflow,
            ),
        ))?;
        let total = state
            .items
            .len()
            .checked_add(reserved)
            .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ReferenceCountOverflow,
            )))?;
        if state.maximum.is_some_and(|maximum| total > maximum) {
            return Ok(Attempt::Occupied(crate::BusyReason::ReferenceRegistry(
                crate::ReferenceRegistryBusy::ReferenceQuotaExceeded,
            )));
        }
        // All outstanding permits must fit, not just this caller's n entries.
        state.items.try_reserve(reserved).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ReferenceAllocation,
            ))
        })?;
        state.reserved = reserved;
        Ok(Attempt::Acquired(Reservation {
            close: None,
            registry: self.0.clone(),
            remaining: n,
            wake: self.1.clone(),
            activity_credit: None,
        }))
    }
    /// Upper bound for a prepaid live snapshot, including expired weak slots.
    /// Do not upgrade-and-drop references under this lock: a last owner's Drop
    /// may notify the reference Wake, whose admission predicate locks Entries.
    pub(crate) fn live_storage_capacity(&self) -> Result<usize> {
        let state = self.0.lock().map_err(|_| Error::Poisoned)?;
        if state.broken {
            return Err(Error::Poisoned);
        }
        Ok(state.items.len())
    }
    pub(crate) fn copy_live_matching(
        &self,
        destination: &mut Vec<Arc<T>>,
        rejected: &mut Vec<Arc<T>>,
        matches: impl Fn(&T) -> bool,
    ) -> Result<bool> {
        // Both buffers belong to this single preparation attempt. Never clear
        // an earlier snapshot while the caller holds session access.
        if !destination.is_empty() || !rejected.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::RevocationSnapshotAlreadyPopulated,
            )));
        }
        let state = self.0.lock().map_err(|_| Error::Poisoned)?;
        if state.broken {
            return Err(Error::Poisoned);
        }
        if destination.capacity() < state.items.len() || rejected.capacity() < state.items.len() {
            return Ok(false);
        }
        for value in state.items.iter().filter_map(Weak::upgrade) {
            destination.push(value);
        }
        drop(state);
        // Partition by moving owners, never by destroying them. The caller
        // retains rejected references until its session guards have left.
        let mut index = 0;
        while index < destination.len() {
            if matches(&destination[index]) {
                index += 1;
            } else {
                rejected.push(destination.swap_remove(index));
            }
        }
        Ok(true)
    }
    pub fn live(&self) -> Result<Vec<Arc<T>>> {
        let mut state = self.0.lock().map_err(|_| Error::Poisoned)?;
        if state.broken {
            return Err(Error::Poisoned);
        }
        state.items.retain(|w| w.strong_count() > 0);
        let mut live = Vec::new();
        live.try_reserve_exact(state.items.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::LiveReferenceAllocation,
            ))
        })?;
        live.extend(state.items.iter().filter_map(Weak::upgrade));
        Ok(live)
    }
}
impl<T> Reservation<T> {
    /// Attribute the complete private candidate before its first continuation.
    /// Activity credit remains charged to that observation after publication
    /// transfers it into an identity; publication does not free those bytes.
    /// Other callers' reservations never enter this account.
    pub(crate) fn begin_observation(
        &mut self,
        payload: &mut crate::symmetric::memory::Credit,
    ) -> Result<()> {
        let activities = self.activity_credit.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ReferenceActivityPreparationAbsent,
            ),
        ))?;
        let bytes = activities.bytes();
        payload.merge_retained(activities)?;
        payload.observation_budget()?;
        *activities = payload.split(bytes)?;
        Ok(())
    }

    pub(crate) fn prepare_activities(
        &mut self,
        credit: crate::symmetric::memory::Credit,
    ) -> Result<()> {
        if self.activity_credit.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ReferenceActivityPreparationAlreadyPresent,
            )));
        }
        self.activity_credit = Some(credit);
        Ok(())
    }
    pub(crate) fn activity_credit(
        &mut self,
        bytes: usize,
    ) -> Result<crate::symmetric::memory::Credit> {
        self.activity_credit
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ReferenceActivityPreparationAbsent,
            )))?
            .split(bytes)
    }
    pub(crate) fn prepare_close(
        &mut self,
        participants: crate::managed::CloseParticipants,
    ) -> Result<()> {
        if self.close.is_some() || participants.remaining() != self.remaining {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ForeignOrExhaustedReferenceReservation,
            )));
        }
        self.close = Some(participants);
        Ok(())
    }
    /// Known creators already carry their creation's close participation.
    /// This lifetime only notifies reference waiters when it is released.
    pub(crate) fn known_reference_lifetime(&self) -> ReferenceLifetime {
        ReferenceLifetime {
            wake: self.wake.clone(),
            _close: None,
        }
    }

    pub(crate) fn reference_lifetime_for(
        &mut self,
        creator: &crate::managed::ObjectCreator,
    ) -> Result<ReferenceLifetime> {
        let unknown = matches!(
            creator,
            crate::managed::ObjectCreator::UnknownSessionCreator
                | crate::managed::ObjectCreator::UnknownPersistence
        );
        let close = if unknown {
            Some(
                self.close
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                        crate::ReferenceRegistryRejection::UnknownCreatorCapacityNotPrepared,
                    )))?
                    .take()?,
            )
        } else {
            None
        };
        Ok(ReferenceLifetime {
            wake: self.wake.clone(),
            _close: close,
        })
    }

    pub fn insert(&mut self, registry: &Registry<T>, value: &Arc<T>) -> Result<()> {
        if !Arc::ptr_eq(&self.registry, &registry.0) || self.remaining == 0 {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ForeignOrExhaustedReferenceReservation,
            )));
        }
        let mut state = self.registry.lock().map_err(|_| Error::Poisoned)?;
        if state.broken || state.reserved == 0 || state.items.len() == state.items.capacity() {
            state.broken = true;
            return Err(Error::Poisoned);
        }
        state.items.push(Arc::downgrade(value));
        state.reserved -= 1;
        self.remaining -= 1;
        Ok(())
    }
}
impl<T> Drop for Reservation<T> {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(remaining) = state.reserved.checked_sub(self.remaining) {
            state.reserved = remaining;
        } else {
            state.broken = true;
        }
        drop(state);
        self.wake.notify();
    }
}

mod activity;
