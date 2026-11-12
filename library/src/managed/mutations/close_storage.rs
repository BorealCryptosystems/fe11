// SPDX-License-Identifier: Apache-2.0
//! Resident close workspace. Capacity is paid at participant admission, not
//! while a closing writer excludes the operations that could release credit.
use super::Destination;
use crate::atomic_update::AtomicUpdate;
use crate::{
    admission_wait::{Attempt, Wake},
    module::SlotDomain,
    registry::{Activity, WritePermit},
    symmetric::memory::{Budget, Credit},
    Error, ResourceAdmission, Result,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock, Weak,
};

pub(super) struct CloseDestination {
    pub key: Destination,
    pub activity: Arc<Activity>,
    pub held: bool,
}
pub(super) struct CloseBuffers {
    pub destinations: Vec<CloseDestination>,
    pub resources: Vec<Arc<Activity>>,
    pub permits: Vec<WritePermit>,
    pub destination_cursor: usize,
    pub resource_cursor: usize,
    _credit: Option<Credit>,
}
impl CloseBuffers {
    fn empty() -> Self {
        Self {
            destinations: Vec::new(),
            resources: Vec::new(),
            permits: Vec::new(),
            destination_cursor: 0,
            resource_cursor: 0,
            _credit: None,
        }
    }
    fn fits(&self, count: usize, unknown: bool) -> bool {
        self.resources.capacity() >= count
            && (unknown || self.destinations.capacity() >= count)
            && count
                .checked_mul(if unknown { 1 } else { 2 })
                .is_some_and(|permits| self.permits.capacity() >= permits)
    }
    fn bytes(destinations: usize, resources: usize, permits: usize) -> Result<usize> {
        [
            (destinations, std::mem::size_of::<CloseDestination>()),
            (resources, std::mem::size_of::<Arc<Activity>>()),
            (permits, std::mem::size_of::<WritePermit>()),
        ]
        .into_iter()
        .try_fold(0usize, |total, (count, width)| {
            count
                .checked_mul(width)
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CoordinationVectorStorageAccounting,
                )))
        })
    }
    fn requested_bytes(count: usize, unknown: bool) -> Result<usize> {
        Self::bytes(
            if unknown { 0 } else { count },
            count,
            count
                .checked_mul(if unknown { 1 } else { 2 })
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorActivityCount,
                )))?,
        )
    }

    fn allocate(count: usize, unknown: bool) -> Result<Self> {
        Self::requested_bytes(count, unknown)?;
        let mut candidate = Self::empty();
        candidate
            .destinations
            .try_reserve_exact(if unknown { 0 } else { count })
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorSnapshotAllocation,
                ))
            })?;
        candidate.resources.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorSnapshotAllocation,
            ))
        })?;
        candidate
            .permits
            .try_reserve_exact(count.checked_mul(if unknown { 1 } else { 2 }).ok_or(
                Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorActivityCount,
                )),
            )?)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorSnapshotAllocation,
                ))
            })?;
        Ok(candidate)
    }

    fn allocated_bytes(&self) -> Result<usize> {
        Self::bytes(
            self.destinations.capacity(),
            self.resources.capacity(),
            self.permits.capacity(),
        )
    }
    pub(super) fn clear(&mut self) {
        self.permits.clear();
        self.destinations.clear();
        self.resources.clear();
        self.destination_cursor = 0;
        self.resource_cursor = 0;
    }
    pub(super) fn destination(
        &mut self,
        key: &Destination,
        activity: &Arc<Activity>,
    ) -> Result<()> {
        if self.destinations.len() == self.destinations.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorCloseCapacityNotPrepared,
            )));
        }
        self.destinations.push(CloseDestination {
            key: key.clone(),
            activity: activity.clone(),
            held: false,
        });
        Ok(())
    }
    pub(super) fn resource(&mut self, activity: &Arc<Activity>) -> Result<()> {
        if self.resources.len() == self.resources.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorCloseCapacityNotPrepared,
            )));
        }
        self.resources.push(activity.clone());
        Ok(())
    }
    pub(super) fn sort(&mut self) {
        self.destinations.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        self.destinations.dedup_by(|a, b| a.key == b.key);
        // Every compared pointer is anchored by a live Arc in this loan.
        self.resources
            .sort_unstable_by_key(|a| Arc::as_ptr(a) as usize);
        self.resources.dedup_by(|a, b| Arc::ptr_eq(a, b));
    }
}

enum Ownership {
    Available(CloseBuffers),
    Loaned(u64),
}
struct State {
    ownership: Ownership,
    serial: u64,
}

/// No Entry/Snapshot is retained in this owner, preventing a close-state cycle.
pub(crate) struct CloseResident {
    state: Mutex<State>,
    participants: AtomicUsize,
    revision: AtomicU64,
    byte_wake: OnceLock<Weak<Wake>>,
    invalid: AtomicBool,
    loaned: AtomicBool,
    unknown: bool,
    domain: Weak<SlotDomain>,
}
impl CloseResident {
    pub(crate) fn new(domain: &Arc<SlotDomain>, unknown: bool) -> Arc<Self> {
        Self::with_domain(Arc::downgrade(domain), unknown)
    }

    fn with_domain(domain: Weak<SlotDomain>, unknown: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                ownership: Ownership::Available(CloseBuffers::empty()),
                serial: 0,
            }),
            participants: AtomicUsize::new(0),
            revision: AtomicU64::new(0),
            byte_wake: OnceLock::new(),
            invalid: AtomicBool::new(false),
            loaned: AtomicBool::new(false),
            unknown,
            domain,
        })
    }
    /// Obtain a capacity recipe without retaining any unpublished byte credit.
    /// A close borrower is awaited here, before allocating the sibling graph.
    pub(super) fn plan(
        self: &Arc<Self>,
        count: usize,
        budget: &Arc<Budget>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<ClosePlan> {
        let wake = budget.admission_wake();
        let registered = self.byte_wake.get_or_init(|| Arc::downgrade(&wake));
        if !registered.ptr_eq(&Arc::downgrade(&wake)) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorCloseBudgetOwner,
            )));
        }
        loop {
            // Resource return and context invalidation use this same channel.
            // Checking the predicate and sleeping under its Wake prevents a
            // close/logout notification from being lost between those actions.
            wake.acquire(admission, || {
                before()?;
                self.check()?;
                Ok(if self.loaned.load(Ordering::Acquire) {
                    Attempt::Occupied(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::SessionClosePending,
                    ))
                } else {
                    Attempt::Acquired(())
                })
            })?;
            let state = self.state.lock().map_err(|_| Error::Poisoned)?;
            let Ownership::Available(current) = &state.ownership else {
                // A borrower won the race after readiness. Retry the same
                // absolute policy, still without any new allocation/credit.
                continue;
            };
            let participants = self.participants.load(Ordering::Acquire);
            let total = participants.checked_add(count).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorParticipantCount,
                ),
            ))?;
            return Ok(ClosePlan {
                owner: self.clone(),
                count,
                participants,
                revision: state.serial,
                capacity: (!current.fits(total, self.unknown)).then_some(total),
            });
        }
    }

    fn notify_bytes(&self) {
        if let Some(wake) = self.byte_wake.get().and_then(Weak::upgrade) {
            wake.notify();
        }
    }

    /// Admit close capacity and reference activities as one unpublished graph.
    /// No participant or sibling byte credit survives a wait or a sizing race.
    /// The caller holds a reference quota, but no session or native guard.
    pub(crate) fn reserve_reference_resources(
        self: &Arc<Self>,
        count: usize,
        activity_bytes: usize,
        budget: &Arc<Budget>,
        admission: &ResourceAdmission,
        before: impl FnMut() -> Result<()>,
        check_additional: impl Fn(usize) -> Result<()>,
    ) -> Result<(CloseParticipants, Credit)> {
        let (participants, activities, _empty) = self.reserve_reference_and_payload(
            count,
            activity_bytes,
            0,
            budget,
            admission,
            before,
            check_additional,
        )?;
        Ok((participants, activities))
    }

    /// Reserve private output storage together with the close/Activity owners.
    /// No caller may retain the first credit while waiting for the second.
    pub(crate) fn reserve_reference_and_payload(
        self: &Arc<Self>,
        count: usize,
        activity_bytes: usize,
        payload_bytes: usize,
        budget: &Arc<Budget>,
        admission: &ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
        check_additional: impl Fn(usize) -> Result<()>,
    ) -> Result<(CloseParticipants, Credit, Credit)> {
        use crate::symmetric::memory::ControlledReservation;

        'plan: loop {
            let plan = self.plan(count, budget, admission, &mut before)?;
            let mut required = plan
                .requested_bytes()?
                .checked_add(activity_bytes)
                .and_then(|n| n.checked_add(payload_bytes))
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::ReferenceCloseStorageAccounting,
                )))?;
            loop {
                let mut prepaid = match budget.reserve_controlled(
                    required,
                    admission,
                    || {
                        before()?;
                        if !plan.current()? {
                            return Ok(Some(()));
                        }
                        // Pure overlap check, under Wake, before any possible
                        // wait. Re-evaluate after actual-capacity replanning.
                        check_additional(required)?;
                        Ok(None)
                    },
                    || Ok((!plan.current()?).then_some(())),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => continue 'plan,
                };
                let allocation = plan.allocate()?;
                let actual = allocation
                    .allocated_bytes()?
                    .checked_add(activity_bytes)
                    .and_then(|n| n.checked_add(payload_bytes))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                        crate::ObjectCleanupRejection::ReferenceCloseStorageAccounting,
                    )))?;
                if actual > required {
                    drop(allocation);
                    drop(prepaid);
                    required = actual;
                    continue;
                }
                before()?;
                let prepared = allocation.bind(&mut prepaid)?;
                let activities = prepaid.split(activity_bytes)?;
                let payload = prepaid.split(payload_bytes)?;
                let Some(participants) = plan.commit(prepared)? else {
                    drop(activities);
                    drop(payload);
                    drop(prepaid);
                    continue 'plan;
                };
                return Ok((participants, activities, payload));
            }
        }
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.invalid.load(Ordering::Acquire) {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn release(&self, count: usize) {
        if self
            .participants
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_sub(count)
            })
            .is_err()
        {
            self.invalid.store(true, Ordering::Release);
        }
        // A participant may die under another owner's guards. This notification
        // takes no catalogue lock and reaches only the slot's leaf wake channel.
        if count != 0 {
            self.notify_bytes();
            if let Some(domain) = self.domain.upgrade() {
                domain.activity.notify();
            }
        }
    }
    pub(super) fn borrow(self: &Arc<Self>) -> Result<CloseLoan> {
        self.check()?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if matches!(state.ownership, Ownership::Loaned(_)) {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionClosePending,
            )));
        }
        let serial = state.serial.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorCloseTicketExhausted,
            ),
        ))?;
        let Ownership::Available(buffers) =
            std::mem::replace(&mut state.ownership, Ownership::Loaned(serial))
        else {
            unreachable!()
        };
        state.serial = serial;
        self.revision.store(serial, Ordering::Release);
        self.loaned.store(true, Ordering::Release);
        drop(state);
        self.notify_bytes();
        Ok(CloseLoan {
            owner: self.clone(),
            serial,
            buffers: Some(buffers),
            notify_pending: false,
        })
    }
}

/// Snapshot used solely for sizing. It grants no close or session authority.
pub(super) struct ClosePlan {
    owner: Arc<CloseResident>,
    count: usize,
    participants: usize,
    revision: u64,
    capacity: Option<usize>,
}

impl ClosePlan {
    /// Pure atomic predicate, suitable for the byte-budget wake lock.
    pub(super) fn current(&self) -> Result<bool> {
        self.owner.check()?;
        Ok(!self.owner.loaned.load(Ordering::Acquire)
            && self.owner.participants.load(Ordering::Acquire) == self.participants
            && self.owner.revision.load(Ordering::Acquire) == self.revision)
    }

    pub(super) fn requested_bytes(&self) -> Result<usize> {
        self.capacity
            .map(|count| CloseBuffers::requested_bytes(count, self.owner.unknown))
            .transpose()
            .map(|bytes| bytes.unwrap_or(0))
    }

    pub(super) fn allocate(&self) -> Result<CloseAllocation> {
        Ok(CloseAllocation {
            owner: self.owner.clone(),
            buffers: self
                .capacity
                .map(|count| CloseBuffers::allocate(count, self.owner.unknown))
                .transpose()?,
        })
    }

    /// Consume only after all sibling resources have been admitted. A race
    /// returns None and discards the candidate outside the resident mutex.
    pub(super) fn commit(&self, mut prepared: ClosePrepared) -> Result<Option<CloseParticipants>> {
        if !Arc::ptr_eq(&self.owner, &prepared.owner) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::ForeignCreatorClosePreparation,
            )));
        }
        let retired;
        let mut state = self.owner.state.lock().map_err(|_| Error::Poisoned)?;
        self.owner.check()?;
        let total = self
            .owner
            .participants
            .load(Ordering::Acquire)
            .checked_add(self.count)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorParticipantCount,
            )))?;
        let Ownership::Available(current) = &state.ownership else {
            return Ok(None);
        };
        let replace = !current.fits(total, self.owner.unknown);
        if replace
            && !prepared
                .buffers
                .as_ref()
                .is_some_and(|candidate| candidate.fits(total, self.owner.unknown))
        {
            return Ok(None);
        }
        let revision = if replace {
            Some(state.serial.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorCloseTicketExhausted,
                ),
            ))?)
        } else {
            None
        };
        // Other increments serialize on state; concurrent drops only reduce
        // the count, so the capacity checked above remains sufficient.
        self.owner
            .participants
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(self.count)
            })
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectCleanup(
                    crate::ObjectCleanupRejection::CreatorParticipantCount,
                ))
            })?;
        if let Some(revision) = revision {
            let Ownership::Available(current) = &mut state.ownership else {
                unreachable!()
            };
            retired = Some(std::mem::replace(
                current,
                prepared.buffers.take().expect("capacity checked"),
            ));
            state.serial = revision;
            self.owner.revision.store(revision, Ordering::Release);
        } else {
            retired = None;
        }
        drop(state);
        drop(retired);
        drop(prepared);
        self.owner.notify_bytes();
        Ok(Some(CloseParticipants {
            owner: self.owner.clone(),
            remaining: self.count,
        }))
    }
}

pub(super) struct CloseAllocation {
    owner: Arc<CloseResident>,
    buffers: Option<CloseBuffers>,
}
pub(super) struct ClosePrepared {
    owner: Arc<CloseResident>,
    buffers: Option<CloseBuffers>,
}
impl CloseAllocation {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.buffers
            .as_ref()
            .map(CloseBuffers::allocated_bytes)
            .transpose()
            .map(|bytes| bytes.unwrap_or(0))
    }
    pub(super) fn bind(mut self, prepaid: &mut Credit) -> Result<ClosePrepared> {
        let wake = prepaid.budget().admission_wake();
        if !self
            .owner
            .byte_wake
            .get()
            .is_some_and(|registered| registered.ptr_eq(&Arc::downgrade(&wake)))
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::ForeignCreatorCloseCredit,
            )));
        }
        if let Some(buffers) = &mut self.buffers {
            buffers._credit = Some(prepaid.split(buffers.allocated_bytes()?)?);
        }
        Ok(ClosePrepared {
            owner: self.owner,
            buffers: self.buffers,
        })
    }
}

/// Reserved and published participants share one counter. Splitting transfers
/// ownership only; it does not count clones or accumulate historical births.
pub(crate) struct CloseParticipants {
    owner: Arc<CloseResident>,
    remaining: usize,
}
impl CloseParticipants {
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }
    pub(crate) fn split(&mut self, count: usize) -> Result<Self> {
        self.owner.check()?;
        self.remaining = self.remaining.checked_sub(count).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorParticipantReservationExhausted,
            ),
        ))?;
        Ok(Self {
            owner: self.owner.clone(),
            remaining: count,
        })
    }
    pub(crate) fn take(&mut self) -> Result<CloseParticipant> {
        self.owner.check()?;
        self.remaining = self.remaining.checked_sub(1).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectCleanup(
                crate::ObjectCleanupRejection::CreatorParticipantReservationExhausted,
            ),
        ))?;
        Ok(CloseParticipant {
            owner: self.owner.clone(),
        })
    }
}
impl Drop for CloseParticipants {
    fn drop(&mut self) {
        self.owner.release(self.remaining);
    }
}
pub(crate) struct CloseParticipant {
    owner: Arc<CloseResident>,
}
impl Drop for CloseParticipant {
    fn drop(&mut self) {
        self.owner.release(1);
    }
}

pub(super) struct CloseLoan {
    owner: Arc<CloseResident>,
    serial: u64,
    pub buffers: Option<CloseBuffers>,
    notify_pending: bool,
}
impl CloseLoan {
    pub(super) fn buffers(&self) -> &CloseBuffers {
        self.buffers.as_ref().expect("live close loan")
    }
    pub(super) fn buffers_mut(&mut self) -> &mut CloseBuffers {
        self.buffers.as_mut().expect("live close loan")
    }
    /// Clear anchors before entering the catalogue section used to return an
    /// unknown loan and its barrier together. Available vectors never hold Arcs.
    pub(super) fn clear(&mut self) {
        self.buffers_mut().clear();
    }
    pub(super) fn return_empty(&mut self) {
        let Some(buffers) = self.buffers.take() else {
            return;
        };
        if !buffers.destinations.is_empty()
            || !buffers.resources.is_empty()
            || !buffers.permits.is_empty()
        {
            self.owner.invalid.store(true, Ordering::Release);
            self.notify_pending = true;
            // Dropping live anchors here would violate the caller's lock order.
            self.buffers = Some(buffers);
            return;
        }
        let mut state = self.owner.state.lock().unwrap_or_else(|p| p.into_inner());
        if !matches!(state.ownership, Ownership::Loaned(serial) if serial == self.serial) {
            self.owner.invalid.store(true, Ordering::Release);
            self.notify_pending = true;
            drop(state);
            drop(buffers);
            return;
        }
        state.ownership = Ownership::Available(buffers);
        self.owner.loaned.store(false, Ordering::Release);
        drop(state);
        self.notify_pending = true;
    }
}
impl Drop for CloseLoan {
    fn drop(&mut self) {
        if self.buffers.is_some() {
            self.clear();
            self.return_empty();
        }
        if self.notify_pending {
            self.owner.notify_bytes();
        }
    }
}
