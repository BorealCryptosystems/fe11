// SPDX-License-Identifier: Apache-2.0
//! Inline session coordination for guard-free resource preparation.
//!
//! This mutex is a leaf: only fixed-size metadata is touched while it is held.
//! Native calls, resource destruction, other locks and notifications belong to
//! the caller after it releases the leaf. Atomic mirrors route a waiter back to
//! session possession; they never authorize use of a native handle or buffer.
use crate::{Error, Result};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
    Mutex,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    ticket: u64,
    revision: u64,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
enum Lifecycle {
    #[default]
    Vacant,
    Live,
    Retired,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResourceCause {
    Busy(crate::BusyReason),
    Limit {
        resource: crate::ResourceKind,
        requested: usize,
        limit: usize,
    },
    Deadline,
    Cancelled,
    Rejected(crate::RejectionReason),
}
impl ResourceCause {
    pub(super) fn from_error(error: &Error) -> Option<Self> {
        match error {
            Error::Busy(reason) => Some(Self::Busy(*reason)),
            Error::ResourceLimitExceeded {
                resource,
                requested,
                limit,
            } => Some(Self::Limit {
                resource: *resource,
                requested: *requested,
                limit: *limit,
            }),
            Error::AdmissionDeadline => Some(Self::Deadline),
            Error::AdmissionCancelled => Some(Self::Cancelled),
            Error::Rejected(reason) => Some(Self::Rejected(*reason)),
            _ => None,
        }
    }
}

// These effects describe the two actual resource-wait failure policies.
#[derive(Clone, Copy)]
pub(super) enum Effect {
    RemoveStateIo,
    PreserveOwner,
}
impl Effect {
    fn index(self) -> usize {
        match self {
            Self::RemoveStateIo => 0,
            Self::PreserveOwner => 1,
        }
    }
}

#[derive(Default)]
struct State {
    ticket: u64,
    revision: u64,
    lifecycle: Lifecycle,
    waiters: usize,
    effects: [Option<ResourceCause>; 2],
}
impl State {
    fn stamp(&self) -> Stamp {
        Stamp {
            ticket: self.ticket,
            revision: self.revision,
        }
    }
    fn current(&self, stamp: Stamp) -> bool {
        self.lifecycle == Lifecycle::Live && self.stamp() == stamp
    }
}

pub(super) struct Effects {
    pub(super) stamp: Stamp,
    pub(super) causes: [Option<ResourceCause>; 2],
}

/// Fixed coordination metadata, owned by SessionEntry rather than an operation
/// allocation. No Arc, native pointer, key, credit or user value lives here.
#[derive(Default)]
pub(crate) struct Progress {
    state: Mutex<State>,
    ticket: AtomicU64,
    revision: AtomicU64,
    lifecycle: AtomicU8,
    cleanup: AtomicBool,
}
impl Progress {
    fn mirror(&self, state: &State) {
        self.ticket.store(state.ticket, Ordering::Release);
        self.revision.store(state.revision, Ordering::Release);
        self.lifecycle
            .store(state.lifecycle as u8, Ordering::Release);
        self.cleanup
            .store(state.effects.iter().any(Option::is_some), Ordering::Release);
    }

    pub(super) fn install(&self, ticket: u64, occupation: &AtomicU64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if ticket == 0 || state.lifecycle == Lifecycle::Live {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationProgressIdentity,
            )));
        }
        *state = State {
            ticket,
            lifecycle: Lifecycle::Live,
            ..State::default()
        };
        self.mirror(&state);
        occupation.store(ticket, Ordering::Release);
        Ok(())
    }

    /// Called with session possession and the resident body locked. Zero
    /// waiters excludes a late unregister effect; both effect slots must also
    /// be empty. This observation neither claims progress nor consumes effects.
    pub(super) fn replacement_ready(&self, ticket: u64) -> Result<bool> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(ticket != 0
            && state.ticket == ticket
            && state.lifecycle == Lifecycle::Live
            && state.waiters == 0
            && state.effects.iter().all(Option::is_none))
    }

    pub(super) fn replace(&self, ticket: u64, occupation: &AtomicU64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if ticket == 0 || state.lifecycle != Lifecycle::Live || ticket == state.ticket {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationProgressIdentity,
            )));
        }
        *state = State {
            ticket,
            lifecycle: Lifecycle::Live,
            ..State::default()
        };
        self.mirror(&state);
        occupation.store(ticket, Ordering::Release);
        Ok(())
    }

    pub(super) fn retire(&self, occupation: &AtomicU64) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        // Retirement always remains possible at the maximum revision. Preserve
        // the exact last ticket for bounded normalization, without an ABA history.
        if state.lifecycle == Lifecycle::Live {
            state.lifecycle = Lifecycle::Retired;
            state.waiters = 0;
            state.effects = [None; 2];
        }
        self.mirror(&state);
        occupation.store(0, Ordering::Release);
        Ok(())
    }

    pub(super) fn retired(&self, ticket: u64) -> Result<bool> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(ticket != 0 && state.lifecycle == Lifecycle::Retired && state.ticket == ticket)
    }

    /// Claim once immediately before the first engaged mutation/native call of
    /// a segment. Pure probes do not call this. Overflow precedes every effect.
    pub(super) fn claim(&self, ticket: u64) -> Result<Stamp> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.lifecycle != Lifecycle::Live || state.ticket != ticket {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        let revision = state.revision.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationProgressRevisionExhausted,
            ),
        ))?;
        state.revision = revision;
        state.waiters = 0;
        state.effects = [None; 2];
        self.mirror(&state);
        Ok(state.stamp())
    }

    /// Observe the revision while the caller possesses the session and owner.
    /// This watch neither registers a waiter nor installs failure effects.
    pub(crate) fn observe_revision(&self, ticket: u64) -> Result<Stamp> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.lifecycle != Lifecycle::Live || state.ticket != ticket {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        Ok(state.stamp())
    }

    pub(super) fn register(&self, ticket: u64) -> Result<Stamp> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.lifecycle != Lifecycle::Live || state.ticket != ticket {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        state.waiters = state.waiters.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationWaiterCount,
            ),
        ))?;
        Ok(state.stamp())
    }

    /// Merge failure and unregister as one transaction. An old registration
    /// never decrements a newer revision's count. The bool requests notification
    /// outside this leaf; it is not permission to execute a cleanup effect.
    pub(super) fn unregister(
        &self,
        stamp: Stamp,
        failure: Option<(Effect, ResourceCause)>,
    ) -> Result<bool> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if !state.current(stamp) {
            return Ok(false);
        }
        let waiters = state.waiters.checked_sub(1).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationWaiterCount,
            ),
        ))?;
        let mut notify = false;
        if let Some((effect, cause)) = failure {
            let slot = &mut state.effects[effect.index()];
            if slot.is_none() {
                *slot = Some(cause);
                notify = true;
            }
        }
        state.waiters = waiters;
        notify |= waiters == 0 && state.effects.iter().any(Option::is_some);
        self.mirror(&state);
        Ok(notify)
    }

    pub(super) fn effects(&self, ticket: u64) -> Result<Option<Effects>> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok((state.lifecycle == Lifecycle::Live
            && state.ticket == ticket
            && state.waiters == 0
            && state.effects.iter().any(Option::is_some))
        .then_some(Effects {
            stamp: state.stamp(),
            causes: state.effects,
        }))
    }

    pub(super) fn acknowledge(&self, effects: &Effects, effect: Effect) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.current(effects.stamp) {
            let index = effect.index();
            if state.effects[index] == effects.causes[index] {
                state.effects[index] = None;
            }
            self.mirror(&state);
        }
        Ok(())
    }

    pub(crate) fn changed(&self, stamp: Stamp) -> bool {
        self.lifecycle.load(Ordering::Acquire) != Lifecycle::Live as u8
            || self.ticket.load(Ordering::Acquire) != stamp.ticket
            || self.revision.load(Ordering::Acquire) != stamp.revision
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }

    pub(crate) fn cleanup_hint(&self) -> bool {
        self.cleanup.load(Ordering::Acquire)
    }
}

/// A registration retains neither an operation Arc nor native/source buffers.
/// Declare it before access guards so abandonment runs after their release.
/// Prepared at the public resource-wait root, outside all source guards.
/// The five error leaves cover the initiating failure, cleanup and a possible
/// unregister failure. Their credit stays at that root after composition;
/// returning an error between preparation helpers is not a public transfer.
pub(super) struct FailureDiagnostics {
    primary: crate::error::PreparedCleanupDiagnostic,
    secondary: crate::error::PreparedFailurePair,
}
impl FailureDiagnostics {
    pub(super) const fn allocation_bytes() -> usize {
        crate::error::PreparedCleanupDiagnostic::allocation_bytes()
            + crate::error::PreparedFailurePair::allocation_bytes()
    }

    pub(super) fn prepare(session: &crate::Session, ticket: u64) -> Result<Self> {
        Self::prepare_in(session, &session.inner.symmetric_budget, ticket)
    }

    pub(super) fn prepare_in(
        session: &crate::Session,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        ticket: u64,
    ) -> Result<Self> {
        use crate::symmetric::memory::ControlledReservation;
        if !budget.same_account(&session.inner.symmetric_budget) {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignDiagnosticPreparationBudget,
            )));
        }
        let bytes = Self::allocation_bytes() + budget.observation_overhead();
        let policy = crate::admission_wait::current();
        let mut prepaid = match budget.reserve_controlled_retaining(
            bytes,
            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
            &policy,
            || {
                super::preparation::context(session)?;
                if session.entry.advanced_operation.load(Ordering::Acquire) != ticket {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StaleOperationTicket,
                    )));
                }
                Ok(None::<()>)
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(()) => {
                unreachable!("diagnostic admission has no redirect")
            }
        };
        // Establish attribution before detaching either set of leaves. Later
        // private candidates use this account, so they cannot wait for the
        // diagnostics that only their own public invocation can release.
        prepaid.observation_budget()?;
        Self::from_prepaid(&mut prepaid)
    }

    /// A poll's envelope is exclusive to that public call, while the admission
    /// owner is shared between polls. Charge these leaves globally so a peer's
    /// envelope remains releasable pressure. The response preparer must include
    /// this call's allocation_bytes() explicitly in its intrinsic source bound.
    pub(super) fn prepare_for_poll(
        session: &crate::Session,
        owner: &std::sync::Arc<crate::symmetric::memory::Budget>,
        retained_bytes: usize,
        ticket: u64,
        admission: crate::session::CleanupAdmission,
    ) -> Result<Self> {
        use crate::symmetric::memory::ControlledReservation;
        let budget = &session.inner.symmetric_budget;
        if !owner.same_account(budget) {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignDiagnosticPreparationBudget,
            )));
        }
        let bytes = Self::allocation_bytes();
        let intrinsic = bytes.checked_add(retained_bytes).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::PollDiagnosticByteCount,
            ),
        ))?;
        let intrinsic = crate::session::lifecycle_diagnostics::Store::including(intrinsic)?;
        owner.check_request(intrinsic)?;
        let policy = crate::admission_wait::current();
        let mut prepaid = match budget.reserve_controlled(
            bytes,
            &policy,
            || {
                owner.check_request(intrinsic)?;
                crate::session::activity::context_admitted(session, admission)?;
                if session.entry.advanced_operation.load(Ordering::Acquire) != ticket {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StaleOperationTicket,
                    )));
                }
                Ok(None::<()>)
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(()) => {
                unreachable!("poll diagnostic admission has no redirect")
            }
        };
        Self::from_prepaid(&mut prepaid)
    }

    /// The caller accounts for this owner through either a common private
    /// account, a consumed-source footprint, or explicit retained-byte admission
    /// before later reservations.
    /// A facade keeps the resulting owner across its inputs and final return.
    pub(super) fn from_prepaid(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        Ok(Self {
            primary: crate::error::PreparedCleanupDiagnostic::prepare(prepaid)?,
            secondary: crate::error::PreparedFailurePair::prepare(prepaid)?,
        })
    }

    pub(super) fn budget(&self) -> &std::sync::Arc<crate::symmetric::memory::Budget> {
        self.secondary.budget()
    }
}

impl crate::symmetric::memory::RetainedStorage for FailureDiagnostics {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        crate::symmetric::memory::RetainedStorage::retain_credits(&self.primary, retained)?;
        crate::symmetric::memory::RetainedStorage::retain_credits(&self.secondary, retained)
    }
}

pub(super) struct Waiter<'a> {
    session: &'a crate::Session,
    stamp: Stamp,
    effect: Effect,
    registered: bool,
}
impl<'a> Waiter<'a> {
    pub(super) fn new(session: &'a crate::Session, ticket: u64, effect: Effect) -> Result<Self> {
        Ok(Self {
            session,
            stamp: session.entry.advanced_progress.register(ticket)?,
            effect,
            registered: true,
        })
    }
    pub(super) fn changed(&self) -> bool {
        self.session.entry.advanced_progress.changed(self.stamp)
    }
    fn unregister(&mut self, cause: Option<ResourceCause>) -> Result<()> {
        if !self.registered {
            return Ok(());
        }
        let result = self
            .session
            .entry
            .advanced_progress
            .unregister(self.stamp, cause.map(|cause| (self.effect, cause)));
        // Even a poisoned leaf is not retried by this registration's Drop.
        // Its marker is retained and the integrity error remains observable.
        self.registered = false;
        if result? {
            self.session
                .snapshot
                .domain
                .needs_local_cleanup
                .store(true, Ordering::Release);
            self.session.inner.symmetric_budget.notify_progress();
            self.session.snapshot.domain.activity.notify();
            self.session.entry.operation.notify();
        }
        Ok(())
    }
    pub(super) fn succeed(&mut self) -> Result<()> {
        self.unregister(None)
    }

    fn apply_failure(&mut self, cause: ResourceCause) -> FailureCleanup {
        let session = self.session;
        // Attempt possession while still registered. Merge+unregister only
        // after acquiring all gates, then apply effects under that same proof.
        let attempt = session.try_local_cleanup(|proof| {
            self.unregister(Some(cause))?;
            proof.maintain()
        });
        match attempt {
            Ok(Some(())) => FailureCleanup::Complete,
            Ok(None) => match self.unregister(Some(cause)) {
                Ok(()) => FailureCleanup::Complete,
                Err(error) => FailureCleanup::Failed(error),
            },
            Err(local) => match self.unregister(Some(cause)) {
                Ok(()) => FailureCleanup::Failed(local),
                Err(unregister) => FailureCleanup::Both { local, unregister },
            },
        }
    }

    /// Error composition needs no new allocation or admission. A caller
    /// may consume this envelope only on its terminal error return; retries use
    /// succeed and leave both slots intact for the same public invocation.
    pub(super) fn fail_prepared(
        &mut self,
        error: Error,
        prepared: &mut FailureDiagnostics,
    ) -> Error {
        let cause = ResourceCause::from_error(&error).unwrap_or(ResourceCause::Cancelled);
        let diagnostic = prepared.primary.take(error);
        let failure = match self.apply_failure(cause) {
            FailureCleanup::Complete => None,
            FailureCleanup::Failed(error) => Some(error),
            FailureCleanup::Both { local, unregister } => {
                Some(prepared.secondary.finish(local, unregister))
            }
        };
        diagnostic.finish_sequence(failure)
    }
}

/// Error composition is separate from the cleanup attempt. During unwinding
/// there is no error recipient, so Drop must not allocate discarded wrappers.
enum FailureCleanup {
    Complete,
    Failed(Error),
    Both { local: Error, unregister: Error },
}
impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        if self.registered {
            // No Result channel during unwind. The bounded marker is retained
            // if one nonblocking local cleanup attempt cannot complete.
            let _ = self.apply_failure(ResourceCause::Cancelled);
        }
    }
}
