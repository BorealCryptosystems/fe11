// SPDX-License-Identifier: Apache-2.0
//! One native waiter, independent image lifetime, and coordinated finalization.
use super::FileIdentity;
use crate::{module::Inner, Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Open,
    Finalizing,
    FinalizationIssued,
    FinalizationPending,
    FinalizationPublicationFailed(fe11_sys::CK_RV),
    FinalizationRefused(fe11_sys::CK_RV),
    Finalized,
    Withdrawn,
}
impl Lifecycle {
    fn admits_events(self) -> bool {
        matches!(self, Self::Open | Self::FinalizationRefused(_))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventMode {
    Poll,
    Blocking,
}

/// Local slot-event/finalization ownership, without a native status query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotEventStatus {
    /// No slot-event call is reserved.
    Idle,
    /// One nonblocking call is reserved or in progress.
    PollIssued,
    /// One blocking call is reserved or in progress; not proof of provider entry.
    BlockingCallIssued,
    /// Finalization admission is closed; completion has not been published.
    Closing,
    /// Finalization succeeded and no waiter retains the identity reservation.
    Finalized,
    /// Finalization succeeded; an outstanding waiter still retains the image.
    FinalizedImageRetained,
    /// A dispatched waiter or finalization has no proven synchronous completion.
    CompletionUnproven,
    /// Finalization admission was withdrawn or its local publication failed.
    FinalizationUncertain,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Waiter {
    Idle,
    Issued(EventMode),
    Uncertain,
}

struct State {
    lifecycle: Lifecycle,
    waiter: Waiter,
    // Only a finalization dispatched during this wait can explain its return.
    // A refused finalization from an earlier wait is not such evidence.
    waiter_saw_finalization: bool,
    registered: bool,
}
impl State {
    /// Retire only this lease's reserved mode after a recorded native return.
    /// This local transition never admits or invokes a new native operation.
    fn returned_waiter(&mut self, mode: EventMode) -> Result<bool> {
        if self.waiter != Waiter::Issued(mode) {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SlotEventOwnerState,
            )));
        }
        let finalization_issued = self.waiter_saw_finalization;
        self.waiter = Waiter::Idle;
        self.waiter_saw_finalization = false;
        Ok(finalization_issued)
    }
}

/// The identity reservation survives successful Finalize while a blocking call
/// is returning. No registry mutex is held while either native function runs.
pub(crate) struct EventRegistry {
    successor_published: AtomicBool,
    // Updated only under State's mutex, alongside waiter admission. Keep this
    // source selector separate from the existing lifecycle transition model.
    source: std::sync::atomic::AtomicU64,
    dispatch: Option<Arc<super::dispatch::Dispatch>>,
    identity: Option<FileIdentity>,
    image_identity: Vec<super::image_reservation::Lease>,
    state: Mutex<State>,
    // Admission observers must not acquire the registry mutex while holding
    // the byte-budget Wake. These mirrors only reject preparation; reserve
    // still validates the authoritative state before granting a lease.
    preparation_closed: AtomicBool,
    preparation_active: AtomicBool,
    // Irreversible refusal mirror for Wake predicates. The waiter under State
    // remains the owner; this flag is never a completion or release proof.
    completion_unproven: AtomicBool,
    admission: OnceLock<Weak<crate::admission_wait::ContextWakes>>,
}

impl EventRegistry {
    pub(super) fn with_dispatch(
        identity: Option<FileIdentity>,
        image_identity: Vec<super::image_reservation::Lease>,
        dispatch: Option<Arc<super::dispatch::Dispatch>>,
    ) -> Self {
        Self {
            successor_published: AtomicBool::new(false),
            source: std::sync::atomic::AtomicU64::new(0),
            dispatch,
            identity,
            image_identity,
            state: Mutex::new(State {
                lifecycle: Lifecycle::Open,
                waiter: Waiter::Idle,
                waiter_saw_finalization: false,
                registered: true,
            }),
            preparation_closed: AtomicBool::new(false),
            preparation_active: AtomicBool::new(false),
            completion_unproven: AtomicBool::new(false),
            admission: OnceLock::new(),
        }
    }

    pub(crate) fn bind_admission(
        &self,
        wake: &Arc<crate::admission_wait::ContextWakes>,
    ) -> Result<()> {
        self.admission.set(Arc::downgrade(wake)).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SlotEventAdmissionAlreadyBound,
            ))
        })
    }
    /// Caller holds the withdrawn runtime's writer and has proved quiescence.
    /// A retirement has no Finalize receipt; image reservation transfer is local.
    pub(crate) fn reserve_successor(&self) -> Result<super::image_reservation::Successor> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if self.successor_published.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::RuntimeSuccessorAlreadyPublished,
            )));
        }
        if matches!(
            state.lifecycle,
            Lifecycle::FinalizationPublicationFailed(fe11_sys::CKR_OK)
        ) {
            // The last waiter can fail local publication after Native recorded
            // success. Reconcile that receipt before transferring ownership.
            self.release_if_complete(&mut state)?;
        }
        if matches!(state.lifecycle, Lifecycle::FinalizationPublicationFailed(_)) {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleIdentityReservationAbsent,
            )));
        }
        if state.waiter != Waiter::Idle
            || matches!(
                state.lifecycle,
                Lifecycle::FinalizationIssued | Lifecycle::FinalizationPending
            )
        {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::RuntimeWaiterOrFinalizationUnresolved,
            )));
        }
        let successor = super::image_reservation::reserve_successor(&self.image_identity)?;
        if state.registered {
            // This file reservation counts only this generation. The image
            // leases already compare generation, so an old Drop cannot erase B.
            if let Some(identity) = self.identity {
                if !super::release_file(identity) {
                    return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::PredecessorFileReservationAbsent,
                    )));
                }
            }
        }
        state.registered = false;
        if state.lifecycle != Lifecycle::Finalized {
            state.lifecycle = Lifecycle::Withdrawn;
        }
        self.preparation_closed.store(true, Ordering::Release);
        Ok(successor)
    }
    pub(crate) fn commit_successor(&self) {
        self.successor_published.store(true, Ordering::Release);
    }

    pub(crate) fn check_preparation(&self) -> Result<()> {
        if self.source.load(Ordering::Acquire) != 0 {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::DifferentSlotEventSourceSelected,
            )));
        }
        if self.preparation_closed.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SlotEventAdmissionClosed,
            )));
        }
        if self.preparation_active.load(Ordering::Acquire) {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SlotEventRequestActive,
            )));
        }
        Ok(())
    }

    pub(crate) fn check_logout_admission(&self) -> Result<()> {
        if self.completion_unproven.load(Ordering::Acquire) {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SlotEventCompletionUnproven,
            )));
        }
        Ok(())
    }

    /// Logout does not free the waiter's image or arguments. A healthy waiter
    /// is compatible in concurrent mode; serialized dispatch keeps its gate.
    pub(crate) fn logout_ready(&self) -> Result<()> {
        self.check_logout_admission()?;
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if !state.lifecycle.admits_events() || state.waiter == Waiter::Uncertain {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SlotEventLifecycleUnresolved,
            )));
        }
        Ok(())
    }

    fn notify_preparation(&self) {
        // All registry mutations release State before notifying. The weak link
        // does not keep the module alive after its native owners have retired.
        if let Some(wake) = self.admission.get().and_then(Weak::upgrade) {
            wake.notify();
        }
    }

    pub(crate) fn status(&self) -> Result<SlotEventStatus> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(match state.lifecycle {
            Lifecycle::Finalized if state.waiter == Waiter::Idle => SlotEventStatus::Finalized,
            Lifecycle::Finalized => SlotEventStatus::FinalizedImageRetained,
            Lifecycle::Finalizing | Lifecycle::FinalizationIssued => SlotEventStatus::Closing,
            Lifecycle::FinalizationPending => SlotEventStatus::CompletionUnproven,
            Lifecycle::Withdrawn | Lifecycle::FinalizationPublicationFailed(_) => {
                SlotEventStatus::FinalizationUncertain
            }
            Lifecycle::Open | Lifecycle::FinalizationRefused(_) => match state.waiter {
                Waiter::Idle => SlotEventStatus::Idle,
                Waiter::Issued(EventMode::Poll) => SlotEventStatus::PollIssued,
                Waiter::Issued(EventMode::Blocking) => SlotEventStatus::BlockingCallIssued,
                Waiter::Uncertain => SlotEventStatus::CompletionUnproven,
            },
        })
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        image: Arc<Inner>,
        mode: EventMode,
        uncertain: Arc<super::Uncertainty>,
    ) -> Result<EventLease> {
        self.reserve_for(image, mode, uncertain, None)
    }

    /// Source selection and waiter reservation share this mutex. A source cannot
    /// change while its native waiter or an unresolved return owns the lease.
    pub(crate) fn select_source(&self, source: Option<crate::module::ClientId>) -> Result<()> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if !state.lifecycle.admits_events() || state.waiter != Waiter::Idle {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SlotEventSourceInUse,
            )));
        }
        self.source
            .store(source.map_or(0, |id| id.value()), Ordering::Release);
        drop(state);
        self.notify_preparation();
        Ok(())
    }

    pub(crate) fn reserve_for(
        self: &Arc<Self>,
        image: Arc<Inner>,
        mode: EventMode,
        uncertain: Arc<super::Uncertainty>,
        source: Option<crate::module::ClientId>,
    ) -> Result<EventLease> {
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if self.source.load(Ordering::Acquire) != source.map_or(0, |id| id.value()) {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::DifferentSlotEventSourceSelected,
            )));
        }
        if !state.lifecycle.admits_events() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SlotEventAdmissionClosed,
            )));
        }
        if state.waiter != Waiter::Idle {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::SlotEventRequestActive,
            )));
        }
        let blocking = if mode == EventMode::Blocking {
            self.dispatch
                .as_ref()
                .map(|dispatch| dispatch.reserve_blocking())
                .transpose()?
        } else {
            None
        };
        state.waiter = Waiter::Issued(mode);
        state.waiter_saw_finalization = false;
        self.preparation_active.store(true, Ordering::Release);
        drop(state);
        self.notify_preparation();
        Ok(EventLease {
            registry: self.clone(),
            image: Some(image),
            uncertain,
            mode,
            phase: LeasePhase::Prepared,
            blocking,
        })
    }

    /// Called while the module's exclusive guard has drained ordinary calls,
    /// including Poll. Only an issued blocking waiter may coexist with Finalize.
    pub(super) fn begin_finalize(&self, recovery: bool) -> Result<()> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(error) if recovery => error.into_inner(),
            Err(_) => return Err(Error::Poisoned),
        };
        if matches!(
            state.lifecycle,
            Lifecycle::Finalized
                | Lifecycle::Finalizing
                | Lifecycle::FinalizationIssued
                | Lifecycle::FinalizationPending
                | Lifecycle::FinalizationPublicationFailed(_)
        ) || state.lifecycle == Lifecycle::Withdrawn && !recovery
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleFinalizationState,
            )));
        }
        match state.waiter {
            Waiter::Issued(EventMode::Poll) => {
                return Err(Error::Busy(crate::BusyReason::NativeExecution(
                    crate::NativeExecutionBusy::SlotEventPolling,
                )));
            }
            Waiter::Uncertain => {
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::SlotEventCompletionUnproven,
                )));
            }
            Waiter::Idle | Waiter::Issued(EventMode::Blocking) => {}
        }
        // Exclusive module possession is not sufficient by itself: this exact
        // image must still own its process-wide reservation. A poisoned local
        // mutex does not erase an otherwise consistent typed return state.
        if !state.registered
            || !super::image_reservation::contains(&self.image_identity)
            || self
                .identity
                .is_some_and(|identity| !super::contains_file(identity))
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleIdentityReservationAbsent,
            )));
        }
        super::image_reservation::reserve_finalize(&self.image_identity)?;
        state.lifecycle = Lifecycle::Finalizing;
        // Admission closes during dispatch; a returned refusal reopens it
        // without erasing the receipt that forbids implicit finalization retry.
        self.preparation_closed.store(true, Ordering::Release);
        drop(state);
        self.notify_preparation();
        Ok(())
    }

    pub(super) fn finalize_dispatched(&self, record: impl FnOnce() -> Result<()>) -> Result<()> {
        {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.lifecycle != Lifecycle::Finalizing {
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::ModuleFinalizationDispatchState,
                )));
            }
        }
        // All fallible local admission checks precede the call counter. After
        // it succeeds, only infallible phase publication/unlock precedes C.
        record()?;
        // The caller owns the exclusive module guard, so no second finalizer
        // can change this phase. Do not retain this diagnostic mutex while
        // waiting for an earlier native callback to leave the dispatch owner.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.lifecycle = Lifecycle::FinalizationIssued;
        state.waiter_saw_finalization = matches!(state.waiter, Waiter::Issued(_));
        Ok(())
    }

    pub(super) fn abort_finalize(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.lifecycle != Lifecycle::Finalizing {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleFinalizationAbortState,
            )));
        }
        state.lifecycle = Lifecycle::Withdrawn;
        Ok(())
    }

    /// Publish a result already recorded by Native under its exclusive guard.
    /// Retrying this local publication never dispatches or changes that result.
    pub(super) fn finish_finalize(&self, code: fe11_sys::CK_RV) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let returned = match code {
            fe11_sys::CKR_OK => Lifecycle::Finalized,
            fe11_sys::CKR_PENDING => Lifecycle::FinalizationPending,
            code => Lifecycle::FinalizationRefused(code),
        };
        if state.lifecycle != Lifecycle::FinalizationIssued
            && state.lifecycle != returned
            && state.lifecycle != Lifecycle::FinalizationPublicationFailed(code)
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleFinalizationReturnState,
            )));
        }
        state.lifecycle = returned;
        let result = (|| {
            if matches!(returned, Lifecycle::FinalizationRefused(_)) {
                // A definite refusal cannot explain loss of initialization seen
                // by an outstanding waiter. An uncertain native effect still can.
                if !crate::native_return::effect_uncertain(code) {
                    state.waiter_saw_finalization = false;
                }
                super::image_reservation::finalization_refused(&self.image_identity)?;
                self.preparation_closed.store(false, Ordering::Release);
            }
            self.release_if_complete(&mut state)
        })();
        if result.is_err() {
            // Keep the exact receipt for local reconciliation. Neither event
            // admission nor a new Finalize may overtake failed publication.
            state.lifecycle = Lifecycle::FinalizationPublicationFailed(code);
        }
        drop(state);
        self.notify_preparation();
        result
    }

    fn release_if_complete(&self, state: &mut State) -> Result<()> {
        if state.registered
            && matches!(
                state.lifecycle,
                Lifecycle::Finalized | Lifecycle::FinalizationPublicationFailed(fe11_sys::CKR_OK)
            )
            && state.waiter == Waiter::Idle
        {
            let removed =
                super::image_reservation::release_with_file(&self.image_identity, self.identity);
            if !removed {
                // The last waiter can publish this failure after Finalize's
                // own receipt. Keep the same observable failure in both paths.
                state.lifecycle = Lifecycle::FinalizationPublicationFailed(fe11_sys::CKR_OK);
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::ModuleIdentityReservationAbsent,
                )));
            }
            state.registered = false;
            state.lifecycle = Lifecycle::Finalized;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeasePhase {
    Prepared,
    Issued,
    NativeReturned,
    Published,
}

pub(crate) struct EventLease {
    registry: Arc<EventRegistry>,
    // Inner owns Native and its image even after explicit Finalize. Holding
    // this Arc does not hold the module's admission/read guard.
    image: Option<Arc<Inner>>,
    uncertain: Arc<super::Uncertainty>,
    mode: EventMode,
    phase: LeasePhase,
    blocking: Option<super::dispatch::BlockingEvent>,
}

impl EventLease {
    pub(crate) fn dispatch(&mut self) {
        self.phase = LeasePhase::Issued;
    }

    pub(crate) fn native_returned(&mut self) {
        self.phase = LeasePhase::NativeReturned;
    }

    /// Publish before an outer owner wakes admission or releases a guard on an
    /// unresolved path. Drop still retains the authoritative waiter and image.
    pub(crate) fn retain_unproven(&self) {
        if self.phase == LeasePhase::Issued {
            self.registry
                .completion_unproven
                .store(true, Ordering::Release);
        }
    }

    /// Publish native return before doing any work requiring module admission.
    /// True means our Finalize was issued; it does not assert its success.
    pub(crate) fn finish(&mut self, rv: fe11_sys::CK_RV) -> Result<bool> {
        if self.phase != LeasePhase::NativeReturned {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::SlotEventNativeReturnUnproven,
            )));
        }
        // Poison cannot erase a recorded native return. Recover metadata only
        // to validate and retire this exact waiter; reserve still rejects poison.
        let mut state = self
            .registry
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let finalization_issued = state.returned_waiter(self.mode).map_err(|error| {
            self.uncertain.mark();
            error
        })?;
        self.registry
            .preparation_active
            .store(false, Ordering::Release);
        // Publish established context loss before making another waiter
        // admissible. NOT_INITIALIZED may result from our concurrent C_Finalize.
        if !(rv == fe11_sys::CKR_CRYPTOKI_NOT_INITIALIZED && finalization_issued)
            && crate::native_return::slot_scope("C_WaitForSlotEvent", rv)
                == crate::native_return::FailureScope::Module
        {
            self.uncertain.observe_runtime_return(rv as u64);
            self.uncertain.mark();
        }
        self.phase = LeasePhase::Published;
        self.registry
            .release_if_complete(&mut state)
            .map_err(|error| {
                self.uncertain.mark();
                error
            })?;
        drop(state);
        self.registry.notify_preparation();
        drop(self.blocking.take());
        Ok(finalization_issued)
    }
}

impl Drop for EventLease {
    fn drop(&mut self) {
        if self.phase == LeasePhase::Published {
            return;
        }
        // Outer event owners also call this before their earlier notifications.
        self.retain_unproven();
        if self.phase != LeasePhase::Prepared {
            self.uncertain.mark();
        }
        {
            let mut state = self
                .registry
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state.waiter != Waiter::Issued(self.mode) {
                // Do not retire a different or already uncertain owner from a
                // mismatched local state, even though this lease is dropping.
                self.uncertain.mark();
                if let Some(image) = self.image.take() {
                    std::mem::forget(image);
                }
                if let Some(blocking) = self.blocking.take() {
                    std::mem::forget(blocking);
                }
                return;
            }
            if self.phase == LeasePhase::Issued {
                // A PENDING return or an interrupted owner is not completion.
                // Preserve exclusivity and image lifetime, never issue a retry.
                state.waiter = Waiter::Uncertain;
            } else {
                state.waiter = Waiter::Idle;
                self.registry
                    .preparation_active
                    .store(false, Ordering::Release);
                if self.registry.release_if_complete(&mut state).is_err() {
                    self.uncertain.mark();
                }
            }
        }
        self.registry.notify_preparation();
        if self.phase == LeasePhase::Issued {
            if let Some(blocking) = self.blocking.take() {
                std::mem::forget(blocking);
            }
            if let Some(image) = self.image.take() {
                std::mem::forget(image);
            }
        }
    }
}
