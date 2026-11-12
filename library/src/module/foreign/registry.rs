// SPDX-License-Identifier: Apache-2.0
//! Short local registry locks; no native call or application destructor under them.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Slot {
    id: u64,
    domain: Arc<SlotDomain>,
}

#[derive(Default)]
struct Entries {
    participants: Vec<Arc<Participant>>,
    works: Vec<Arc<Work>>,
    slots: Vec<Slot>,
}

/// Lost native identity is independent of whether an argument graph is still
/// borrowed. Use this only for authority/readiness, never as a release proof.
pub(super) fn native_context_retired(work: &Work) -> bool {
    work.native_retired.load(Ordering::Acquire)
        || work.domain.as_ref().is_some_and(|domain| {
            let current = domain.foreign_epoch.load(Ordering::Acquire);
            current == u64::MAX || work.token_epoch != Some(current)
        })
        || work.session.as_ref().is_some_and(|session| {
            session.native_retired.load(Ordering::Acquire)
                || session.token_epoch != work.token_epoch
                || session.scope.slot() != work.scope.slot()
        })
        || work.join_source.as_ref().is_some_and(|source| {
            source.native_retired.load(Ordering::Acquire)
                || source.token_epoch != work.token_epoch
                || source.scope.slot() != work.scope.slot()
        })
}

pub(crate) struct Registry {
    callbacks_closed: Mutex<bool>,
    callback_window: AtomicBool,
    untracked: Arc<AtomicBool>,
    image: Arc<crate::native::image::LoadedImage>,
    dispatch: Option<Arc<crate::native::dispatch::Dispatch>>,
    entries: Mutex<Entries>,
}

/// Prepared retirement storage outlives native/module/token guards. Moving a
/// graph here must never invoke its application's destructor under those guards.
#[derive(Default)]
pub(crate) struct Retired {
    graphs: Vec<Box<dyn Send + Sync>>,
    pub(super) current: Option<Box<dyn Send + Sync>>,
}

impl Registry {
    pub(crate) fn new(
        image: Arc<crate::native::image::LoadedImage>,
        dispatch: Option<Arc<crate::native::dispatch::Dispatch>>,
    ) -> Self {
        Self {
            callbacks_closed: Mutex::new(false),
            callback_window: AtomicBool::new(false),
            untracked: Arc::new(AtomicBool::new(false)),
            image,
            dispatch,
            entries: Mutex::new(Entries::default()),
        }
    }

    pub(super) fn callback_dispatch(&self) -> Result<Option<crate::native::dispatch::Callback>> {
        self.dispatch
            .as_ref()
            .map(|dispatch| dispatch.callback())
            .transpose()
    }

    pub(super) fn callback_admission(
        &self,
        work: Option<&Arc<Work>>,
    ) -> Result<std::sync::MutexGuard<'_, bool>> {
        let gate = self.callbacks_closed.lock().map_err(|_| Error::Poisoned)?;
        if *gate && !self.callback_window.load(Ordering::Acquire)
            || work
                .and_then(|work| work.domain.as_ref())
                .is_some_and(|domain| {
                    domain.foreign_callbacks_closed.load(Ordering::Acquire)
                        && !domain.foreign_callback_window.load(Ordering::Acquire)
                })
        {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignCallbackAdmissionClosed,
            )));
        }
        Ok(gate)
    }

    pub(crate) fn seal_callbacks(
        &self,
        slot: Option<(u64, Arc<SlotDomain>)>,
    ) -> Result<CallbackSeal<'_>> {
        let mut gate = self.callbacks_closed.lock().map_err(|_| Error::Poisoned)?;
        if *gate || self.callbacks_active(slot.as_ref().map(|(id, _)| *id))? {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing,
            )));
        }
        if let Some((_, domain)) = &slot {
            domain
                .foreign_callbacks_closed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| {
                    Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignSlotCallbackAdmissionClosed,
                    ))
                })?;
        } else {
            *gate = true;
        }
        Ok(CallbackSeal {
            registry: self,
            domain: slot.map(|(_, domain)| domain),
            committed: false,
        })
    }

    pub(crate) fn image_id(&self) -> usize {
        Arc::as_ptr(&self.image) as usize
    }

    pub(crate) fn domain(&self, slot: u64) -> Result<Arc<SlotDomain>> {
        fe11_sys::CK_SLOT_ID::try_from(slot).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignSlotConversion,
            ))
        })?;
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        if let Some(existing) = entries.slots.iter().find(|entry| entry.id == slot) {
            return Ok(existing.domain.clone());
        }
        entries.slots.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignSlotRegistryAllocation,
            ))
        })?;
        let domain = Arc::new(SlotDomain::new());
        entries.slots.push(Slot {
            id: slot,
            domain: domain.clone(),
        });
        Ok(domain)
    }

    /// Capture only an existing domain in this runtime. Event observation must
    /// not require discovery or create a slot on behalf of the application.
    pub(crate) fn observed_slot_epoch(&self, slot: u64) -> Result<Option<(Arc<SlotDomain>, u64)>> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        Ok(entries
            .slots
            .iter()
            .find(|entry| entry.id == slot)
            .map(|entry| {
                let epoch = entry.domain.foreign_epoch.load(Ordering::Acquire);
                (entry.domain.clone(), epoch)
            }))
    }

    pub(super) fn register(
        &self,
        inner: &Arc<Inner>,
        owner: Box<dyn Send + Sync>,
    ) -> Result<ForeignParticipant> {
        // The opaque owner is established before any guard and remains outside
        // their scope on every error. The registry only moves/clones Arc values.
        let id = match ClientId::allocate(&inner.next_client) {
            Ok(id) => id,
            Err(error) => {
                // Enrollment can describe resources already in native use.
                // Failure to allocate metadata is not their termination proof.
                self.untracked.store(true, Ordering::Release);
                std::mem::forget(owner);
                std::mem::forget(self.image.clone());
                return Err(error);
            }
        };
        let participant = Arc::new(Participant {
            id,
            image: self.image.clone(),
            owner: Mutex::new(Some(owner)),
            finalized: AtomicBool::new(false),
            callbacks: AtomicUsize::new(0),
            untracked: self.untracked.clone(),
        });
        let publication = (|| -> Result<()> {
            let _state = inner.read()?;
            let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
            entries.participants.try_reserve(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignParticipantAllocation,
                ))
            })?;
            entries.participants.push(participant.clone());
            Ok(())
        })();
        if let Err(error) = publication {
            self.untracked.store(true, Ordering::Release);
            std::mem::forget(participant);
            return Err(error);
        }
        Ok(ForeignParticipant {
            inner: inner.clone(),
            participant,
        })
    }

    pub(super) fn publish(&self, work: &Arc<Work>) -> Result<()> {
        let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        if work.kind == ForeignWorkKind::Session {
            for old in &entries.works {
                if old.kind == ForeignWorkKind::Session
                    && old.scope() == work.scope()
                    && work.session_handle.load(Ordering::Acquire) != 0
                {
                    let phase = old.state.lock().map_err(|_| Error::Poisoned)?.phase;
                    if !matches!(phase, Phase::Returned) {
                        return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                            crate::ExternalExecutionRejection::ForeignSessionAlreadyRegistered,
                        )));
                    }
                }
            }
        }
        entries.works.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignWorkRegistryAllocation,
            ))
        })?;
        entries.works.push(work.clone());
        Ok(())
    }

    pub(super) fn check_session(&self, selected: &Arc<Work>) -> Result<()> {
        if native_context_retired(selected) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignNativeContextRetired,
            )));
        }
        let Some(session) = &selected.session else {
            return Ok(());
        };
        if session.state.lock().map_err(|_| Error::Poisoned)?.phase != Phase::SessionOpen {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignSessionRetired,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if Arc::ptr_eq(work, selected) {
                continue;
            }
            if work
                .session
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, session))
            {
                let phase = work.state.lock().map_err(|_| Error::Poisoned)?.phase;
                if matches!(
                    phase,
                    Phase::Reserved(_) | Phase::Issued(_) | Phase::Uncertain
                ) {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignSessionExecutionActive,
                    )));
                }
                // A returned multipart step is different from an actual pending
                // native execution; the call module checks that distinction.
                if phase == Phase::Progressable(Progress::Pending) {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignSessionNativeCallPending,
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn check_opened_handle(&self, selected: &Arc<Work>, handle: u64) -> Result<()> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for old in &entries.works {
            if !Arc::ptr_eq(old, selected)
                && old.kind == ForeignWorkKind::Session
                && old.scope.slot() == selected.scope.slot()
                && old.session_handle.load(Ordering::Acquire) == handle
                && old.state.lock().map_err(|_| Error::Poisoned)?.phase != Phase::Returned
            {
                let retired = old.native_retired.load(Ordering::Acquire)
                    || old.token_epoch != selected.token_epoch;
                if !retired || old.callbacks.load(Ordering::Acquire) != 0 {
                    return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                        crate::ExternalExecutionRejection::ForeignNativeSessionHandleReused,
                    )));
                }
                // Numeric reuse is no release proof. Verify that the old
                // session and every child have returned, then keep their
                // graphs anchored under the retired identity.
                for prior in &entries.works {
                    if !Arc::ptr_eq(prior, old)
                        && !prior.session.as_ref().is_some_and(|s| Arc::ptr_eq(s, old))
                    {
                        continue;
                    }
                    if prior.callbacks.load(Ordering::Acquire) != 0 {
                        return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                            crate::ExternalExecutionBusy::ReusedForeignSessionCallbackActive,
                        )));
                    }
                    match prior.state.lock().map_err(|_| Error::Poisoned)?.phase {
                        Phase::Prepared
                        | Phase::PreparedJoin
                        | Phase::Returned
                        | Phase::Detached
                        | Phase::SessionOpen
                        | Phase::Progressable(Progress::Sequence) => {}
                        _ => {
                            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                                crate::ExternalExecutionBusy::ReusedForeignExecutionUnresolved,
                            )))
                        }
                    }
                }
                old.native_retired.store(true, Ordering::Release);
            }
        }
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<ForeignStatus> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        let mut status = ForeignStatus {
            participants: entries.participants.len(),
            ..ForeignStatus::default()
        };
        for participant in &entries.participants {
            status.callbacks = status
                .callbacks
                .checked_add(participant.callbacks.load(Ordering::Acquire))
                .ok_or(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignCallbackCount,
                )))?;
        }
        for work in &entries.works {
            match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                Phase::SessionOpen => status.sessions += 1,
                Phase::Reserved(_)
                | Phase::Issued(_)
                | Phase::Progressable(_)
                | Phase::JoinReserved => status.progressable += 1,
                Phase::Uncertain => status.uncertain += 1,
                _ => {}
            }
            status.callbacks = status
                .callbacks
                .checked_add(work.callbacks.load(Ordering::Acquire))
                .ok_or(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignCallbackCount,
                )))?;
        }
        Ok(status)
    }

    pub(crate) fn callbacks_active(&self, slot: Option<u64>) -> Result<bool> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        if slot.is_none()
            && entries
                .participants
                .iter()
                .any(|p| p.callbacks.load(Ordering::Acquire) != 0)
        {
            return Ok(true);
        }
        Ok(entries.works.iter().any(|work| {
            slot.map_or(true, |slot| work.scope.slot() == Some(slot))
                && work.callbacks.load(Ordering::Acquire) != 0
        }))
    }

    pub(crate) fn finalization_ready(&self) -> Result<()> {
        self.check_tracked()?;
        if self.callbacks_active(None)? {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignCallbackActive,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                Phase::Prepared
                | Phase::PreparedJoin
                | Phase::Returned
                | Phase::Detached
                | Phase::JoinReserved => {}
                Phase::SessionOpen | Phase::Progressable(Progress::Sequence)
                    if native_context_retired(work) =>
                {
                    // Its handle cannot be closed individually, but it has no
                    // outstanding execution. Only the subsequent successful
                    // Finalize, not this check, can release its retained graph.
                }
                Phase::SessionOpen => {
                    return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                        crate::ExternalExecutionRejection::ForeignSessionsActive,
                    )))
                }
                _ => {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignNativeWorkUnresolved,
                    )))
                }
            }
        }
        Ok(())
    }

    /// Inspect completion, not ownership release. The caller holds the token
    /// writer, which excludes new work on this slot through Logout's return.
    /// Module-only calls may overlap: their contract forbids token/session use.
    pub(crate) fn logout_ready(&self, slot: u64) -> Result<()> {
        self.check_tracked()?;
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            let scoped_slot = work.scope.slot();
            if scoped_slot.is_some_and(|other| other != slot) {
                continue;
            }
            match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                Phase::Prepared | Phase::PreparedJoin | Phase::Returned | Phase::Detached => {}
                Phase::Reserved(_) | Phase::Issued(_) if scoped_slot.is_none() => {}
                Phase::SessionOpen | Phase::Progressable(Progress::Sequence)
                    if scoped_slot == Some(slot) => {}
                _ => {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignNativeExecutionUnresolved,
                    )))
                }
            }
        }
        // No seal or callback-quiescence claim: Logout releases no graph.
        Ok(())
    }
    pub(crate) fn successor_ready(&self) -> Result<()> {
        self.check_tracked()?;
        if self.callbacks_active(None)? {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignCallbackActive,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                Phase::Prepared
                | Phase::PreparedJoin
                | Phase::Returned
                | Phase::Detached
                | Phase::SessionOpen
                | Phase::Progressable(Progress::Sequence) => {}
                _ => {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignNativeExecutionUnresolved,
                    )))
                }
            }
        }
        Ok(())
    }
    /// The slot writer excludes native dispatch. Check before withdrawing a
    /// live epoch: rediscovery must not strand a peer's still-usable session.
    /// Already retired sequences retain their graph; pending execution and
    /// callbacks continue to prevent replacement even after identity loss.
    pub(crate) fn slot_successor_ready(&self, slot: u64) -> Result<()> {
        self.check_tracked()?;
        if self.callbacks_active(Some(slot))? {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignTokenCallbackActive,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if work.scope.slot() != Some(slot) {
                continue;
            }
            match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                Phase::Prepared | Phase::PreparedJoin | Phase::Returned | Phase::Detached => {}
                Phase::SessionOpen | Phase::Progressable(Progress::Sequence)
                    if native_context_retired(work) => {}
                Phase::SessionOpen | Phase::Progressable(Progress::Sequence) => {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::LiveForeignTokenResourcesRequireCompletion,
                    )));
                }
                _ => {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignTokenExecutionUnresolved,
                    )))
                }
            }
        }
        Ok(())
    }

    pub(crate) fn seal_successor_callbacks(&self) -> Result<Option<CallbackSeal<'_>>> {
        // A completed Finalize may already have sealed these callbacks.
        let closed = *self.callbacks_closed.lock().map_err(|_| Error::Poisoned)?;
        if closed {
            self.successor_ready()?;
            Ok(None)
        } else {
            self.seal_callbacks(None).map(Some)
        }
    }

    pub(crate) fn maintenance_ready(&self, slot: u64) -> Result<()> {
        self.check_tracked()?;
        if self.callbacks_active(Some(slot))? {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignTokenCallbackActive,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if work.scope.slot() == Some(slot) {
                match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                    Phase::Prepared
                    | Phase::PreparedJoin
                    | Phase::Returned
                    | Phase::Detached
                    | Phase::JoinReserved => {}
                    _ => {
                        return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                            crate::ExternalExecutionBusy::ForeignTokenResourcesActive,
                        )))
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn collective_close_ready(&self, slot: u64) -> Result<()> {
        self.check_tracked()?;
        if self.callbacks_active(Some(slot))? {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignTokenCallbackActive,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if work.scope.slot() != Some(slot) {
                continue;
            }
            match work.state.lock().map_err(|_| Error::Poisoned)?.phase {
                Phase::Prepared
                | Phase::PreparedJoin
                | Phase::Returned
                | Phase::Detached
                | Phase::JoinReserved
                | Phase::SessionOpen => {}
                Phase::Progressable(_)
                    if work.kind == ForeignWorkKind::Operation && work.session.is_some() => {}
                _ => return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                    crate::ExternalExecutionBusy::ForeignCollectiveCloseLacksTerminationContract,
                ))),
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_retirement(&self, retired: &mut Retired) -> Result<()> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        retired
            .graphs
            .try_reserve(entries.works.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignRetirementAllocation,
                ))
            })
    }

    fn check_tracked(&self) -> Result<()> {
        if self.untracked.load(Ordering::Acquire) {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::UnregisteredForeignNativeResourceRetained,
            )));
        }
        Ok(())
    }

    /// Caller owns module/slot exclusion and a native success for this exact
    /// scope. Detached jobs are not declared terminated by collective close.
    pub(crate) fn retire(&self, slot: Option<(u64, u64)>, retired: &mut Retired) -> Result<()> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if slot.is_some_and(|(slot, epoch)| {
                work.scope.slot() != Some(slot) || work.token_epoch != Some(epoch)
            }) {
                continue;
            }
            let mut state = work.state.lock().map_err(|_| Error::Poisoned)?;
            if matches!(
                state.phase,
                Phase::Uncertain | Phase::Detached | Phase::JoinReserved
            ) {
                continue;
            }
            if retired.graphs.len() == retired.graphs.capacity() && state.graph.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignRetirementCapacityChanged,
                )));
            }
            state.phase = Phase::Returned;
            if work.callbacks.load(Ordering::Acquire) == 0 {
                if let Some(graph) = state.graph.take() {
                    retired.graphs.push(graph);
                }
            }
            drop(state);
            Self::settle_join(work)?;
        }
        if slot.is_none() {
            for participant in &entries.participants {
                participant.finalized.store(true, Ordering::Release);
            }
        }
        Ok(())
    }

    pub(super) fn abandoned(&self, participant: &Arc<Participant>) -> Result<Option<Arc<Work>>> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if !Arc::ptr_eq(&work.participant, participant) {
                continue;
            }
            let phase = work.state.lock().map_err(|_| Error::Poisoned)?.phase;
            if matches!(
                phase,
                Phase::Progressable(_) | Phase::SessionOpen | Phase::Detached
            ) && work
                .held
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Some(work.clone()));
            }
        }
        Ok(None)
    }

    pub(super) fn session_close_ready(&self, session: &Arc<Work>) -> Result<()> {
        if session.kind != ForeignWorkKind::Session {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignCloseSessionOwner,
            )));
        }
        if session.callbacks.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignSessionCallbackActive,
            )));
        }
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if work
                .session
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, session))
            {
                let phase = work.state.lock().map_err(|_| Error::Poisoned)?.phase;
                match phase {
                    Phase::Prepared
                    | Phase::PreparedJoin
                    | Phase::Returned
                    | Phase::Detached
                    | Phase::JoinReserved => {}
                    Phase::Progressable(_) if work.kind == ForeignWorkKind::Operation => {}
                    _ => return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignSessionCloseLacksTerminationContract,
                    ))),
                }
                if work.callbacks.load(Ordering::Acquire) != 0 {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignOperationCallbackActive,
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn retire_session(&self, session: &Arc<Work>, retired: &mut Retired) -> Result<()> {
        let entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
        for work in &entries.works {
            if !work
                .session
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, session))
            {
                continue;
            }
            let mut state = work.state.lock().map_err(|_| Error::Poisoned)?;
            if matches!(
                state.phase,
                Phase::Detached | Phase::JoinReserved | Phase::Uncertain
            ) {
                continue;
            }
            if state.graph.is_some() && retired.graphs.len() == retired.graphs.capacity() {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignRetirementCapacityChanged,
                )));
            }
            state.phase = Phase::Returned;
            if work.callbacks.load(Ordering::Acquire) == 0 {
                if let Some(graph) = state.graph.take() {
                    retired.graphs.push(graph);
                }
            }
            drop(state);
            Self::settle_join(work)?;
        }
        Ok(())
    }

    fn settle_join(work: &Work) -> Result<()> {
        if let Some(source) = &work.join_source {
            let mut state = source.state.lock().map_err(|_| Error::Poisoned)?;
            if state.phase == Phase::JoinReserved {
                // Session/global closure proves the new loan ended, not that
                // the detached identifier expired. Restore its sole capability
                // for an explicit native Join; no automatic job replay occurs.
                state.phase = Phase::Detached;
            }
        }
        Ok(())
    }

    pub(crate) fn wait_callbacks(&self, inner: &Inner, slot: Option<u64>) -> Result<()> {
        inner.check_lifecycle_reentry()?;
        self.check_tracked()?;
        if let Some(dispatch) = &self.dispatch {
            dispatch.check_lifecycle()?;
        }
        inner
            .state
            .admission_wake()
            .acquire(&crate::admission_wait::current(), || {
                if self.callbacks_active(slot)? {
                    Ok(crate::admission_wait::Attempt::Occupied(
                        crate::BusyReason::ExternalExecution(
                            crate::ExternalExecutionBusy::ForeignCallbackActive,
                        ),
                    ))
                } else {
                    Ok(crate::admission_wait::Attempt::Acquired(()))
                }
            })
    }

    /// Called with no native/module/token guard. Callback exit only wakes this
    /// path; it never executes an opaque graph destructor on a native thread.
    pub(super) fn collect_completed(&self) -> Result<usize> {
        let mut retired = Retired::default();
        let mut records = Vec::new();
        {
            let mut entries = self.entries.lock().map_err(|_| Error::Poisoned)?;
            // Size both destination vectors against the same locked population.
            // No graph is moved until every fallible allocation has succeeded.
            retired
                .graphs
                .try_reserve(entries.works.len())
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ExternalExecution(
                        crate::ExternalExecutionRejection::ForeignCollectionAllocation,
                    ))
                })?;
            records.try_reserve(entries.works.len()).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignCollectionAllocation,
                ))
            })?;
            for work in &entries.works {
                let mut state = work.state.lock().map_err(|_| Error::Poisoned)?;
                let returned = matches!(
                    state.phase,
                    Phase::Returned | Phase::Detached | Phase::JoinReserved
                ) || matches!(state.phase, Phase::Prepared | Phase::PreparedJoin)
                    && !work.held.load(Ordering::Acquire);
                if returned && work.callbacks.load(Ordering::Acquire) == 0 {
                    if let Some(graph) = state.graph.take() {
                        retired.graphs.push(graph);
                    }
                }
            }
            let mut index = 0;
            while index < entries.works.len() {
                let work = &entries.works[index];
                let state = work.state.lock().map_err(|_| Error::Poisoned)?;
                let removable = work.callbacks.load(Ordering::Acquire) == 0
                    && (state.phase == Phase::Returned
                        || matches!(state.phase, Phase::Prepared | Phase::PreparedJoin)
                            && !work.held.load(Ordering::Acquire));
                drop(state);
                if removable {
                    records.push(entries.works.swap_remove(index));
                } else {
                    index += 1;
                }
            }
        }
        // Potentially last Work/Participant owners are released only after the
        // registry mutex. Detached jobs stay claimable; native loans stay rooted.
        drop(records);
        Ok(retired.graphs.len())
    }
}

pub(crate) struct CallbackSeal<'a> {
    registry: &'a Registry,
    domain: Option<Arc<SlotDomain>>,
    committed: bool,
}
impl CallbackSeal<'_> {
    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
    pub(crate) fn native_window(&self) -> NativeCallbackWindow<'_> {
        let flag = self
            .domain
            .as_ref()
            .map_or(&self.registry.callback_window, |domain| {
                &domain.foreign_callback_window
            });
        flag.store(true, Ordering::Release);
        NativeCallbackWindow(flag)
    }
    pub(super) fn begin_native(&self) {
        self.domain
            .as_ref()
            .map_or(&self.registry.callback_window, |domain| {
                &domain.foreign_callback_window
            })
            .store(true, Ordering::Release);
    }
    pub(super) fn end_native(&self) {
        self.domain
            .as_ref()
            .map_or(&self.registry.callback_window, |domain| {
                &domain.foreign_callback_window
            })
            .store(false, Ordering::Release);
    }
}
/// A lifecycle function can itself invoke application mutex/notify callbacks.
/// New entries close on its actual return; active guards retain their owners.
pub(crate) struct NativeCallbackWindow<'a>(&'a AtomicBool);
impl Drop for NativeCallbackWindow<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Drop for CallbackSeal<'_> {
    fn drop(&mut self) {
        self.end_native();
        if !self.committed {
            let mut gate = self
                .registry
                .callbacks_closed
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(domain) = &self.domain {
                domain
                    .foreign_callbacks_closed
                    .store(false, Ordering::Release);
            } else {
                *gate = false;
            }
        }
    }
}
