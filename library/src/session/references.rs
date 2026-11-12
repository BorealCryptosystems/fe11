// SPDX-License-Identifier: Apache-2.0
//! Reference quota admission precedes the call's credited materialization.
//! A brief module read captures the registries and immutable function checks;
//! no module/token/session/object guard survives a quota wait.
use super::{AdmissionProgress, Session};
use crate::{
    module::State,
    registry::{ControlledReference, Registry, Reservation},
    AdvancedSessionMode, Error, ResourceAdmission, Result,
};
use std::sync::atomic::Ordering;

#[derive(Clone, Copy)]
pub(crate) enum ReferenceMode {
    Synchronous,
    SynchronousAdmission,
    Advanced,
    // Preparation only; an Init attempt does not acquire the occupied ticket.
    InitAttempt,
}

/// A quota acquired by this invocation before materialization. It carries no
/// native/session guard and no strong session/module owner. Final access must
/// match both registries and the exact entry before consuming the publication
/// permit. This prevents a prepared owner from reserving a second quota later.
pub(crate) struct ManagedReferences {
    uid: u64,
    entry: std::sync::Weak<crate::module::SessionEntry>,
    mode: ReferenceMode,
    managed: Registry<crate::managed::NativeIdentity>,
    objects: Registry<crate::managed::NativeIdentity>,
    permit: Reservation<crate::managed::NativeIdentity>,
}

impl ManagedReferences {
    /// Final possession validates the exact registry and session before taking
    /// the quota. A refusal leaves its participants with the access-first owner.
    pub(crate) fn into_permit_retained(
        references: &mut Option<Self>,
        session: &Session,
        access: &super::SessionAccess<'_>,
    ) -> Result<Reservation<crate::managed::NativeIdentity>> {
        references
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ReferenceReservationAbsent,
            )))?
            .check(session, access)?;
        Ok(references
            .take()
            .expect("reference checked before transfer")
            .permit)
    }

    pub(crate) fn check(&self, session: &Session, access: &super::SessionAccess<'_>) -> Result<()> {
        if self.uid != session.uid
            || !self
                .entry
                .ptr_eq(&std::sync::Arc::downgrade(&session.entry))
            || !access.owns_session(session)
            || !self.managed.same_registry(&access.managed)
            || !self.objects.same_registry(&access.objects)
        {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ForeignOrExhaustedReferenceReservation,
            )));
        }
        session.reference_context(self.mode)?;
        session.entry_common(access)?;
        Ok(())
    }
}

pub(crate) struct ReferenceAdmission<'a> {
    session: &'a Session,
    mode: ReferenceMode,
    admission: ResourceAdmission,
    managed: Registry<crate::managed::NativeIdentity>,
    objects: Registry<crate::managed::NativeIdentity>,
    progress: AdmissionProgress,
}

impl Session {
    /// Immutable admission for a start that does not publish a managed key.
    /// Reuses local context admission without consuming any reference quota or retaining a guard.
    pub(crate) fn advanced_preflight(
        &self,
        checks: impl Fn(&State) -> Result<()>,
    ) -> Result<AdmissionProgress> {
        Ok(self
            .reference_admission(ReferenceMode::Advanced, checks)?
            .progress)
    }

    /// Check restoration's destination under session possession before any
    /// storage wait. A parked ticket cannot be replaced by restoration; it is
    /// different from contention on a gate, which keeps the caller's policy.
    /// The installer must repeat this check after preparation releases access.
    pub(crate) fn recovery_preflight(
        &self,
        checks: impl Fn(&State) -> Result<()>,
    ) -> Result<AdmissionProgress> {
        let progress = AdmissionProgress::default();
        let access = self.advanced_access_progress(super::CleanupAdmission::Ordinary, &progress)?;
        if self.entry.advanced_operation.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::CombinedOperations(
                crate::CombinedOperationsBusy::RecoveryDestinationActive,
            )));
        }
        checks(&access)?;
        drop(access);
        Ok(progress)
    }
    /// The initiating epoch is checked before the immutable preflight can wait.
    /// The returned progress is reused by the same start's aggregate factory.
    pub(crate) fn advanced_preflight_at_epoch(
        &self,
        epoch: u64,
        checks: impl Fn(&State) -> Result<()>,
    ) -> Result<AdmissionProgress> {
        Ok(self
            .reference_admission_at_epoch(ReferenceMode::Advanced, epoch, checks)?
            .progress)
    }

    pub(crate) fn init_preflight_at_epoch(
        &self,
        epoch: u64,
        checks: impl Fn(&State) -> Result<()>,
    ) -> Result<AdmissionProgress> {
        Ok(self
            .reference_admission_at_epoch(ReferenceMode::InitAttempt, epoch, checks)?
            .progress)
    }

    pub(crate) fn key_admission_search(state: &State, required: bool) -> Result<()> {
        if required
            && (state.native.table.C_FindObjectsInit.is_none()
                || state.native.table.C_FindObjects.is_none()
                || state.native.table.C_FindObjectsFinal.is_none())
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionSearchFunctionsUnavailable,
            )));
        }
        Ok(())
    }

    pub(crate) fn reference_search_functions(state: &State) -> Result<()> {
        state.native.table.C_FindObjectsInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CFindObjectsInitUnavailable,
            ),
        ))?;
        state.native.table.C_FindObjects.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CFindObjectsUnavailable,
            ),
        ))?;
        state
            .native
            .table
            .C_FindObjectsFinal
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CFindObjectsFinalUnavailable,
            )))?;
        Ok(())
    }

    // These observations run again under Registry's Wake. They take no mutex,
    // allocate nothing and do not establish native possession or handle validity.
    fn reference_context(&self, mode: ReferenceMode) -> Result<()> {
        self.inner.state.check_admission(false)?;
        self.snapshot.check_drain(false)?;
        if matches!(mode, ReferenceMode::SynchronousAdmission)
            && self.entry.mode != AdvancedSessionMode::Synchronous
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SynchronousAdmissionRequiresASynchronousSession,
            )));
        }
        if matches!(
            mode,
            ReferenceMode::Synchronous | ReferenceMode::SynchronousAdmission
        ) {
            if self.entry.mode == AdvancedSessionMode::Asynchronous {
                return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::AsynchronousSessionRequiresOwnedDispatch,
                )));
            }
            if self.entry.advanced_operation.load(Ordering::Acquire) != 0 {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        self.inner.availability.check_available()?;
        self.snapshot.check()?;
        if let Some(notification) = &self.entry.notification {
            notification.check()?;
        }
        if self.entry.closed.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionClosed,
            )));
        }
        if self.entry.close_attempted.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionClosingOrCloseFailed,
            )));
        }
        if self.entry.generation != self.snapshot.generation
            || self.entry.slot as u64 != self.snapshot.capabilities.identity.slot
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionGenerationMismatch,
            )));
        }
        if self.entry.poisoned.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionStateUncertain,
            )));
        }
        if matches!(mode, ReferenceMode::Advanced)
            && self.entry.advanced_operation.load(Ordering::Acquire) != 0
        {
            return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                crate::OperationOwnershipBusy::AdvancedOperation,
            )));
        }
        Ok(())
    }

    pub(crate) fn reference_admission(
        &self,
        mode: ReferenceMode,
        immutable_checks: impl Fn(&State) -> Result<()>,
    ) -> Result<ReferenceAdmission<'_>> {
        self.reference_admission_with_epoch(mode, None, immutable_checks)
    }

    pub(crate) fn reference_admission_at_epoch(
        &self,
        mode: ReferenceMode,
        epoch: u64,
        immutable_checks: impl Fn(&State) -> Result<()>,
    ) -> Result<ReferenceAdmission<'_>> {
        self.reference_admission_with_epoch(mode, Some(epoch), immutable_checks)
    }

    fn reference_admission_with_epoch(
        &self,
        mode: ReferenceMode,
        epoch: Option<u64>,
        immutable_checks: impl Fn(&State) -> Result<()>,
    ) -> Result<ReferenceAdmission<'_>> {
        let admission = crate::admission_wait::current();
        let progress = AdmissionProgress::default();
        loop {
            let state = match epoch {
                Some(epoch) => self.read_at_epoch(epoch)?,
                None => self.inner.read()?,
            };
            match self.reference_context(mode) {
                Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                ))) if progress.can_maintain() && self.entry.advanced_progress.cleanup_hint() => {
                    drop(state);
                    progress.maintain_local(self)?;
                    continue;
                }
                result => result?,
            }
            immutable_checks(&state)?;
            return Ok(ReferenceAdmission {
                session: self,
                mode,
                admission,
                managed: state.managed.clone(),
                objects: state.objects.clone(),
                progress,
            });
        }
    }
}

impl ReferenceAdmission<'_> {
    pub(crate) fn progress(&self) -> &AdmissionProgress {
        &self.progress
    }

    /// Preserve both the original progress context and the admitted permit on
    /// refusal. Taking them follows the last registry/cardinality validation.
    pub(crate) fn into_prepaid_managed_retained(
        admission: &mut Option<Self>,
        permit: &mut Option<Reservation<crate::managed::NativeIdentity>>,
        count: usize,
    ) -> Result<ManagedReferences> {
        let candidate =
            admission
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ReferenceAdmissionAbsent,
                )))?;
        let reservation =
            permit
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ReferenceReservationAbsent,
                )))?;
        if !candidate.managed.matches_reservation(reservation, count) {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ForeignOrExhaustedReferenceReservation,
            )));
        }
        let admission = admission
            .take()
            .expect("reference admission checked before transfer");
        let permit = permit
            .take()
            .expect("reference reservation checked before transfer");
        Ok(ManagedReferences {
            uid: admission.session.uid,
            entry: std::sync::Arc::downgrade(&admission.session.entry),
            mode: admission.mode,
            managed: admission.managed,
            objects: admission.objects,
            permit,
        })
    }

    /// Revalidate under final ordinary possession, before the first native
    /// observation/effect. Publication's insert check is deliberately later
    /// and does not replace this pre-dispatch binding check.
    pub(crate) fn check(&self, access: &super::SessionAccess<'_>) -> Result<()> {
        if !access.owns_session(self.session)
            || !self.managed.same_registry(&access.managed)
            || !self.objects.same_registry(&access.objects)
        {
            return Err(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                crate::ReferenceRegistryRejection::ForeignOrExhaustedReferenceReservation,
            )));
        }
        self.reference_context_under_access(access)
    }

    fn reference_context_under_access(&self, state: &State) -> Result<()> {
        self.session.reference_context(self.mode)?;
        self.session.entry_common(state).map(|_| ())
    }

    fn reserve<T>(&mut self, registry: &Registry<T>, count: usize) -> Result<Reservation<T>> {
        loop {
            let result = registry.reserve_controlled(count, &self.admission, || {
                match self.session.reference_context(self.mode) {
                    Err(Error::Busy(crate::BusyReason::OperationOwnership(
                        crate::OperationOwnershipBusy::AdvancedOperation,
                    ))) if self.progress.can_maintain()
                        && self.session.entry.advanced_progress.cleanup_hint() =>
                    {
                        Ok(Some(()))
                    }
                    result => result.map(|()| None),
                }
            })?;
            match result {
                ControlledReference::Acquired(mut reservation) => {
                    let bytes = count
                        .checked_mul(crate::managed::resource_activity_bytes()?)
                        .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::ActivityStorageAccounting,
                        )))?;
                    let (participants, activity_credit) = self
                        .session
                        .snapshot
                        .unknown_close
                        .reserve_reference_resources(
                            count,
                            bytes,
                            &self.session.inner.symmetric_budget,
                            &self.admission,
                            || self.session.reference_context(self.mode),
                            |required| self.progress.check_retained(self.session, required),
                        )?;
                    reservation.prepare_close(participants)?;
                    reservation.prepare_activities(activity_credit)?;
                    return Ok(reservation);
                }
                ControlledReference::Redirect(()) => {
                    self.progress.maintain_local(self.session)?;
                }
            }
        }
    }

    pub(crate) fn managed(
        &mut self,
        count: usize,
    ) -> Result<Reservation<crate::managed::NativeIdentity>> {
        let registry = self.managed.clone();
        self.reserve(&registry, count)
    }

    /// Admit a complete discovered-output group. Only the reference count is
    /// reserved before memory; close, Activity and private payload credits are
    /// one atomic byte request. The caller's observation predicate participates
    /// in every wait, including authentication changes after native Find.
    pub(crate) fn objects_with_storage(
        &self,
        count: usize,
        bytes: usize,
        before: impl Fn() -> Result<()>,
    ) -> Result<(
        Reservation<crate::managed::NativeIdentity>,
        crate::symmetric::memory::Credit,
    )> {
        self.references_with_storage(&self.objects, count, bytes, before, |_| Ok(()))
    }

    /// Output references escape to the caller and keep global credit. While
    /// preparing them, include this observation's private retained storage in
    /// the intrinsic bound, including close/Activity capacity discovered later.
    pub(crate) fn objects_with_storage_observing(
        &self,
        count: usize,
        bytes: usize,
        observation: &std::sync::Arc<crate::symmetric::memory::Budget>,
        before: impl Fn() -> Result<()>,
    ) -> Result<(
        Reservation<crate::managed::NativeIdentity>,
        crate::symmetric::memory::Credit,
    )> {
        if !observation.same_account(&self.session.inner.symmetric_budget) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignReferenceObservationBudget,
            )));
        }
        self.references_with_storage(&self.objects, count, bytes, before, |required| {
            observation.check_request(required)
        })
    }

    /// Admit a complete creation candidate without retaining separately
    /// credited close/Activity participants while its payload waits. Sharing
    /// this immutable admission context also keeps one progress token across
    /// the factory and its final possession checks.
    pub(crate) fn managed_with_storage(
        &self,
        count: usize,
        bytes: usize,
        before: impl Fn() -> Result<()>,
    ) -> Result<(
        Reservation<crate::managed::NativeIdentity>,
        crate::symmetric::memory::Credit,
    )> {
        self.references_with_storage(&self.managed, count, bytes, before, |_| Ok(()))
    }

    /// The payload includes observation-account metadata. Activity storage and
    /// payload share that private account through every later allocation and
    /// through publication into the returned identity. Only shared close
    /// workspace remains outside it; it is not this invocation's private graph.
    pub(crate) fn managed_with_observation_storage(
        &self,
        count: usize,
        bytes: usize,
        before: impl Fn() -> Result<()>,
    ) -> Result<(
        Reservation<crate::managed::NativeIdentity>,
        crate::symmetric::memory::Credit,
    )> {
        let (mut reservation, mut payload) = self.managed_with_storage(count, bytes, before)?;
        reservation.begin_observation(&mut payload)?;
        Ok((reservation, payload))
    }

    fn references_with_storage(
        &self,
        registry: &Registry<crate::managed::NativeIdentity>,
        count: usize,
        bytes: usize,
        before: impl Fn() -> Result<()>,
        check_additional: impl Fn(usize) -> Result<()>,
    ) -> Result<(
        Reservation<crate::managed::NativeIdentity>,
        crate::symmetric::memory::Credit,
    )> {
        loop {
            let result = registry.reserve_controlled(count, &self.admission, || {
                before()?;
                match self.session.reference_context(self.mode) {
                    Err(Error::Busy(crate::BusyReason::OperationOwnership(
                        crate::OperationOwnershipBusy::AdvancedOperation,
                    ))) if self.progress.can_maintain()
                        && self.session.entry.advanced_progress.cleanup_hint() =>
                    {
                        Ok(Some(()))
                    }
                    result => result.map(|()| None),
                }
            })?;
            match result {
                ControlledReference::Acquired(mut reservation) => {
                    let activity_bytes = count
                        .checked_mul(crate::managed::resource_activity_bytes()?)
                        .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::ActivityStorageAccounting,
                        )))?;
                    let (participants, activities, payload) = self
                        .session
                        .snapshot
                        .unknown_close
                        .reserve_reference_and_payload(
                        count,
                        activity_bytes,
                        bytes,
                        &self.session.inner.symmetric_budget,
                        &self.admission,
                        || {
                            before()?;
                            self.session.reference_context(self.mode)
                        },
                        |required| {
                            self.progress.check_retained(self.session, required)?;
                            check_additional(super::lifecycle_diagnostics::Store::including(
                                required,
                            )?)
                        },
                    )?;
                    reservation.prepare_close(participants)?;
                    reservation.prepare_activities(activities)?;
                    before()?;
                    return Ok((reservation, payload));
                }
                ControlledReference::Redirect(()) => self.progress.maintain_local(self.session)?,
            }
        }
    }
}
