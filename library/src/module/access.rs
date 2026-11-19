// SPDX-License-Identifier: Apache-2.0
//! Prepare and acquire token administration access with context revalidation.
//! Local maintenance is redirected outside byte admission before possession is retried.

use super::*;

impl<'a> TokenAccess<'a> {
    /// Byte admission for an administrative candidate. A marked local owner
    /// may hold the bytes needed by that candidate; redirect outside Wake to
    /// reclaim it before waiting. No native operation is replayed or cancelled.
    pub(crate) fn reserve_preparation(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        bytes: usize,
        retained_bytes: usize,
    ) -> Result<crate::symmetric::memory::Credit> {
        Self::reserve_preparation_scoped(
            inner,
            snapshot,
            permit,
            bytes,
            retained_bytes,
            local_maintenance::LocalMaintenance::Marked,
        )
    }

    pub(super) fn reserve_authentication_preparation(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        bytes: usize,
        retained_bytes: usize,
    ) -> Result<crate::symmetric::memory::Credit> {
        Self::reserve_preparation_scoped(
            inner,
            snapshot,
            permit,
            bytes,
            retained_bytes,
            local_maintenance::LocalMaintenance::Authentication,
        )
    }

    fn reserve_preparation_scoped(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        bytes: usize,
        retained_bytes: usize,
        scope: local_maintenance::LocalMaintenance,
    ) -> Result<crate::symmetric::memory::Credit> {
        use crate::symmetric::memory::ControlledReservation;
        use local_maintenance::LocalMaintenance;
        let authentication = matches!(scope, LocalMaintenance::Authentication);
        let admission = crate::admission_wait::current();
        let immediate = matches!(admission, crate::ResourceAdmission::Immediate)
            || crate::notify::in_callback();
        let mut attempted = false;
        let check = || {
            // Token maintenance requires normal module admission. This
            // permit authorizes only the token drain checked below.
            inner.state.check_admission(false)?;
            inner.availability.check_available()?;
            snapshot.check()?;
            snapshot.check_drain(permit)?;
            if snapshot
                .domain
                .advanced_count_invalid
                .load(Ordering::Acquire)
            {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                )));
            }
            Ok(())
        };
        loop {
            match inner.symmetric_budget.reserve_controlled_retaining(
                bytes,
                retained_bytes,
                &admission,
                || {
                    // The retained native owner may hold all available bytes.
                    // Reject withdrawal before waiting for credits it cannot
                    // safely release, including after each Wake notification.
                    check()?;
                    Ok(None::<()>)
                },
                || {
                    Ok(((!authentication || !immediate || !attempted)
                        && snapshot.domain.needs_local_cleanup.load(Ordering::Acquire)
                        && snapshot.domain.advanced_stranded.load(Ordering::Acquire) != 0
                        && snapshot.domain.closing_active.load(Ordering::Acquire) == 0)
                        .then_some(()))
                },
            )? {
                ControlledReservation::Acquired(credit) => return Ok(credit),
                ControlledReservation::Redirect(()) => {
                    // Wake has left scope, and no candidate/credit is held.
                    if !authentication {
                        drop(Self::new(inner, snapshot, permit)?);
                        continue;
                    }
                    attempted = true;
                    // Reclaim abandoned owners only. A live suspended ticket
                    // is unrelated to memory pressure and remains untouched.
                    let sweep = {
                        let state = inner.read()?;
                        snapshot.sweep_local(
                            &state,
                            permit,
                            true,
                            LocalMaintenance::Marked,
                            &crate::ResourceAdmission::Immediate,
                        )
                    };
                    let close_pending = match sweep {
                        Ok(()) => false,
                        Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::SessionClosePending,
                        ))) if !immediate => true,
                        Err(error) => return Err(error),
                    };
                    if !immediate
                        && (close_pending
                            || snapshot.domain.needs_local_cleanup.load(Ordering::Acquire))
                    {
                        // Drop every sweep guard before waiting. A rearmed hint
                        // alone cannot justify an immediate retry of the sweep.
                        snapshot.wait_writer_ready(inner, permit, true, scope, &admission)?;
                        let candidates = inner.session_ledger.local_candidates(&snapshot.domain)?;
                        for candidate in &candidates {
                            inner.session_ledger.wait_local_candidate(
                                candidate,
                                &snapshot.domain,
                                &admission,
                                true,
                                &check,
                            )?;
                        }
                    }
                }
            }
        }
    }

    /// Admit a complete private candidate before attempting token possession.
    /// A busy attempt destroys it before waiting, so an active owner can obtain
    /// memory to finish. Readiness only permits replanning, never native retry.
    pub(crate) fn prepare<T>(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, Self)> {
        Self::prepare_scoped(
            inner,
            snapshot,
            permit,
            local_maintenance::LocalMaintenance::Marked,
            prepare,
        )
    }

    pub(super) fn prepare_authentication<T>(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, Self)> {
        Self::prepare_scoped(
            inner,
            snapshot,
            permit,
            local_maintenance::LocalMaintenance::Authentication,
            prepare,
        )
    }

    fn prepare_scoped<T>(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        scope: local_maintenance::LocalMaintenance,
        mut prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, Self)> {
        let admission = crate::admission_wait::current();
        loop {
            admission.check_available()?;
            let candidate = prepare()?;
            let attempt = admission.try_once(|| {
                crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
                    Self::acquire(inner, snapshot, permit, true, scope)
                })
            });
            match attempt {
                Ok(access) => return Ok((candidate, access)),
                Err(Error::Busy(reason)) => {
                    drop(candidate);
                    if matches!(admission, crate::ResourceAdmission::Immediate)
                        || crate::notify::in_callback()
                    {
                        return Err(Error::Busy(reason));
                    }
                }
                Err(error) => return Err(error),
            }
            snapshot.wait_writer_ready(inner, permit, true, scope, &admission)?;
        }
    }

    pub(super) fn logout(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
    ) -> Result<Self> {
        Self::acquire(
            inner,
            snapshot,
            permit,
            true,
            local_maintenance::LocalMaintenance::Logout,
        )
    }

    pub(crate) fn new(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
    ) -> Result<Self> {
        Self::acquire(
            inner,
            snapshot,
            permit,
            true,
            local_maintenance::LocalMaintenance::Marked,
        )
    }

    pub(crate) fn refresh(inner: &'a Arc<Inner>, snapshot: &'a Arc<TokenSnapshot>) -> Result<Self> {
        Self::acquire(
            inner,
            snapshot,
            true,
            false,
            local_maintenance::LocalMaintenance::Invalidated,
        )
    }

    pub(super) fn acquire(
        inner: &'a Arc<Inner>,
        snapshot: &'a Arc<TokenSnapshot>,
        permit: bool,
        require_current: bool,
        scope: local_maintenance::LocalMaintenance,
    ) -> Result<Self> {
        let admission = crate::admission_wait::current();
        loop {
            admission.check_available()?;
            let logout = matches!(scope, local_maintenance::LocalMaintenance::Logout);
            let state = if logout {
                inner.check_logout_admission()?;
                let state = inner
                    .state
                    .read_checked(&|| inner.check_logout_admission())?;
                Inner::validate_logout(&state, snapshot)?;
                state
            } else {
                inner.read()?
            };
            // Never wait for a cooperative owner while holding the dispatch
            // it needs to finish. This attempt performs local maintenance only.
            let token = snapshot.write_with_local_maintenance(
                &state,
                permit,
                require_current,
                scope,
                &crate::ResourceAdmission::Immediate,
            );
            match token {
                Ok(token) => {
                    admission.check_available()?;
                    if logout {
                        Inner::validate_logout(&state, snapshot)?;
                    } else {
                        Inner::validate(&state)?;
                    }
                    return Ok(Self {
                        _token: token,
                        state,
                        _snapshot: snapshot.clone(),
                        _inner: inner.clone(),
                    });
                }
                Err(Error::Busy(reason)) => {
                    drop(state);
                    if matches!(admission, crate::ResourceAdmission::Immediate)
                        || crate::notify::in_callback()
                    {
                        return Err(Error::Busy(reason));
                    }
                }
                Err(error) => return Err(error),
            }
            // Wait without a module read as well as without dispatch: a
            // concurrent close needs the module writer to publish its result.
            // Readiness grants no native authority and performs no reclamation.
            snapshot.wait_writer_ready(inner, permit, require_current, scope, &admission)?;
            // The readiness writer/gate has left scope. Reacquire the normal
            // order and revalidate; never carry a writer into dispatch or renew
            // the caller's deadline after another contender wins.
        }
    }

    pub(crate) fn into_guards(
        self,
    ) -> (
        crate::admission_wait::ReadGuard<'a, State>,
        crate::admission_wait::WriteGuard<'a, ()>,
    ) {
        (self.state, self._token)
    }

    /// Publish token-scoped exclusion before returning its writer. This path
    /// retains only owned data/referents; it allocates nothing and runs no
    /// application destructor. An explicit close cannot free quarantined data.
    pub(crate) fn quarantine_returned<T: Send + 'static>(self, data: T, pending: bool) {
        self.state.native.mark_uncertain();
        if pending {
            self._snapshot
                .domain
                .pending_token_call
                .store(true, Ordering::Release);
            self.state.native.mark_unscoped_pending();
        }
        let image = self.state.native.image.clone();
        let snapshot = self._snapshot.clone();
        // Addressed calls retain an independent data box. Value-only controls
        // retain existing Arc referents; neither path lends a stack address.
        // Neither an Arc nor an image lease is a borrowed lock guard.
        std::mem::forget((data, image, snapshot));
        drop(self);
    }
}

impl std::ops::Deref for TokenAccess<'_> {
    type Target = State;

    fn deref(&self) -> &State {
        &self.state
    }
}

impl ModuleBinding {
    pub(crate) fn persistent_digest(self) -> Result<[u8; 32]> {
        match self.identity {
            provenance::BindingIdentity::File(digest) => Ok(digest),
            provenance::BindingIdentity::Local(_) => Err(Error::Unsupported(
                crate::UnsupportedReason::ModuleLifecycle(crate::ModuleLifecycleUnsupported::AutonomousArchiveRequiresAnObservedModuleFile),
            )),
        }
    }
}

impl Inner {
    pub fn read(&self) -> Result<crate::admission_wait::ReadGuard<'_, State>> {
        let state = self.state.read()?;
        Self::validate(&state)?;
        Ok(state)
    }

    pub fn read_admitted(
        &self,
        permit: bool,
    ) -> Result<crate::admission_wait::ReadGuard<'_, State>> {
        let state = self.state.read_admitted(permit)?;
        Self::validate(&state)?;
        Ok(state)
    }

    // Only explicit ModuleDrain session cleanup may read an uncertain owner.
    // StateLock independently requires possession of the active drain permit.
    pub(crate) fn read_module_cleanup(
        &self,
    ) -> Result<crate::admission_wait::ReadGuard<'_, State>> {
        let state = self.state.read_admitted(true)?;
        Self::validate_open(&state)?;
        Ok(state)
    }

    pub(super) fn validate_open(state: &State) -> Result<()> {
        if state.closed || state.native.finalization_succeeded() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ModuleClosed,
            )));
        }
        if state.native.finalization_incomplete() {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::ModuleFinalizationCompletionUnproven,
            )));
        }
        Ok(())
    }

    pub(crate) fn validate(state: &State) -> Result<()> {
        Self::validate_open(state)?;
        state.native.check_available()
    }

    /// Atomic-only half of Logout admission, including every resource wait.
    /// Authoritative registries are inspected outside Wake, under possession.
    pub(crate) fn check_logout_admission(&self) -> Result<()> {
        self.availability.check_native_authority()?;
        self.state.check_admission(false)?;
        self.availability.check_token_registry()?;
        self.slot_events.check_logout_admission()
    }

    /// Validate in dependency order while lifecycle possession is held.
    /// Closure and native authority come first: a cached identity cannot revive
    /// a finalized or withdrawn runtime. The snapshot and registry then establish
    /// the exact current token, rather than accepting an equal reused slot.
    /// Only after identity is established can completion checks authorize Logout;
    /// neither a pending call nor a blocking event may be treated as completed.
    pub(crate) fn validate_logout(state: &State, snapshot: &TokenSnapshot) -> Result<()> {
        Self::validate_open(state)?;
        state.native.check_native_authority()?;
        snapshot.check()?;
        // Generic uncertainty is not an identity proof. Verify the exact
        // current snapshot outside Wake; a poisoned registry cannot authorize C.
        let registry = state.token_registry()?;
        if !registry
            .tokens
            .iter()
            .any(|token| std::ptr::eq(token.as_ref(), snapshot))
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::TokenContextRetired,
            )));
        }
        drop(registry);
        if state.native.has_unscoped_pending() {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::NativeCallCompletionUnproven,
            )));
        }
        state.native.events.logout_ready()?;
        Ok(())
    }
}
