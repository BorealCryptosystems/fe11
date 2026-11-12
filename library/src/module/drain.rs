// SPDX-License-Identifier: Apache-2.0
//! Drive explicit session draining, deferred cleanup and module shutdown.
//! Drain ownership controls cleanup without treating every retained call as completed.

use super::*;

impl ModuleDrain {
    /// Progress an already admitted operation during this owner's drain.
    /// This does not permit a new operation or bypass context withdrawal.
    pub fn poll_advanced(
        &self,
        session: &crate::AdvancedSession,
        ticket: &mut crate::OperationTicket,
    ) -> Result<crate::OperationProgress> {
        if !Arc::ptr_eq(&self.inner, &session.session.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ForeignDrainingSession,
            )));
        }
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        session.poll_admitted(
            ticket,
            crate::session::CleanupAdmission::Module,
            &mut diagnostics,
        )
    }

    /// Explicit cleanup of an advanced session, including a pending native close.
    pub fn close_advanced_session(
        &self,
        session: &crate::AdvancedSession,
    ) -> Result<crate::AdvancedCloseStatus> {
        let mut diagnostics = None;
        if !Arc::ptr_eq(&self.inner, &session.session.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ForeignDrainingSession,
            )));
        }
        crate::advanced::close_status(
            crate::session::close_entry(
                &self.inner,
                &session.session.entry,
                crate::session::CleanupAdmission::Module,
                &mut diagnostics,
            ),
            session.mode(),
        )
    }

    /// Close a session belonging to this owner, including a token already drained.
    /// Its activity/ownership guards still apply; token drain flags are preserved.
    pub fn close_session(&self, session: &crate::Session) -> Result<()> {
        let mut diagnostics = None;
        if !Arc::ptr_eq(&self.inner, &session.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ForeignDrainingSession,
            )));
        }
        crate::session::close_entry(
            &self.inner,
            &session.entry,
            crate::session::CleanupAdmission::Module,
            &mut diagnostics,
        )
    }

    /// Attempt bounded first closures of deferred resources owned by this module.
    pub fn reap_sessions(&self, maximum: usize) -> Result<usize> {
        let mut diagnostics = None;
        crate::session::reap_entries(
            &self.inner,
            maximum,
            None,
            None,
            crate::session::CleanupAdmission::Module,
            &mut diagnostics,
        )
    }

    /// Finalize when no usable session or unresolved native work remains.
    /// Recovery may retire unusable synchronous session owners, but cannot
    /// complete pending calls or close an asynchronous session on their behalf.
    pub fn close(&self) -> Result<()> {
        self.inner.foreign.wait_callbacks(&self.inner, None)?;
        let mut retired = FinalizationRetired::default();
        close_owner(&self.inner, true, &mut retired)
    }
}

impl Drop for ModuleDrain {
    fn drop(&mut self) {
        self.inner.state.end_drain();
        self.inner.context_wakes.notify();
    }
}

impl TokenDrain {
    /// Progress an already admitted operation of this drained token context.
    pub fn poll_advanced(
        &self,
        session: &crate::AdvancedSession,
        ticket: &mut crate::OperationTicket,
    ) -> Result<crate::OperationProgress> {
        if !Arc::ptr_eq(&self.context.inner, &session.session.inner)
            || !Arc::ptr_eq(&self.context.snapshot, &session.session.snapshot)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ForeignDrainingSession,
            )));
        }
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        session.poll_admitted(
            ticket,
            crate::session::CleanupAdmission::Token,
            &mut diagnostics,
        )
    }

    /// Close an advanced session of this drained context. Pending closure keeps
    /// its allocations and can be observed again through this same permit.
    pub fn close_advanced_session(
        &self,
        session: &crate::AdvancedSession,
    ) -> Result<crate::AdvancedCloseStatus> {
        let mut diagnostics = None;
        if !Arc::ptr_eq(&self.context.inner, &session.session.inner)
            || !Arc::ptr_eq(&self.context.snapshot, &session.session.snapshot)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ForeignDrainingSession,
            )));
        }
        crate::advanced::close_status(
            crate::session::close_entry(
                &self.context.inner,
                &session.session.entry,
                crate::session::CleanupAdmission::Token,
                &mut diagnostics,
            ),
            session.mode(),
        )
    }

    /// Explicitly recover this drained token generation's sessions. Retained
    /// older generations are not released by closing the current slot.
    /// Busy performs no dispatch. Success proves session closure, not absence of
    /// effects of interrupted requests. Refresh/select/login remain explicit.
    pub fn recover_sessions(&self) -> Result<()> {
        self.context.lifecycle_access.require_owner()?;
        self.context.inner.foreign.wait_callbacks(
            &self.context.inner,
            Some(self.context.snapshot.capabilities.identity.slot),
        )?;
        let mut foreign_retired = foreign::Retired::default();
        let mut diagnostics: Option<crate::session::lifecycle_diagnostics::RecoveryDiagnostic> =
            None;
        // Every potentially last owner is declared before coordination guards.
        // On success, error or unwind its destructor therefore runs after them.
        let mut batch;
        let mut closed_frames = Vec::new();
        let mut closed_operations = Vec::new();
        let mut close_reservation = None;
        let mut recovery_owners: Option<_> = None;
        let snapshot = &self.context.snapshot;
        snapshot.check()?;
        let foreign_epoch = snapshot.domain.foreign_epoch.load(Ordering::Acquire);
        let admission = crate::admission_wait::current();
        let mut previous_population = None;
        let mut maintenance_attempted = false;
        let (s, _activity, call, observe, mut info, slot, _foreign_callbacks) = loop {
            let (s, _activity) = loop {
                snapshot.recovery_population()?;
                if snapshot.domain.closing_active.load(Ordering::Acquire) == 0 {
                    let state = self.context.inner.read()?;
                    snapshot.local_ledgers(&state)?;
                }
                // Every population wait is outside module/token/session guards.
                // An unlock notification alone cannot satisfy A == S > N.
                let allow_maintenance = !maintenance_attempted
                    || (matches!(admission, crate::ResourceAdmission::WaitUntil { .. })
                        && !crate::notify::in_callback());
                match snapshot.wait_recovery_population(
                    &admission,
                    previous_population,
                    allow_maintenance,
                )? {
                    crate::admission_wait::WriterReadiness::Ready => {}
                    crate::admission_wait::WriterReadiness::MaintenanceRequired => {
                        maintenance_attempted = true;
                        let state = self.context.inner.read()?;
                        snapshot.sweep_local(
                            &state,
                            true,
                            false,
                            local_maintenance::LocalMaintenance::Marked,
                            &admission,
                        )?;
                        continue;
                    }
                }
                let state = self.context.inner.read()?;
                let writer = match snapshot.domain.activity.try_write() {
                    Ok(writer) => writer,
                    Err(std::sync::TryLockError::WouldBlock) => {
                        if matches!(admission, crate::ResourceAdmission::Immediate) {
                            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                                crate::ModuleLifecycleBusy::TokenActivity,
                            )));
                        }
                        continue;
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
                };
                let (active, stranded) = snapshot.recovery_population()?;
                if active < stranded {
                    return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                    )));
                }
                if snapshot.domain.closing_active.load(Ordering::Acquire) != 0 || active > stranded
                {
                    if matches!(admission, crate::ResourceAdmission::Immediate) {
                        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::AdvancedTokenActivity,
                        )));
                    }
                    previous_population = None;
                    continue;
                }
                let owners =
                    recovery_owners.insert(state.operations.recovery_owners(&snapshot.domain)?);
                owners.prove(&state.session_ledger)?;
                if owners.len() > stranded {
                    return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                    )));
                }
                if owners.len() == stranded {
                    break (state, writer);
                }
                if matches!(admission, crate::ResourceAdmission::Immediate) {
                    return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::AdvancedTokenActivity,
                    )));
                }
                previous_population = Some((active, stranded));
                drop(writer);
                drop(state);
                // A previously extracted owner can still contribute to A/S. Its
                // actual Drop, not our own unlock, must change the observed pair.
                drop(recovery_owners.take());
            };
            snapshot.check()?;
            let slot = snapshot.capabilities.identity.slot as CK_SLOT_ID;
            self.context
                .inner
                .foreign
                .collective_close_ready(slot as u64)?;
            self.context
                .inner
                .foreign
                .prepare_retirement(&mut foreign_retired)?;
            if !s
                .token_registry()?
                .tokens
                .iter()
                .any(|t| Arc::ptr_eq(t, snapshot))
            {
                return Err(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::TokenContextReplaced,
                    ),
                ));
            }
            let call = s.native.table.C_CloseAllSessions.ok_or(Error::Rejected(
                crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::CCloseAllSessionsUnavailable,
                ),
            ))?;
            let observe = s.native.table.C_GetTokenInfo.ok_or(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::CGetTokenInfoUnavailable,
                ),
            ))?;
            let info = crate::native::frame::NativeFrame::new(crate::native::output::token_info())?;
            // A token-wide invocation may still be executing even when no
            // session receipt exists. It excludes collective close on this slot.
            if snapshot.domain.has_pending_token_call() {
                return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::NativeTokenCallPending,
                )));
            }
            // Snapshot and all output slots precede the first native observation.
            batch = s.session_ledger.prepare_generation_recovery(
                &snapshot.capabilities.identity,
                snapshot.generation,
            )?;
            if batch
                .entries_for_close()
                .any(|entry| entry.recovery.has_pending_call())
            {
                return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::NativeRecoveryCallPending,
                )));
            }
            let diagnostic_entry = batch.entries_for_close().next().cloned();
            if !diagnostics
                .as_ref()
                .is_some_and(|prepared| prepared.matches(diagnostic_entry.as_ref()))
            {
                // No native observation/effect has occurred. Refill outside
                // every guard and discard captures before byte admission.
                drop(_activity);
                drop(s);
                drop(close_reservation.take());
                drop(recovery_owners.take());
                drop(batch);
                drop(info);
                drop(std::mem::take(&mut closed_frames));
                drop(std::mem::take(&mut closed_operations));
                drop(diagnostics.take());
                diagnostics = Some(
                    crate::session::lifecycle_diagnostics::RecoveryDiagnostic::prepare(
                        diagnostic_entry.as_ref(),
                        &self.context.inner.symmetric_budget,
                        &admission,
                        || {
                            self.context.inner.state.check_admission(false)?;
                            snapshot.check_drain(true)
                        },
                    )?,
                );
                previous_population = None;
                continue;
            }
            let count = batch.entries_for_close().count();
            closed_frames.try_reserve(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoverySnapshotAllocation,
                ))
            })?;
            closed_operations.try_reserve(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoverySnapshotAllocation,
                ))
            })?;
            // One deduplicated set across the whole native batch. Per-session
            // acquisition could take the same anonymous writer twice and deadlock.
            crate::managed::reserve_recovery_batch(
                &self.context.inner,
                &batch,
                &mut close_reservation,
            )?;
            // reserve_recovery_batch installs the outer owner before any fallible
            // preparation and never removes it. Only its successful return reaches
            // this borrow; waits release it explicitly before restarting the loop.
            let blocked = close_reservation
                .as_mut()
                .expect("prepared recovery owner")
                .protect_for_recovery(&batch, &admission)?;
            if let Some(activity) = blocked {
                // No C call has occurred. Release the full partial possession set
                // and the slot/module guards before honoring the caller's wait.
                // Keep the batch anchored solely for the ownership predicate.
                drop(_activity);
                drop(s);
                drop(close_reservation.take());
                drop(recovery_owners.take());
                activity.wait_for_recovery(&batch, &admission)?;
                drop(batch);
                previous_population = None;
                continue;
            }
            let callbacks = match self
                .context
                .inner
                .foreign
                .seal_callbacks(Some((slot as u64, snapshot.domain.clone())))
            {
                Ok(seal) => seal,
                Err(Error::Busy(crate::BusyReason::ExternalExecution(
                    crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing,
                ))) => {
                    drop(_activity);
                    drop(s);
                    drop(close_reservation.take());
                    drop(recovery_owners.take());
                    self.context
                        .inner
                        .foreign
                        .wait_callbacks(&self.context.inner, Some(slot as u64))?;
                    previous_population = None;
                    continue;
                }
                Err(error) => return Err(error),
            };
            break (s, _activity, call, observe, info, slot, callbacks);
        };
        let diagnostic = diagnostics
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::CollectiveCloseDiagnosticAbsent,
            )))?
            .take()?;
        // No owner can disappear safely on a Rust unwind after the first native
        // effect. Ordinary error returns below explicitly finish this guard.
        let mut sequence = RecoverySequence {
            native: &s.native,
            armed: true,
            native_inflight: false,
        };
        let _callback_window = _foreign_callbacks.native_window();
        let outcome = (|| -> Result<()> {
            s.native.record("C_GetTokenInfo")?;
            // SAFETY: slot writer excludes local native activity; NativeFrame
            // retains its aligned output and mapping on an unexpected Pending.
            sequence.entering_native_call();
            let rv = unsafe { observe(slot, &mut *info) };
            sequence.native_call_returned();
            info.retain_if_pending(rv, &s.native);
            s.apply_failure_scope(
                snapshot,
                crate::native_return::slot_scope("C_GetTokenInfo", rv),
            );
            check_discovery(&s.native, rv, "C_GetTokenInfo")?;
            let observed = TokenIdentity {
                slot: slot as u64,
                manufacturer: info.manufacturerID,
                model: info.model,
                serial: info.serialNumber,
            };
            if observed != snapshot.capabilities.identity {
                s.retire_context(snapshot)?;
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::RecoveryTokenIdentityChanged,
                )));
            }
            for entry in batch.entries_for_close() {
                entry.snapshot.invalidate();
                entry.snapshot.forget_authentication()?;
            }
            s.retire_context(snapshot)?;
            crate::managed::revoke_token(&s, slot)?;
            s.session_ledger.start_recovery(&mut batch)?;

            // Admission precedes the exact dispatch counter.
            // If recording itself refuses, reconcile the started ledger just
            // as for a stale context; no native close was attempted.
            let prepared = Inner::validate(&s).and_then(|()| s.native.record("C_CloseAllSessions"));
            if let Err(error) = prepared {
                if s.session_ledger
                    .finish_recovery(
                        &mut batch,
                        crate::session_budget::RecoveryCompletion::NotDispatched,
                    )
                    .is_err()
                {
                    s.native.mark_uncertain();
                }
                return Err(error);
            }
            // SAFETY: the explicit drain owns the slot writer and protected
            // creator set. No retained numeric handle is passed to this call.
            sequence.entering_native_call();
            let rv = unsafe { call(slot) };
            sequence.native_call_returned();
            let proved = rv == CKR_OK && !s.native.is_uncertain();
            let completion = if crate::native_return::call_memory_returned(rv) {
                crate::session_budget::RecoveryCompletion::Returned { closed: proved }
            } else {
                // This evidence cannot depend on a nonempty session batch.
                s.native.mark_unscoped_pending();
                crate::session_budget::RecoveryCompletion::Unproven
            };
            let recorded = s
                .session_ledger
                .record_recovery_completion(&batch, completion);
            s.native.observe_runtime_return(rv);

            if rv == CKR_PENDING {
                // Even an empty close batch can leave token-wide execution
                // pending. Per-session close receipts cannot represent it.
                snapshot
                    .domain
                    .pending_token_call
                    .store(true, Ordering::Release);
                s.native.mark_unscoped_pending();
            }

            let local = (|| -> Result<()> {
                recorded?;
                if proved {
                    self.context
                        .inner
                        .foreign
                        .retire(Some((slot as u64, foreign_epoch)), &mut foreign_retired)?;
                    for entry in batch.entries_for_close() {
                        closed_frames.push(entry.recovery.take_closed());
                        closed_operations.push(s.operations.take_closed(entry)?);
                        crate::managed::forget_creator(&self.context.inner, entry.credit.uid())?;
                    }
                }
                s.session_ledger.finish_recovery(&mut batch, completion)
            })();
            if local.is_err() {
                s.native.mark_uncertain();
            }
            s.apply_failure_scope(snapshot, crate::native_return::recover_scope(rv));
            // Keep the actual collective-close return if a concurrent
            // withdrawal prevents local publication. Never reissue the close.
            diagnostic.finish_native(
                rv,
                local.and_then(|()| {
                    if rv == CKR_OK {
                        Inner::validate(&s)
                    } else {
                        Ok(())
                    }
                }),
            )?;
            check(rv, "C_CloseAllSessions", true)?;
            Ok(())
        })();
        sequence.armed = false;
        outcome
    }

    /// Authenticate through this drain once previously admitted operations finish.
    pub fn login_as(&self, role: LoginRole, pin: impl Into<crate::PinRequest>) -> Result<()> {
        let mut diagnostic = None;
        self.context
            .login_admitted(role, pin.into(), None, true, &mut diagnostic)
    }

    /// Authenticate a named user via C_LoginUser while draining this token.
    pub fn login_user(
        &self,
        role: LoginRole,
        pin: impl Into<crate::PinRequest>,
        user_name: Vec<u8>,
    ) -> Result<()> {
        let mut diagnostic = None;
        self.context
            .login_admitted(role, pin.into(), Some(user_name), true, &mut diagnostic)
    }

    /// End authentication and revoke private aliases during this drain.
    /// Suspended operations remain owned; native calls must have returned.
    pub fn logout(&self) -> Result<()> {
        let mut diagnostics = None;
        self.context.logout_admitted(true, &mut diagnostics)
    }

    pub(super) fn check_session(&self, session: &crate::Session) -> Result<()> {
        if !Arc::ptr_eq(&self.context.inner, &session.inner)
            || !Arc::ptr_eq(&self.context.snapshot, &session.snapshot)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ForeignDrainingSession,
            )));
        }
        Ok(())
    }

    /// Close an exact-context session during this drain. Busy retains its owner;
    /// calls already in flight are never cancelled or closed underneath.
    pub fn close_session(&self, session: &crate::Session) -> Result<()> {
        let mut diagnostics = None;
        self.check_session(session)?;
        crate::session::close_entry(
            &self.context.inner,
            &session.entry,
            crate::session::CleanupAdmission::Token,
            &mut diagnostics,
        )
    }

    /// Attempt bounded deferred first closures only within this drained context.
    /// Other tokens and previously failed native closures are never selected.
    pub fn reap_sessions(&self, maximum: usize) -> Result<usize> {
        let mut diagnostics = None;
        crate::session::reap_entries(
            &self.context.inner,
            maximum,
            Some(&self.context.snapshot),
            None,
            crate::session::CleanupAdmission::Token,
            &mut diagnostics,
        )
    }

    /// Request USER PIN initialization through this exact context's session.
    /// The native module checks its role and session mode.
    pub fn initialize_user_pin(
        &self,
        session: &crate::Session,
        pin: impl Into<crate::PinRequest>,
    ) -> Result<()> {
        self.check_session(session)?;
        let mut diagnostic = None;
        session.initialize_pin_admitted(pin.into(), true, &mut diagnostic)
    }

    /// Request a PIN change through a session belonging to this exact context.
    /// The native session state determines the affected PIN; no role is inferred
    /// from a cached observation and no login is performed on the caller's behalf.
    pub fn change_pin(
        &self,
        session: &crate::Session,
        old: SecretPin,
        new: SecretPin,
    ) -> Result<()> {
        self.check_session(session)?;
        let mut diagnostic = None;
        session.change_pin_admitted(
            crate::PinChange::ProvidedPair { old, new },
            true,
            &mut diagnostic,
        )
    }

    /// Change both PINs using the explicitly chosen source while draining.
    pub fn change_pin_with(
        &self,
        session: &crate::Session,
        change: crate::PinChange,
    ) -> Result<()> {
        self.check_session(session)?;
        let mut diagnostic = None;
        session.change_pin_admitted(change, true, &mut diagnostic)
    }
}

impl Drop for TokenDrain {
    fn drop(&mut self) {
        self.context
            .snapshot
            .domain
            .draining
            .store(false, Ordering::Release);
        self.context.snapshot.domain.activity.notify();
        self.context.snapshot.notify_admission();
        self.context.inner.session_ledger.notify_admission();
    }
}
