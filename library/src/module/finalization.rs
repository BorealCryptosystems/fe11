// SPDX-License-Identifier: Apache-2.0
//! Prepare finalization diagnostics and acquire shutdown authority.
//! Outstanding sessions, callbacks and foreign calls are checked before native Finalize.

use super::*;

impl FinalizationDiagnostics {
    pub(super) fn prepare(budget: &Arc<crate::symmetric::memory::Budget>) -> Result<Self> {
        let credit = budget
            .reserve(2 * crate::error::CompletionStorage::allocation_bytes())?
            .into_module_resident()?;
        Ok(Self {
            native: Some(crate::error::CompletionStorage::allocate()?),
            publication: Some(crate::error::CompletionStorage::allocate()?),
            _credit: credit,
        })
    }

    pub(super) fn replenish(&mut self) -> Result<()> {
        // The previous public invocation relinquished the exclusive lease
        // after transferring its result. A local repair may reuse the credit,
        // but must prepare fresh leaves before reacquiring native possession.
        if self.native.is_none() {
            self.native = Some(crate::error::CompletionStorage::allocate()?);
        }
        if self.publication.is_none() {
            self.publication = Some(crate::error::CompletionStorage::allocate()?);
        }
        Ok(())
    }
}

pub(super) fn prepare_finalization(
    inner: &Inner,
    permit: bool,
) -> Result<crate::admission_wait::WriteGuard<'_, FinalizationDiagnostics>> {
    let mut diagnostics = inner.finalization.write_in_context(
        &inner.state.admission_wake(),
        &crate::admission_wait::current(),
        crate::BusyReason::LocalAdmission(crate::LocalAdmissionBusy::ModuleActivity),
        || {
            inner.state.check_admission(permit)?;
            Ok(None)
        },
    )?;
    diagnostics.replenish()?;
    Ok(diagnostics)
}

pub(super) fn close_owner(
    inner: &Inner,
    permit: bool,
    retired: &mut FinalizationRetired,
) -> Result<()> {
    loop {
        let mut diagnostics = prepare_finalization(inner, permit)?;
        let result = finalize_owner(inner, permit, &mut diagnostics, retired);
        if matches!(
            result,
            Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing
            )))
        ) {
            // This refusal precedes C_Finalize. Release every possession,
            // preserve WaitUntil, then revalidate the complete lifecycle state.
            drop(diagnostics);
            inner.foreign.wait_callbacks(inner, None)?;
            continue;
        }
        return result;
    }
}

pub(super) fn finalize_owner(
    inner: &Inner,
    permit: bool,
    diagnostics: &mut FinalizationDiagnostics,
    retired: &mut FinalizationRetired,
) -> Result<()> {
    // prepare_finalization replenishes both leaves before returning the exclusive
    // diagnostic guard. close_owner calls this function once per prepared guard;
    // a retry reacquires/replenishes it. No other writer can consume these leaves.
    let native_diagnostic = diagnostics
        .native
        .take()
        .expect("finalization prepared")
        .bind("C_Finalize");
    let mut publication_diagnostic = Some(
        diagnostics
            .publication
            .take()
            .expect("publication prepared")
            .bind("C_Finalize"),
    );
    let closing = inner.state.reserve_close()?;
    let mut state = inner.state.write_closing(permit, closing.as_ref())?;
    if state.closed {
        return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
            crate::ModuleLifecycleRejection::ModuleClosed,
        )));
    }
    let ledger = state.session_ledger.clone();
    let already_finalized = state.native.finalization_succeeded();
    let mut foreign_callbacks = if already_finalized {
        None
    } else {
        Some(inner.foreign.seal_callbacks(None)?)
    };
    inner.foreign.prepare_retirement(&mut retired.foreign)?;
    if !already_finalized {
        inner.foreign.finalization_ready()?;
        // The explicit owner may recover returned, withdrawn work. `permit`
        // remains solely the StateLock drain authority, never a recovery flag.
        Inner::validate_open(&state)?;
        if state.native.execution_unproven() {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::NativeCallCompletionUnproven,
            )));
        }
    }
    let mut seal = if already_finalized
        || ledger.local_poisoned()
        || !ledger.is_empty()?
        || !state.operations.is_empty()?
    {
        retired.entries = ledger.finalization_candidates()?;
        if !already_finalized {
            for entry in &retired.entries {
                validate_finalization_entry(&state, entry)?;
                if entry.mode != crate::AdvancedSessionMode::Synchronous
                    && !entry.closed.load(Ordering::Acquire)
                {
                    return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::AsynchronousSessionRequiresExplicitClose,
                    )));
                }
            }
            state.operations.finalization_ready(&retired.entries)?;
        }
        ledger.seal_recovery(&retired.entries)?
    } else {
        ledger.seal_empty()?
    };
    // Mutex/notification callbacks caused by this native lifecycle invocation
    // must still enter. Their owners remain retained through its return.
    let callback_window = foreign_callbacks.as_ref().map(|seal| seal.native_window());
    let result = if already_finalized {
        native_diagnostic.finish(state.native.repair_finalization())
    } else if state.native.is_uncertain() {
        state.native.finalize_recovery(
            &mut retired.notifications,
            native_diagnostic,
            &mut publication_diagnostic,
        )
    } else {
        state.native.finalize(
            &mut retired.notifications,
            native_diagnostic,
            &mut publication_diagnostic,
        )
    };
    drop(callback_window);
    if state.native.finalization_succeeded() {
        if let Some(seal) = &mut foreign_callbacks {
            seal.commit();
        }
    }
    if result.is_ok() || state.native.is_uncertain() {
        seal.commit();
    }
    // A local refusal before Finalize dispatch restores the previous admission;
    // success or native uncertainty keeps all new reservations excluded.
    result?;
    // Native's raw OK already rejects every dispatch through validate_open.
    // Keep State.closed false until these local publications finish, so a later
    // close request can repair them without issuing a second native Finalize.
    let quarantined = state.native.is_uncertain();
    // finalize_admitted consumes this leaf only when returning a compounded
    // pre-dispatch error. Its successful and repair paths leave it present;
    // result? above excludes every consuming path before this take.
    publication_diagnostic
        .take()
        .expect("successful finalization keeps publication diagnostic")
        .finish((|| {
            inner.foreign.retire(None, &mut retired.foreign)?;
            retired.operations = Some(state.operations.take_finalized(
                &retired.entries,
                state.native.image.clone(),
                quarantined,
            )?);
            retired.sessions =
                Some(ledger.take_finalized(state.native.image.clone(), quarantined)?);
            state.close_local();
            Ok(())
        })())
}

/// This is an instance-finalization gate, not a permission to reuse a handle.
/// The module writer excludes normal calls; each retained owner must also have
/// returned and have permanently lost its ordinary dispatch authority.
pub(super) fn validate_finalization_entry(state: &State, entry: &Arc<SessionEntry>) -> Result<()> {
    if entry.snapshot.domain.has_pending_token_call() {
        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
            crate::ModuleLifecycleBusy::NativeTokenCallPending,
        )));
    }
    // Query accounting before taking the session gate. A collective attempt
    // has no individual CloseControl; it must supply its own exact return proof.
    let collective = entry.credit.collective_completion()?;
    if collective.is_some_and(|completion| !completion.return_known()) {
        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
            crate::ModuleLifecycleBusy::SessionCloseCompletionUnproven,
        )));
    }
    let _session = match entry.operation.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionActivity,
            )))
        }
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
    };
    let closed = entry.closed.load(Ordering::Acquire);
    if !state.native.is_uncertain()
        && !closed
        && !entry.poisoned.load(Ordering::Acquire)
        && entry.snapshot.valid.load(Ordering::Acquire)
    {
        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
            crate::ModuleLifecycleBusy::UsableSessionPreventsRecoveryFinalization,
        )));
    }
    if entry.recovery.has_pending_call() {
        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
            crate::ModuleLifecycleBusy::NativeSessionCallPending,
        )));
    }
    let close = entry
        .close_control
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match close.as_ref().map(|control| control.phase) {
        Some(phase) if phase.execution_unproven() => {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionCloseCompletionUnproven,
            )));
        }
        None if entry.close_attempted.load(Ordering::Acquire) && collective.is_none() => {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::SessionCloseResultAbsent,
            )));
        }
        _ => {}
    }
    Ok(())
}
