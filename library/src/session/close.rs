// SPDX-License-Identifier: Apache-2.0
//! Close or reap session owners using their native completion evidence.
//! Local cleanup, explicit close and Drop preserve distinct outcomes and authority.

use super::*;

impl Session {
    // Acquisition is module -> token -> session; field order releases in reverse.
    /// Local-only cleanup from a scope which owns no module/token/session
    /// guard. Every missing gate is tried once; this never waits or calls C.
    pub(crate) fn try_local_cleanup<T>(
        &self,
        action: impl FnOnce(&LocalOwnership<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        let state = match self.inner.state.observe() {
            Ok(state) => state,
            // Only contention is optional. A permanent capacity/configuration
            // failure must propagate through the ordinary error branch.
            Err(Error::Busy(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        Inner::validate(&state)?;
        let token = match self.snapshot.domain.activity.try_read() {
            Ok(token) => token,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
        };
        let session = match self.entry.operation.try_lock() {
            Ok(session) => session,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
        };
        self.entry_common(&state)?;
        action(&LocalOwnership {
            target: LocalTarget::Current(self),
            state: &state,
            _session: &session,
            _token: LocalTokenProof::Shared { _guard: &token },
        })
        .map(Some)
    }

    /// Close this session and its created session objects. Busy preserves this
    /// borrowed Session and performs no C_CloseSession. Native failures retain
    /// credits and are never retried by Drop or reap.
    pub fn close(&self) -> Result<()> {
        let mut diagnostics = None;
        close_entry(
            &self.inner,
            &self.entry,
            CleanupAdmission::Ordinary,
            &mut diagnostics,
        )
    }
}

pub(crate) fn reap_entries(
    inner: &Arc<Inner>,
    maximum: usize,
    context: Option<&Arc<crate::module::TokenSnapshot>>,
    client: Option<crate::module::ClientId>,
    admission: CleanupAdmission,
    diagnostics: &mut Option<lifecycle_diagnostics::Loan>,
) -> Result<usize> {
    let entries = inner
        .session_ledger
        .deferred_for(maximum, context, client)?;
    let mut closed = 0;
    for entry in entries {
        // A preceding success/Busy has no compound error retained here.
        drop(diagnostics.take());
        match close_entry(inner, &entry, admission, diagnostics) {
            Ok(()) => closed += 1,
            // Do not hide a permanent ResourceLimitExceeded as deferred work.
            Err(Error::Busy(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(closed)
}

impl CloseOwnership<'_> {
    pub(crate) fn entry(&self) -> &SessionEntry {
        self.entry
    }
}

pub(crate) fn close_entry(
    inner: &Arc<Inner>,
    entry: &Arc<SessionEntry>,
    admission: CleanupAdmission,
    diagnostics: &mut Option<lifecycle_diagnostics::Loan>,
) -> Result<()> {
    *diagnostics = Some(lifecycle_diagnostics::Store::loan(
        entry,
        &crate::ResourceAdmission::Immediate,
    )?);
    // These owners outlive every guard below, including early return/unwind.
    // Any barrier retained by the control outlives object/frame restitution.
    use crate::advanced::{
        CloseFailureProgress, CloseFailureRetention, ClosePhase, ClosePublication,
    };
    let mut _retired_control = None;
    let mut _retired_preparation = None;
    let mut _retired_scope = None;
    let mut _retired_operation = None;
    let mut _retired_frames = None;
    let s = if matches!(admission, CleanupAdmission::Module) {
        inner.read_module_cleanup()?
    } else {
        inner.read_admitted(false)?
    };
    // Select once under module/token/transition/session possession. Maintenance
    // and any retained receipt use the existing protected path. The receipt
    // guard publishes a retained local-close signal before possession is lost.
    let guards = super::close_admission::CloseGuards::acquire(&s, entry, admission)?;
    let mut control = super::close_scope::CloseReceipt::new(entry, &s.native);
    if entry.native_handle_retired()
        && !matches!(
            control.as_ref().map(|control| control.phase),
            Some(ClosePhase::Returned { .. })
        )
    {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::NativeSessionHandleRetired,
        )));
    }
    if entry.snapshot.domain.has_pending_token_call() {
        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
            crate::ModuleLifecycleBusy::NativeTokenCallPending,
        )));
    }
    if entry.recovery.has_pending_call() {
        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
            crate::ModuleLifecycleBusy::NativeSessionCallPending,
        )));
    }
    if entry.closed.load(Ordering::Acquire) && control.is_none() {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionClosed,
        )));
    }
    if entry.close_attempted.load(Ordering::Acquire) && control.is_none() {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionCloseAlreadyAttempted,
        )));
    }
    // Automatic completion of an internal admission cannot authorise cleanup
    // after token retirement. Explicit owner maintenance remains a separate API.

    let diagnostic = diagnostics
        .as_mut()
        .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SessionLifecycleDiagnosticAbsent,
        )))?
        .completion("C_CloseSession")?;
    if control.is_none() {
        if !guards.is_local() {
            crate::managed::reserve_session_close(inner, &s, entry, &mut _retired_preparation)?;
            let reservation = _retired_preparation.as_mut().expect("prepared close owner");
            reservation.protect_for_close(entry.credit.uid())?;
            entry.snapshot.advance_close_epoch()?;
        }
        let ticket = entry.credit.closing()?;
        // All fallible preparation completed; invalidation precedes possible C
        // effects and stays in force on refusal, uncertainty, pending or unwind.
        if let Some(reservation) = _retired_preparation.as_mut() {
            reservation.revoke_unknown();
        }
        *control = Some(crate::advanced::CloseState {
            ticket,
            name: *b"C_CloseSession\0",
            phase: ClosePhase::Prepared,
            scope: if guards.is_local() {
                super::close_scope::CloseScope::Local { signal: None }
            } else {
                super::close_scope::CloseScope::Protected {
                    reservation: _retired_preparation.take(),
                }
            },
        });
        // Under session/object ownership this revokes all creator aliases before C.
        // closed itself is set only after native success, never inferred from refusal.
        entry.close_attempted.store(true, Ordering::Release);
        // A resource waiter owns only observation metadata and cannot infer a
        // close from credit return: Pending/refusal may retain every buffer.
        // Wake every admission domain after invalidation and before native
        // close: quota/readiness waiters cannot rely on a later credit return.
        // No catalogue mutex is held here; their predicates only revalidate.
        inner.context_wakes.notify();
    }
    let close = control.as_mut().expect("prepared close owner");
    let completing = matches!(
        close.phase,
        ClosePhase::Pending
            | ClosePhase::Returned {
                async_completion: true,
                ..
            }
    );
    let (rv, returned_now) = match close.phase {
        ClosePhase::Prepared => {
            let close_session =
                crate::native::functions::resolve(s.native.table.C_CloseSession, "C_CloseSession")?;
            s.native.record("C_CloseSession")?;
            close.phase = ClosePhase::Issued;
            // SAFETY: table and session possession remain owned. Either all
            // affected objects are protected, or this entry never attempted
            // creation and has no retained owners. The transition excludes an
            // Open reusing the native handle before this close is published.
            let code = unsafe { close_session(entry.handle) };
            close.record_return(code, false);
            s.native.observe_runtime_return(code);
            (code, true)
        }
        ClosePhase::Pending => {
            // An unexpected synchronous PENDING does not establish an async
            // protocol. Keep the owner and report its original pending result.
            if entry.mode != crate::AdvancedSessionMode::Asynchronous {
                return check(CKR_PENDING, "C_CloseSession", true);
            }
            let call = s
                .native
                .asynchronous
                .and_then(|functions| functions.complete)
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
                )))?;
            s.native.record("C_AsyncComplete")?;
            close.phase = ClosePhase::Issued;
            // SAFETY: this exact close is pending, and its stable name remains
            // owned here until the observation returns. Close has no output.
            let code = unsafe { call(entry.handle, close.name.as_mut_ptr(), std::ptr::null_mut()) };
            close.record_return(code, true);
            s.native.observe_async_return(code);
            (code, true)
        }
        ClosePhase::Issued => {
            // A Rust unwind is not proof of a native return. No second close or
            // speculative observation is admitted from this state.
            s.native.mark_uncertain();
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionCloseCompletionUnproven,
            )));
        }
        ClosePhase::Returned { code, .. } => (code, false),
    };
    let observe_context = |_| {
        // Publish native closure before any fallible local bookkeeping. This
        // owner retains its separate staged failure-publication protocol.
        entry
            .close_pending
            .store(rv == CKR_PENDING, Ordering::Release);
        if rv == CKR_OK {
            entry.closed.store(true, Ordering::Release);
        }
        if returned_now {
            match crate::native_return::close_scope(rv) {
                crate::native_return::FailureScope::Session => {
                    entry.credit.withdraw_native_handle();
                    entry.poisoned.store(true, Ordering::Release);
                }
                crate::native_return::FailureScope::Token => entry.snapshot.invalidate(),
                _ => {}
            }
        }
    };
    use crate::native_return::protocol::PendingInspection;
    let returned = if completing {
        PendingInspection::completed("C_CloseSession", rv, observe_context)
    } else {
        PendingInspection::returned("C_CloseSession", rv, observe_context)
    };
    // Close and its completion have no output descriptor or result bytes.
    returned.inspect(|| Ok(())).resolve(|_, cause| cause)?;
    if returned_now {}
    if rv == CKR_PENDING {
        // Do not finish/quarantine the closing credit: this is an outstanding
        // close, not a completed failed close. No hidden polling or second close.
        if entry.mode != crate::AdvancedSessionMode::Asynchronous {
            s.native.mark_uncertain();
        }
        return check(rv, "C_CloseSession", true);
    }
    let ticket = close.ticket;
    let ClosePhase::Returned { publication, .. } = &mut close.phase else {
        unreachable!("non-pending close return recorded");
    };
    if rv == CKR_OK
        && (*publication == ClosePublication::Quarantined
            || (*publication == ClosePublication::Observed && s.native.is_uncertain()))
    {
        // A concurrent boundary failure or callback can quarantine the image
        // while CloseSession is in C. Its success code cannot override that
        // quarantine. Keep the control (including its native name), recovery
        // frames and operation reachable through this exact Entry/UID.
        entry.poisoned.store(true, Ordering::Release);
        let local = if *publication == ClosePublication::Quarantined {
            Ok(())
        } else {
            entry.credit.finish_close(ticket, false).map(|()| {
                *publication = ClosePublication::Quarantined;
            })
        };
        return diagnostic.finish_native(rv, local.and_then(|()| Inner::validate(&s)));
    }
    if *publication == ClosePublication::Observed {
        // Classify native uncertainty once. A subsequent local publication
        // failure does not erase the recorded return or convert its repair
        // into another native call or a fictitious pending observation.
        *publication = if rv == CKR_OK {
            ClosePublication::Releasing
        } else {
            ClosePublication::Failure {
                progress: CloseFailureProgress::Accounting,
                retention: if s.native.is_uncertain() {
                    CloseFailureRetention::Quarantined
                } else {
                    CloseFailureRetention::Ordinary
                },
            }
        };
    }
    if rv != CKR_OK {
        entry.poisoned.store(true, Ordering::Release);
        let ClosePublication::Failure {
            progress,
            retention,
        } = publication
        else {
            unreachable!("refused close has failure publication");
        };
        let local = (|| -> Result<()> {
            if *progress == CloseFailureProgress::Accounting {
                entry.credit.finish_close(ticket, false)?;
                *progress = CloseFailureProgress::Classifying;
            }
            if *progress == CloseFailureProgress::Classifying {
                // A local receipt proved the ledger empty before C and keeps
                // that scope across repair. Never manufacture a writer proof.
                if !close.scope.is_local() {
                    let proof = CloseOwnership {
                        entry,
                        _token: guards.writer().ok_or(Error::Poisoned)?,
                        _session: &guards.session,
                    };
                    s.operations.classify_failed_close(&proof)?;
                }
                *progress = CloseFailureProgress::Scope;
            }
            s.publish_close_failure_scope(entry, crate::native_return::close_scope(rv), progress)
        })();
        if local.is_err() {
            *retention = CloseFailureRetention::Quarantined;
            s.native.mark_uncertain();
        }
        if *progress == CloseFailureProgress::Complete
            && *retention == CloseFailureRetention::Ordinary
        {
            // Keep the exact receipt, but release transient barriers only after
            // all guards leave scope. Reap and explicit close cannot replay C.
            _retired_scope = Some(close.scope.release());
        }
        diagnostic.finish_native(rv, local)?;
        return check(rv, "C_CloseSession", rv != CKR_SESSION_HANDLE_INVALID);
    }
    let local = (|| -> Result<()> {
        entry.snapshot.notify_admission();
        if *publication == ClosePublication::Releasing {
            crate::managed::forget_creator(inner, entry.credit.uid())?;
            *publication = ClosePublication::CreatorForgotten;
        }
        if *publication == ClosePublication::CreatorForgotten {
            let last_session = !s
                .session_ledger
                .has_other_slot(entry.slot, entry.credit.uid())?;
            if last_session {
                // The ledger counts Fe11 owners, not all native sessions.
                entry.snapshot.forget_authentication()?;
            }
            *publication = ClosePublication::AuthenticationExpired;
        }
        if *publication == ClosePublication::AuthenticationExpired {
            _retired_operation = s.operations.take_closed(entry)?;
            _retired_frames = Some(entry.recovery.take_closed());
            *publication = ClosePublication::FramesRetired;
        }
        if *publication == ClosePublication::FramesRetired {
            // Keep the ledger's strong Entry anchor until all other fallible
            // publication is complete, including across an explicit repair.
            entry.credit.finish_close(ticket, true)?;
            entry.deferred_close.store(false, Ordering::Release);
            entry.unpublished_object.store(false, Ordering::Release);
            *publication = ClosePublication::Complete;
        }
        Ok(())
    })();
    if local.is_err() {
        s.native.mark_uncertain();
    }
    if local.is_ok() {
        _retired_control = control.take();
    }
    diagnostic.finish(local)
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.drop_behavior == SessionDropBehavior::KeepOpen
            || self.entry.closed.load(Ordering::Acquire)
            || self.entry.close_attempted.load(Ordering::Acquire)
            || self.entry.deferred_close.load(Ordering::Acquire)
        {
            return;
        }
        // Drop performs only immediate local acquisition. This says nothing
        // about the duration of C_CloseSession if native dispatch is admitted.
        let mut diagnostics = None;
        let result = crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
            close_entry(
                &self.inner,
                &self.entry,
                CleanupAdmission::Ordinary,
                &mut diagnostics,
            )
        });
        if result.is_err() && !self.entry.close_attempted.load(Ordering::Acquire) {
            // The ledger already owns this entry and its snapshot/possession.
            // No native wait, retry or credit release is hidden in this transfer.
            self.entry.deferred_close.store(true, Ordering::Release);
        }
    }
}
