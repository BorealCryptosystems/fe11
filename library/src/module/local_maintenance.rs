// SPDX-License-Identifier: Apache-2.0
//! Token writers may reclaim marked, inactive local owners before waiting for
//! the advanced-owner population. This is not cancellation or native recovery.
//! A weak candidate list never extends notification payload/image lifetimes.
use super::{SessionEntry, SlotDomain, State, TokenSnapshot};
use crate::{
    admission_wait::{GateAdmission, ReadGuard, WriteGuard, WriterAdmission},
    Error, ResourceAdmission, Result,
};
use std::sync::{atomic::Ordering, Arc};

fn check_admission(admission: &ResourceAdmission) -> Result<()> {
    if let ResourceAdmission::WaitUntil {
        deadline,
        cancellation,
    } = admission
    {
        if cancellation.is_cancelled() {
            return Err(Error::AdmissionCancelled);
        }
        if std::time::Instant::now() >= *deadline {
            return Err(Error::AdmissionDeadline);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum LocalMaintenance {
    Marked,
    // Refresh keeps old graphs. Its caller separately proves returned execution
    // and retires their admission leases under this same physical slot writer.
    Invalidated,
    // Logout changes authentication, not ownership of native operation memory.
    // Keep suspended owners intact; the token writer still excludes dispatch.
    Logout,
}

/// A claimed notification is rearmed after guards leave scope if inspection
/// could not finish. Completing this pass never clears a concurrent publication.
struct SweepClaim<'a> {
    domain: &'a Arc<SlotDomain>,
    complete: bool,
}
impl Drop for SweepClaim<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.domain
                .needs_local_cleanup
                .store(true, Ordering::Release);
            self.domain.activity.notify();
        }
    }
}

impl TokenSnapshot {
    fn local_context(&self, permit: bool, require_current: bool) -> Result<()> {
        self.check_drain(permit)?;
        if require_current {
            self.check()?;
        }
        if self.domain.advanced_count_invalid.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        Ok(())
    }

    fn local_preconditions(&self, permit: bool, require_current: bool) -> Result<()> {
        self.local_context(permit, require_current)?;
        if self.domain.closing_active.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionClosePending,
            )));
        }
        Ok(())
    }

    /// Inspect the real global mutex poison, even when no new hint is present.
    /// No registry mutex is acquired while a Wake predicate is being evaluated.
    pub(super) fn local_ledgers(&self, state: &State) -> Result<()> {
        if self.domain.advanced_active.load(Ordering::Acquire) != 0
            && (state.session_ledger.local_poisoned() || state.operations.local_poisoned())
        {
            return Err(Error::Poisoned);
        }
        Ok(())
    }

    pub(super) fn write_with_local_maintenance(
        &self,
        state: &State,
        permit: bool,
        require_current: bool,
        scope: LocalMaintenance,
        admission: &ResourceAdmission,
    ) -> Result<WriteGuard<'_, ()>> {
        let mut attempted = false;
        loop {
            check_admission(admission)?;
            self.local_context(permit, require_current)?;
            if self.domain.closing_active.load(Ordering::Acquire) == 0 {
                self.local_ledgers(state)?;
            }
            let retain_operations = matches!(
                scope,
                LocalMaintenance::Logout | LocalMaintenance::Invalidated
            );
            let may_sweep = !retain_operations
                && (!attempted
                    || (matches!(admission, ResourceAdmission::WaitUntil { .. })
                        && !crate::notify::in_callback()));
            let result = self.domain.activity.write_with_maintenance(
                admission,
                crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenActivity),
                || {
                    self.local_context(permit, require_current)?;
                    if self.domain.closing_active.load(Ordering::Acquire) != 0 {
                        return Ok(Some(crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::SessionClosePending,
                        )));
                    }
                    Ok((!retain_operations
                        && self.domain.advanced_active.load(Ordering::Acquire) != 0)
                        .then_some(crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::AdvancedTokenActivity,
                        )))
                },
                || {
                    may_sweep
                        && self.domain.closing_active.load(Ordering::Acquire) == 0
                        && self.domain.needs_local_cleanup.load(Ordering::Acquire)
                },
            )?;
            match result {
                WriterAdmission::Acquired(writer) => {
                    self.local_preconditions(permit, require_current)?;
                    if !retain_operations
                        && self.domain.advanced_active.load(Ordering::Acquire) != 0
                    {
                        return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::AdvancedTokenActivity,
                        )));
                    }
                    return Ok(writer);
                }
                WriterAdmission::MaintenanceRequired => {
                    attempted = true;
                    self.sweep_local(state, permit, require_current, scope, admission)?;
                    // All sweep guards and weak candidates have left scope.
                    // Immediate performs one normal reevaluation; WaitUntil
                    // keeps its original absolute deadline and cancellation.
                }
            }
        }
    }

    /// Wait only for a reason to retry the nonblocking maintenance pass.
    /// No module read, dispatch, native call or owner mutation is retained here.
    pub(super) fn wait_writer_ready(
        &self,
        inner: &super::Inner,
        permit: bool,
        require_current: bool,
        scope: LocalMaintenance,
        admission: &ResourceAdmission,
    ) -> Result<()> {
        self.local_context(permit, require_current)?;
        if inner.session_ledger.local_poisoned() {
            return Err(Error::Poisoned);
        }
        if matches!(scope, LocalMaintenance::Logout) {
            // Context withdrawals notify the module Wake, not this activity's
            // private Wake. Binding also forwards activity releases to it.
            let writer = self.domain.activity.write_in_context(
                &inner.state.admission_wake(),
                admission,
                crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenActivity),
                || {
                    inner.check_logout_admission()?;
                    self.local_context(permit, require_current)?;
                    Ok(
                        (self.domain.closing_active.load(Ordering::Acquire) != 0).then_some(
                            crate::BusyReason::ModuleLifecycle(
                                crate::ModuleLifecycleBusy::SessionClosePending,
                            ),
                        ),
                    )
                },
            )?;
            drop(writer);
            inner.check_logout_admission()?;
            return admission.check_available();
        }
        let ready = self.domain.activity.write_with_maintenance(
            admission,
            crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenActivity),
            || {
                self.local_context(permit, require_current)?;
                if self.domain.closing_active.load(Ordering::Acquire) != 0 {
                    return Ok(Some(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::SessionClosePending,
                    )));
                }
                Ok((!matches!(
                    scope,
                    LocalMaintenance::Logout | LocalMaintenance::Invalidated
                ) && self.domain.advanced_active.load(Ordering::Acquire) != 0)
                    .then_some(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::AdvancedTokenActivity,
                    )))
            },
            || {
                !matches!(
                    scope,
                    LocalMaintenance::Logout | LocalMaintenance::Invalidated
                ) && self.domain.closing_active.load(Ordering::Acquire) == 0
                    && self.domain.needs_local_cleanup.load(Ordering::Acquire)
            },
        )?;
        match ready {
            WriterAdmission::Acquired(writer) => drop(writer),
            WriterAdmission::MaintenanceRequired => {
                // A blocked marked gate must become available before another
                // sweep. Weak candidates neither hold a module read nor keep
                // unrelated notification handlers alive while visiting peers.
                let candidates = inner.session_ledger.local_candidates(&self.domain)?;
                for candidate in &candidates {
                    inner.session_ledger.wait_local_candidate(
                        candidate,
                        &self.domain,
                        admission,
                        matches!(scope, LocalMaintenance::Marked),
                        || self.local_context(permit, require_current),
                    )?;
                }
            }
        }
        admission.check_available()
    }

    fn local_applicable(
        &self,
        state: &State,
        entry: &SessionEntry,
        scope: LocalMaintenance,
    ) -> bool {
        Arc::ptr_eq(&entry.snapshot.domain, &self.domain)
            && !state.native.is_uncertain()
            && !entry.closed.load(Ordering::Acquire)
            && !entry.close_attempted.load(Ordering::Acquire)
            && !entry.close_pending.load(Ordering::Acquire)
            && !entry.poisoned.load(Ordering::Acquire)
            && !entry.advanced_progress.is_poisoned()
            && entry.advanced_operation.load(Ordering::Acquire) != 0
            && entry.advanced_progress.cleanup_hint()
            && (matches!(scope, LocalMaintenance::Marked)
                || !entry.snapshot.valid.load(Ordering::Acquire))
    }

    /// One weak snapshot, a complete nonwaiting pass, then only blocked marked
    /// targets in captured order. No gate is retained while visiting another.
    pub(super) fn sweep_local(
        &self,
        state: &State,
        permit: bool,
        require_current: bool,
        scope: LocalMaintenance,
        admission: &ResourceAdmission,
    ) -> Result<()> {
        check_admission(admission)?;
        self.local_preconditions(permit, require_current)?;
        self.local_ledgers(state)?;
        if !self
            .domain
            .needs_local_cleanup
            .swap(false, Ordering::AcqRel)
        {
            return Ok(());
        }
        let mut claim = SweepClaim {
            domain: &self.domain,
            complete: false,
        };
        let mut candidates = match state.session_ledger.local_candidates(&self.domain) {
            Ok(candidates) => candidates,
            Err(Error::Poisoned) => {
                // Permanent global poison is reported by the real ledger; it
                // must not create a repeatedly rearmed, doomed sweep.
                claim.complete = true;
                return Err(Error::Poisoned);
            }
            Err(error) => return Err(error),
        };
        let reader = match self.domain.activity.read(
            admission,
            crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::AdvancedTokenActivity),
            || {
                self.local_context(permit, require_current)?;
                Ok(
                    (self.domain.closing_active.load(Ordering::Acquire) != 0).then_some(
                        crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::SessionClosePending,
                        ),
                    ),
                )
            },
        ) {
            Ok(reader) => reader,
            Err(Error::Busy(_)) => {
                self.local_preconditions(permit, require_current)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        self.local_preconditions(permit, require_current)?;
        for candidate in &mut candidates {
            check_admission(admission)?;
            let blocked = state.session_ledger.with_local_candidate(
                candidate,
                &self.domain,
                &reader,
                |entry| {
                    if !self.local_applicable(state, entry, scope) {
                        return Ok(false);
                    }
                    let gate = match entry.operation.try_lock() {
                        Ok(gate) => gate,
                        Err(std::sync::TryLockError::WouldBlock) => return Ok(true),
                        Err(std::sync::TryLockError::Poisoned(_)) => return Ok(false),
                    };
                    check_admission(admission)?;
                    if self.local_applicable(state, entry, scope) {
                        crate::session::maintain_retained_entry(state, entry, &reader, &gate)?;
                    }
                    Ok(false)
                },
            );
            match blocked {
                Ok(blocked) => candidate.blocked = blocked.unwrap_or(false),
                Err(Error::Poisoned) => {
                    claim.complete = true;
                    return Err(Error::Poisoned);
                }
                Err(error) => return Err(error),
            }
        }
        if matches!(admission, ResourceAdmission::Immediate) || crate::notify::in_callback() {
            check_admission(admission)?;
            claim.complete = !candidates.iter().any(|candidate| candidate.blocked);
            return Ok(());
        }
        for candidate in candidates.iter().filter(|candidate| candidate.blocked) {
            let result = state.session_ledger.with_local_candidate(
                candidate,
                &self.domain,
                &reader,
                |entry| {
                    self.wait_marked_target(
                        state,
                        entry,
                        &reader,
                        permit,
                        require_current,
                        scope,
                        admission,
                    )
                },
            );
            if let Err(error) = result {
                if matches!(error, Error::Poisoned) {
                    claim.complete = true;
                }
                return Err(error);
            }
        }
        claim.complete = true;
        check_admission(admission)?;
        Ok(())
    }

    fn wait_marked_target(
        &self,
        state: &State,
        entry: &SessionEntry,
        reader: &ReadGuard<'_, ()>,
        permit: bool,
        require_current: bool,
        scope: LocalMaintenance,
        admission: &ResourceAdmission,
    ) -> Result<()> {
        let gate = match entry.operation.acquire_while(admission, || {
            self.local_preconditions(permit, require_current)?;
            Ok(self.local_applicable(state, entry, scope))
        }) {
            Ok(GateAdmission::Acquired(gate)) => gate,
            Ok(GateAdmission::Revalidate) | Err(Error::Poisoned) => return Ok(()),
            Err(error) => return Err(error),
        };
        check_admission(admission)?;
        self.local_preconditions(permit, require_current)?;
        if self.local_applicable(state, entry, scope) {
            crate::session::maintain_retained_entry(state, entry, reader, &gate)?;
        }
        Ok(())
    }
}
