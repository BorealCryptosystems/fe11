// SPDX-License-Identifier: Apache-2.0
//! Maintain module runtime state and publish context retirement.
//! Failure scopes withdraw the affected authority without inventing native cleanup.

use super::*;

impl SlotDomain {
    pub(super) fn new() -> Self {
        Self {
            foreign_epoch: std::sync::atomic::AtomicU64::new(0),
            foreign_callbacks_closed: AtomicBool::new(false),
            foreign_callback_window: AtomicBool::new(false),
            activity: crate::admission_wait::ResourceRwLock::new(()),
            pending_token_call: AtomicBool::new(false),
            advanced_active: std::sync::atomic::AtomicUsize::new(0),
            advanced_stranded: std::sync::atomic::AtomicUsize::new(0),
            advanced_count_invalid: AtomicBool::new(false),
            needs_local_cleanup: AtomicBool::new(false),
            closing_active: std::sync::atomic::AtomicUsize::new(0),
            close_epoch: std::sync::atomic::AtomicU64::new(0),
            transition: crate::admission_wait::ResourceGate::new(
                crate::BusyReason::SessionLifecycle(crate::SessionLifecycleBusy::SessionTransition),
            ),
            admission: std::sync::OnceLock::new(),
            draining: AtomicBool::new(false),
        }
    }

    pub(crate) fn has_pending_token_call(&self) -> bool {
        self.pending_token_call.load(Ordering::Acquire)
    }

    pub(crate) fn retire_foreign_epoch(&self, observed: u64) {
        // Saturation seals future foreign admission; no ABA through wraparound.
        let _ = self.foreign_epoch.compare_exchange(
            observed,
            observed.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.activity.notify();
    }
}

impl SessionEntry {
    /// Local withdrawal forbids old-handle dispatch, not memory retention.
    pub(crate) fn native_handle_retired(&self) -> bool {
        self.credit.native_handle_retired() || !self.snapshot.valid.load(Ordering::Acquire)
    }
}

impl TokenRegistry {
    pub fn advance(&mut self) -> Result<()> {
        self.revision = self.revision.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::TokenRegistryRevisionExhausted,
            ),
        ))?;
        Ok(())
    }
}

impl State {
    pub(super) fn close_local(&mut self) {
        self.closed = true;
        self.native.close_admission();
    }

    /// Complete a recorded Close refusal without replaying its native call or
    /// its already-published authentication change. The caller owns the exact
    /// CloseState and advances each phase before another fallible operation.
    pub(crate) fn publish_close_failure_scope(
        &self,
        entry: &SessionEntry,
        scope: crate::native_return::FailureScope,
        progress: &mut crate::advanced::CloseFailureProgress,
    ) -> Result<()> {
        use crate::advanced::CloseFailureProgress;
        use crate::native_return::FailureScope;
        if *progress == CloseFailureProgress::Complete {
            return Ok(());
        }
        match scope {
            FailureScope::Token => {
                let mut registry = self.token_registry()?;
                if *progress == CloseFailureProgress::Scope {
                    entry.snapshot.forget_authentication()?;
                    *progress = CloseFailureProgress::AuthenticationDone;
                }
                if *progress == CloseFailureProgress::AuthenticationDone {
                    if registry.tokens.iter().any(|token| {
                        token.generation == entry.snapshot.generation
                            && token.capabilities.identity.slot
                                == entry.snapshot.capabilities.identity.slot
                    }) {
                        registry.advance()?;
                    }
                    *progress = CloseFailureProgress::Complete;
                }
            }
            FailureScope::Session => {
                entry.credit.retire_native_handle()?;
                entry.snapshot.notify_admission();
                *progress = CloseFailureProgress::Complete;
            }
            FailureScope::Module | FailureScope::None => {
                // The irreversible runtime observation preceded publication.
                *progress = CloseFailureProgress::Complete;
            }
        }
        Ok(())
    }

    /// Withdraw the exact local session on an established native invalidity.
    /// A family's conservative sequence scope is not proof of session closure;
    /// its operation owner independently decides retention and further progress.
    /// This changes admission and, for a proven lost handle, its native quota.
    /// No frame, key lease, callback or retained-byte credit is released.
    pub(crate) fn apply_session_failure(
        &self,
        entry: &SessionEntry,
        rv: CK_RV,
        scope: crate::native_return::FailureScope,
    ) {
        self.native.observe_runtime_return(rv);
        if crate::native_return::native_context_scope(rv)
            == crate::native_return::FailureScope::Session
        {
            if entry.credit.retire_native_handle().is_err() {
                self.native.mark_uncertain();
            }
            entry.poisoned.store(true, Ordering::Release);
        }
        self.apply_failure_scope(&entry.snapshot, scope);
    }

    pub fn token_registry(&self) -> Result<std::sync::MutexGuard<'_, TokenRegistry>> {
        self.current_tokens.lock().map_err(|_| {
            self.native.mark_token_registry_unverifiable();
            Error::Poisoned
        })
    }

    pub fn apply_failure_scope(
        &self,
        token: &TokenSnapshot,
        scope: crate::native_return::FailureScope,
    ) {
        use crate::native_return::FailureScope;
        match scope {
            FailureScope::Module => self.native.mark_uncertain(),
            FailureScope::Token => {
                if self.retire_context(token).is_err() {
                    self.native.mark_uncertain();
                }
            }
            FailureScope::Session => token.notify_admission(),
            FailureScope::None => {}
        }
    }

    pub fn check_session_return(
        &self,
        entry: &SessionEntry,
        call: crate::native_return::SessionCall,
        rv: CK_RV,
        may_have_effect: bool,
    ) -> Result<()> {
        use crate::native_return::FailureScope;
        let scope = call.scope(rv);
        if scope == FailureScope::Session {
            entry.poisoned.store(true, Ordering::Release);
        }
        self.apply_session_failure(entry, rv, scope);
        check(
            rv,
            call.function(),
            may_have_effect
                || matches!(scope, FailureScope::Token | FailureScope::Module)
                || self.native.is_uncertain(),
        )
    }

    pub fn check_attribute_return(&self, handle: CK_SESSION_HANDLE, rv: CK_RV) -> Result<()> {
        use crate::native_return::{attribute_scope, FailureScope};
        let scope = attribute_scope(rv);
        // An attribute access refusal does not establish token-wide logout.
        // Preserve the native error without changing the global role/epoch.
        if scope == FailureScope::Module {
            self.native.mark_uncertain();
        } else if scope != FailureScope::None {
            match self.session_ledger.for_handle(handle) {
                Ok(entry) => {
                    if scope == FailureScope::Session {
                        entry.poisoned.store(true, Ordering::Release);
                    }
                    self.apply_session_failure(&entry, rv, scope);
                }
                Err(_) => self.native.mark_uncertain(),
            }
        }
        check(
            rv,
            "C_GetAttributeValue",
            matches!(scope, FailureScope::Token | FailureScope::Module)
                || self.native.is_uncertain(),
        )
    }

    // Retire only the generation that reported a native failure. Advancing the
    // short registry revision prevents a concurrent discovery from publishing
    // a replacement based on an observation made before that failure.
    pub fn retire_context(&self, token: &TokenSnapshot) -> Result<()> {
        let _notify = self.session_ledger.notify_admission_on_drop();
        let mut registry = self.token_registry()?;
        token.invalidate();
        token.forget_authentication()?;
        let result = if registry.tokens.iter().any(|t| {
            t.generation == token.generation
                && t.capabilities.identity.slot == token.capabilities.identity.slot
        }) {
            registry.advance()
        } else {
            Ok(())
        };
        drop(registry);
        result.map_err(|error| {
            self.native.mark_uncertain();
            error
        })
    }

    pub fn retire_slot(&self, slot: CK_SLOT_ID) -> Result<()> {
        self.retire_slot_into(slot, None)
    }

    pub(super) fn retire_slot_into(
        &self,
        slot: CK_SLOT_ID,
        mut generations: Option<&mut Vec<u64>>,
    ) -> Result<()> {
        let _notify = self.session_ledger.notify_admission_on_drop();
        let mut registry = self.token_registry()?;
        if let Some(generations) = generations.as_mut() {
            // A caller needing the retired generation set receives all of it
            // or an allocation error before any retirement. Error cleanup that
            // only withdraws the slot needs no vector or byte admission.
            generations
                .try_reserve_exact(registry.tokens.len())
                .map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::TokenRetirementAllocation,
                    ))
                })?;
        }
        // No native calls or alias-registry acquisition under this short mutex.
        for t in registry
            .tokens
            .iter()
            .filter(|t| t.capabilities.identity.slot == slot as u64)
        {
            t.invalidate();
            t.forget_authentication()?;
            if let Some(generations) = generations.as_mut() {
                generations.push(t.generation);
            }
        }
        let revision = registry.advance();
        drop(registry);
        revision.map_err(|error| {
            self.native.mark_uncertain();
            error
        })
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if self.closed
            || self.native.finalization_succeeded()
            || self.native.uncertainty_flag().initialization_lost()
        {
            // Old generations have no authority over numeric handles in a
            // successor. Retention is separate from successful native cleanup.
            self.operations.quarantine();
            return;
        }
        if !self.native.allows_implicit_cleanup() {
            // Attachment never acquires implicit cleanup authority over the
            // application's existing initialization, including opening errors.
            if !self.native.finalization_succeeded() {
                self.native.mark_uncertain();
                self.operations.quarantine();
            }
            return;
        }
        // No State owner remains, but a loader alias may still own the shared
        // dispatch. Destruction never waits or overlaps that native call.
        let _dispatch = match self
            .native
            .dispatch
            .as_ref()
            .map(|dispatch| dispatch.enter(&crate::ResourceAdmission::Immediate, None))
            .transpose()
        {
            Ok(guard) => guard,
            Err(_) => {
                self.native.mark_uncertain();
                self.operations.quarantine();
                return;
            }
        };
        // Recheck after possession: the alias may have withdrawn the image.
        if self.native.is_uncertain() {
            self.operations.quarantine();
            return;
        }
        let entries = match self.session_ledger.entries_for_close() {
            Ok(v) => v,
            Err(_) => {
                self.native.mark_uncertain();
                self.operations.quarantine();
                return;
            }
        };
        for entry in entries {
            if entry.native_handle_retired() {
                // No deferred Close may target a number reused after retirement.
                // Retain the old graph; withdrawal is not a successful close.
                self.native.mark_uncertain();
                break;
            }
            let close_session = match crate::native::functions::resolve(
                self.native.table.C_CloseSession,
                "C_CloseSession",
            ) {
                Ok(call) => call,
                Err(_) => {
                    self.native.mark_uncertain();
                    break;
                }
            };
            if entry.close_attempted.swap(true, Ordering::AcqRel) {
                self.native.mark_uncertain();
                break;
            }
            if self.native.record("C_CloseSession").is_err() {
                self.native.mark_uncertain();
                break;
            }
            // SAFETY: remaining live handles belong to this sole native owner.
            let rv = unsafe { close_session(entry.handle) };
            if rv != CKR_OK as fe11_sys::CK_RV || self.native.is_uncertain() {
                let _ = entry.credit.quarantine();
                self.apply_session_failure(&entry, rv, crate::native_return::close_scope(rv));
                // Sole-owner destruction: retain the mapping while cleanup
                // is unproven; there is no other live token to admit here.
                // A callback may have quarantined the image even if this
                // particular close returned OK. Do not release retained data
                // or overwrite that stronger uncertainty with this result.
                self.native.mark_uncertain();
                break;
            }
            entry.closed.store(true, Ordering::Release);
            entry.snapshot.notify_admission();
            entry.recovery.release_closed();
            if self.operations.release_closed(&entry).is_err() {
                self.native.mark_uncertain();
                break;
            }
            entry.unpublished_object.store(false, Ordering::Release);
            if entry.credit.release().is_err() {
                self.native.mark_uncertain();
                break;
            }
        }
        // Untracked uncertain opens also prevent a presumed-safe finalize/unload.
        if !self.session_ledger.is_empty().unwrap_or(false) {
            self.native.mark_uncertain();
        }
        if self.native.is_uncertain() {
            self.operations.quarantine();
        }
    }
}
