Cause contracts for `ModuleLifecycleBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AdvancedTokenActivity"></a>

### `AdvancedTokenActivity`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `matches!(admission, crate::ResourceAdmission::Immediate)`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `matches!(admission, crate::ResourceAdmission::Immediate)`.
- `TokenSnapshot::write_with_local_maintenance` — `src/module/local_maintenance.rs`.
- `TokenSnapshot::write_with_local_maintenance` — `src/module/local_maintenance.rs`. Enclosing true branch: `!retain_operations && self.domain.advanced_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::wait_writer_ready` — `src/module/local_maintenance.rs`.
- `TokenSnapshot::sweep_local` — `src/module/local_maintenance.rs`.
- `TokenSnapshot::wait_recovery_population` — `src/module/token_snapshot.rs`. Enclosing true branch: `active != stranded || previous == Some((active, stranded))`.


<a id="cause-AsynchronousSessionRequiresExplicitClose"></a>

### `AsynchronousSessionRequiresExplicitClose`


Local detection/handling phase and implementation owner:

- `finalize_owner` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `entry.mode != crate::AdvancedSessionMode::Synchronous && !entry.closed.load(Ordering::Acquire)`.


<a id="cause-ModuleFinalizationCompletionUnproven"></a>

### `ModuleFinalizationCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Uncertainty::check_native_authority` — `src/native.rs`. Enclosing match alternative: `value if value == AdmissionLifecycle::Finalizing as u8`.
- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `self.finalization_incomplete()`.
- `Inner::validate_open` — `src/module/access.rs`. Enclosing true branch: `state.native.finalization_incomplete()`.


<a id="cause-NativeCallCompletionUnproven"></a>

### `NativeCallCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Native::finalize_admitted` — `src/native.rs`. Enclosing true branch: `self.execution_unproven()`.
- `Inner::validate_logout` — `src/module/access.rs`. Enclosing true branch: `state.native.has_unscoped_pending()`.
- `finalize_owner` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `state.native.execution_unproven()`.


<a id="cause-NativeRecoveryCallPending"></a>

### `NativeRecoveryCallPending`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `batch .entries_for_close() .any(|entry| entry.recovery.has_pending_call())`.


<a id="cause-NativeSessionCallPending"></a>

### `NativeSessionCallPending`


Local detection/handling phase and implementation owner:

- `TokenContext::logout_entry` — `src/module/authentication.rs`. Enclosing true branch: `entry.recovery.has_pending_call()`.
- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `entry.recovery.has_pending_call()`.
- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing true branch: `entry.recovery.has_pending_call()`.


<a id="cause-NativeTokenCallPending"></a>

### `NativeTokenCallPending`


Local detection/handling phase and implementation owner:

- `TokenContext::logout_entry` — `src/module/authentication.rs`. Enclosing true branch: `self.snapshot.domain.has_pending_token_call()`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `snapshot.domain.has_pending_token_call()`.
- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `entry.snapshot.domain.has_pending_token_call()`.
- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing true branch: `entry.snapshot.domain.has_pending_token_call()`.


<a id="cause-SessionActivity"></a>

### `SessionActivity`


Local detection/handling phase and implementation owner:

- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing match alternative: `Err(std::sync::TryLockError::WouldBlock)`.
- `Session::prepare_administrative_access` — `src/session/preparation.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.
- `TokenContext::open_session_mode_with_notify` — `src/module/sessions.rs`.
- `CloseGuards<'a>::acquire` — `src/session/close_admission.rs`. Enclosing match alternative: `Err(TryLockError::WouldBlock)`.


<a id="cause-SessionCloseCompletionUnproven"></a>

### `SessionCloseCompletionUnproven`


Local detection/handling phase and implementation owner:

- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `collective.is_some_and(|completion| !completion.return_known())`.
- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing match alternative: `Some(phase) if phase.execution_unproven()`.
- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing match alternative: `ClosePhase::Issued`.


<a id="cause-SessionClosePending"></a>

### `SessionClosePending`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::local_preconditions` — `src/module/local_maintenance.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::write_with_local_maintenance` — `src/module/local_maintenance.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::wait_writer_ready` — `src/module/local_maintenance.rs`. Enclosing true branch: `matches!(scope, LocalMaintenance::Logout)`.
- `TokenSnapshot::wait_writer_ready` — `src/module/local_maintenance.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::sweep_local` — `src/module/local_maintenance.rs`.
- `CloseResident::plan` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `self.loaned.load(Ordering::Acquire)`.
- `CloseResident::borrow` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `matches!(state.ownership, Ownership::Loaned(_))`.
- `TokenSnapshot::read_activity_on` — `src/module/token_snapshot.rs`.
- `TokenSnapshot::read_activity_on` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::module_cleanup_activity` — `src/module/token_snapshot.rs`.
- `TokenSnapshot::module_cleanup_activity` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::context_authentication_activity_on` — `src/module/token_snapshot.rs`.
- `TokenSnapshot::context_authentication_activity_on` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::maintenance_activity_with_policy` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::maintenance_activity_with_policy` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.
- `TokenSnapshot::wait_recovery_population` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.closing_active.load(Ordering::Acquire) != 0`.


<a id="cause-TokenActivity"></a>

### `TokenActivity`


Local detection/handling phase and implementation owner:

- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `matches!(admission, crate::ResourceAdmission::Immediate)`.
- `TokenSnapshot::write_with_local_maintenance` — `src/module/local_maintenance.rs`.
- `TokenSnapshot::wait_writer_ready` — `src/module/local_maintenance.rs`. Enclosing true branch: `matches!(scope, LocalMaintenance::Logout)`.
- `TokenSnapshot::wait_writer_ready` — `src/module/local_maintenance.rs`.
- `TokenSnapshot::maintenance_activity_with_policy` — `src/module/token_snapshot.rs`.
- `TokenSnapshot::wait_recovery_population` — `src/module/token_snapshot.rs`.


<a id="cause-TokenActivityDuringContextAuthentication"></a>

### `TokenActivityDuringContextAuthentication`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::context_authentication_activity_on` — `src/module/token_snapshot.rs`. Enclosing match alternative: `Some(domain)`.
- `TokenSnapshot::context_authentication_activity_on` — `src/module/token_snapshot.rs`. Enclosing match alternative: `None`.


<a id="cause-TokenActivityDuringSessionClose"></a>

### `TokenActivityDuringSessionClose`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::close_activity` — `src/module/token_snapshot.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.
- `busy_token` (module-level helper) — `src/session/close_admission.rs`.
- `CloseGuards::local` — `src/session/close_admission.rs`. Token-reader contention invoking `busy_token`.
- `CloseGuards::local` — `src/session/close_admission.rs`. Session-gate contention invoking `busy_token`.


<a id="cause-TokenAdministration"></a>

### `TokenAdministration`


Local detection/handling phase and implementation owner:

- `TokenSnapshot::read_activity_on` — `src/module/token_snapshot.rs`. Enclosing match alternative: `Some(context)`.
- `TokenSnapshot::read_activity_on` — `src/module/token_snapshot.rs`. Enclosing match alternative: `None`.
- `TokenSnapshot::module_cleanup_activity` — `src/module/token_snapshot.rs`.


<a id="cause-TokenDraining"></a>

### `TokenDraining`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/module/foreign/call.rs`. Enclosing true branch: `!matches!(mode, AdmissionMode::Module) && domain.draining.load(Ordering::Acquire) != matches!(mode, AdmissionMode::Token)`.
- `TokenContext::reserve_drain` — `src/module/sessions.rs`.
- `TokenSnapshot::check_drain` — `src/module/token_snapshot.rs`. Enclosing true branch: `self.domain.draining.load(Ordering::Acquire) != permit`.


<a id="cause-UsableSessionPreventsRecoveryFinalization"></a>

### `UsableSessionPreventsRecoveryFinalization`


Local detection/handling phase and implementation owner:

- `validate_finalization_entry` (module-level helper) — `src/module/finalization.rs`. Enclosing true branch: `!state.native.is_uncertain() && !closed && !entry.poisoned.load(Ordering::Acquire) && entry.snapshot.valid.load(Ordering::Acquire)`.

