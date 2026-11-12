Cause contracts for `ExternalExecutionBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ForeignJoinSourceClaimed"></a>

### `ForeignJoinSourceClaimed`


Local detection/handling phase and implementation owner:

- `ForeignWork::begin_admitted` — `src/module/foreign/call.rs`. Enclosing true branch: `source.phase != Phase::Detached`.


<a id="cause-ForeignCallbackActive"></a>

### `ForeignCallbackActive`


Local detection/handling phase and implementation owner:

- `Registry::finalization_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.callbacks_active(None)?`.
- `Registry::successor_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.callbacks_active(None)?`.
- `Registry::wait_callbacks` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.callbacks_active(slot)?`.


<a id="cause-ForeignCallbackActiveOrClosing"></a>

### `ForeignCallbackActiveOrClosing`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ExternalExecution( crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing, )))`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ExternalExecution( crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing, )))`.
- `close_owner` (module-level helper) — `src/module/finalization.rs`.
- `ForeignWork::begin_admitted` — `src/module/foreign/call.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ExternalExecution( crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing, )))`.
- `Registry::seal_callbacks` — `src/module/foreign/registry.rs`. Enclosing true branch: `*gate || self.callbacks_active(slot.as_ref().map(|(id, _)| *id))?`.


<a id="cause-ForeignCallbackAdmissionClosed"></a>

### `ForeignCallbackAdmissionClosed`


Local detection/handling phase and implementation owner:

- `Registry::callback_admission` — `src/module/foreign/registry.rs`. Enclosing true branch: `*gate && !self.callback_window.load(Ordering::Acquire) || work .and_then(|work| work.domain.as_ref()) .is_some_and(|domain| { domain.foreign_callbacks_closed.load(Ordering::Acquire) && !domain.foreign_callback_window.load(Ordering::Acquire) })`.


<a id="cause-ForeignCollectiveCloseLacksTerminationContract"></a>

### `ForeignCollectiveCloseLacksTerminationContract`


Local detection/handling phase and implementation owner:

- `Registry::collective_close_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignNativeExecutionUnresolved"></a>

### `ForeignNativeExecutionUnresolved`


Local detection/handling phase and implementation owner:

- `Registry::logout_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.
- `Registry::successor_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignNativeWorkUnresolved"></a>

### `ForeignNativeWorkUnresolved`


Local detection/handling phase and implementation owner:

- `Registry::finalization_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignOperationCallbackActive"></a>

### `ForeignOperationCallbackActive`


Local detection/handling phase and implementation owner:

- `Registry::session_close_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `work.callbacks.load(Ordering::Acquire) != 0`.


<a id="cause-ForeignSessionActivity"></a>

### `ForeignSessionActivity`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::register_work` — `src/module/foreign.rs`.


<a id="cause-ForeignSessionCallbackActive"></a>

### `ForeignSessionCallbackActive`


Local detection/handling phase and implementation owner:

- `Registry::session_close_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `session.callbacks.load(Ordering::Acquire) != 0`.


<a id="cause-ForeignSessionCloseLacksTerminationContract"></a>

### `ForeignSessionCloseLacksTerminationContract`


Local detection/handling phase and implementation owner:

- `Registry::session_close_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignSessionExecutionActive"></a>

### `ForeignSessionExecutionActive`


Local detection/handling phase and implementation owner:

- `Registry::check_session` — `src/module/foreign/registry.rs`. Enclosing true branch: `matches!( phase, Phase::Reserved(_) | Phase::Issued(_) | Phase::Uncertain )`.


<a id="cause-ForeignSessionNativeCallPending"></a>

### `ForeignSessionNativeCallPending`


Local detection/handling phase and implementation owner:

- `Registry::check_session` — `src/module/foreign/registry.rs`. Enclosing true branch: `phase == Phase::Progressable(Progress::Pending)`.


<a id="cause-ForeignSlotCallbackAdmissionClosed"></a>

### `ForeignSlotCallbackAdmissionClosed`


Local detection/handling phase and implementation owner:

- `Registry::seal_callbacks` — `src/module/foreign/registry.rs`. Enclosing true branch: `let Some((_, domain)) = &slot`.


<a id="cause-ForeignTokenActivity"></a>

### `ForeignTokenActivity`


Local detection/handling phase and implementation owner:

- `admit` (module-level helper) — `src/module/foreign/call.rs`. Enclosing match alternative: `ForeignAccess::Session`.
- `admit` (module-level helper) — `src/module/foreign/call.rs`. Enclosing match alternative: `ForeignAccess::Token`.
- `contention` (module-level helper) — `src/module/foreign/call.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.


<a id="cause-ForeignTokenCallbackActive"></a>

### `ForeignTokenCallbackActive`


Local detection/handling phase and implementation owner:

- `Registry::slot_successor_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.callbacks_active(Some(slot))?`.
- `Registry::maintenance_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.callbacks_active(Some(slot))?`.
- `Registry::collective_close_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.callbacks_active(Some(slot))?`.


<a id="cause-ForeignTokenExecutionUnresolved"></a>

### `ForeignTokenExecutionUnresolved`


Local detection/handling phase and implementation owner:

- `Registry::slot_successor_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignTokenResourcesActive"></a>

### `ForeignTokenResourcesActive`


Local detection/handling phase and implementation owner:

- `Registry::maintenance_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-LiveForeignTokenResourcesRequireCompletion"></a>

### `LiveForeignTokenResourcesRequireCompletion`


Local detection/handling phase and implementation owner:

- `Registry::slot_successor_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `Phase::SessionOpen | Phase::Progressable(Progress::Sequence)`.


<a id="cause-NativeLifecycleReentry"></a>

### `NativeLifecycleReentry`


Local detection/handling phase and implementation owner:

- `Inner::check_lifecycle_reentry` — `src/module/foreign.rs`. Enclosing true branch: `crate::notify::in_callback_for(image) || call::in_call(image)`.


<a id="cause-ReusedForeignExecutionUnresolved"></a>

### `ReusedForeignExecutionUnresolved`


Local detection/handling phase and implementation owner:

- `Registry::check_opened_handle` — `src/module/foreign/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ReusedForeignSessionCallbackActive"></a>

### `ReusedForeignSessionCallbackActive`


Local detection/handling phase and implementation owner:

- `Registry::check_opened_handle` — `src/module/foreign/registry.rs`. Enclosing true branch: `prior.callbacks.load(Ordering::Acquire) != 0`.


<a id="cause-UnregisteredForeignNativeResourceRetained"></a>

### `UnregisteredForeignNativeResourceRetained`


Local detection/handling phase and implementation owner:

- `Registry::check_tracked` — `src/module/foreign/registry.rs`. Enclosing true branch: `self.untracked.load(Ordering::Acquire)`.
