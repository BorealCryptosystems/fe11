Cause contracts for `CancellationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CancellationPending"></a>

### `CancellationPending`


Local detection/handling phase and implementation owner:

- `AdvancedSession::cancel` — `src/advanced/cancellation.rs`. Enclosing true branch: `op.cancel.is_submitted()`.
- `drive` (module-level helper) — `src/advanced/operation.rs`. Enclosing true branch: `op.cancel.is_submitted()`.
- `AdvancedSession::advance_state_capture` — `src/advanced/saved_state.rs`. Enclosing true branch: `op.cancel.is_submitted()`.


<a id="cause-OperationDetachmentControl"></a>

### `OperationDetachmentControl`


Local detection/handling phase and implementation owner:

- `AdvancedSession::cancel` — `src/advanced/cancellation.rs`. Enclosing true branch: `op.detachment().is_some()`.
- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `op.detachment().is_some()`.
- `drive` (module-level helper) — `src/advanced/operation.rs`. Enclosing true branch: `op.detachment().is_some()`.


<a id="cause-OperationRejoinControl"></a>

### `OperationRejoinControl`


Local detection/handling phase and implementation owner:

- `AdvancedSession::cancel` — `src/advanced/cancellation.rs`. Enclosing true branch: `op.rejoin().is_some()`.
- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `op.rejoin().is_some()`.
- `drive` (module-level helper) — `src/advanced/operation.rs`. Enclosing true branch: `op.rejoin().is_some()`.


<a id="cause-StateRestorationActive"></a>

### `StateRestorationActive`


Local detection/handling phase and implementation owner:

- `AdvancedSession::cancel` — `src/advanced/cancellation.rs`. Enclosing true branch: `op.restore_owner().is_some()`.
