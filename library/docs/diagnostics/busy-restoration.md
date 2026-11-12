Cause contracts for `RestorationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DestinationOperationControlActive"></a>

### `DestinationOperationControlActive`


Local detection/handling phase and implementation owner:

- `check_restore_target` (module-level helper) — `src/advanced/restoration.rs`. Enclosing true branch: `op.rejoin().is_some() || op.detachment().is_some() || op.state_io().is_some() || op.restore_owner().is_some() || op.joined.is_some() || op.cancel.is_submitted() || op.cancellation.is_withdrawn() || op.body.pending() || op.validation.as_ref().is_some_and(|v| v.waiting())`.


<a id="cause-RestorationControlActive"></a>

### `RestorationControlActive`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_restore_detachment` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `op.rejoin().is_some() || op.detachment().is_some() || op.cancel.is_submitted()`.


<a id="cause-RestorationTransferActive"></a>

### `RestorationTransferActive`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `op.restore_transfer().is_some() || op.rejoin().is_some()`.
- `AdvancedSession::start_restore_detachment` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `op.restore_transfer().is_some()`.
