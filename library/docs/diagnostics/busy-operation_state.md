Cause contracts for `OperationStateBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-StateCaptureTransfer"></a>

### `StateCaptureTransfer`


Local detection/handling phase and implementation owner:

- `AdvancedSession::advance_state_capture` — `src/advanced/saved_state.rs`. Enclosing true branch: `op.detachment().is_some() || op.rejoin().is_some()`.

