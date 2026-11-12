Cause contracts for `NativeMessagesBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-GenericMessageControlChanged"></a>

### `GenericMessageControlChanged`


Local detection/handling phase and implementation owner:

- `submit_with_budget` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `waiting.changed()`.


<a id="cause-MessageDestinationRevocationCapacityChanged"></a>

### `MessageDestinationRevocationCapacityChanged`


Local detection/handling phase and implementation owner:

- `Destination<'a>::try_access` — `src/advanced/native_messages/restoration.rs`.
