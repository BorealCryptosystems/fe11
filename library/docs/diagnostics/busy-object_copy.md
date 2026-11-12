Cause contracts for `ObjectCopyBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CopyCreationPlanChanged"></a>

### `CopyCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`. Enclosing true branch: `!current()?`.
- `execute` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectCopy( crate::ObjectCopyBusy::CopyCreationPlanChanged, )))`.
