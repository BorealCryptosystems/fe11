Cause contracts for `ObjectObservationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-RsaObjectCreationPlanChanged"></a>

### `RsaObjectCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `!current()?`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::ObjectObservation( crate::ObjectObservationBusy::RsaObjectCreationPlanChanged, )))`.
