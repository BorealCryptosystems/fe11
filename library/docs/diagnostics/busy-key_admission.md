Cause contracts for `KeyAdmissionBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-InitialCreationPlanChanged"></a>

### `InitialCreationPlanChanged`


Local detection/handling phase and implementation owner:

- `Admission::new` — `src/advanced/admission/preparation.rs`. Enclosing true branch: `!current()?`.
- `Admission::new` — `src/advanced/admission/preparation.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::KeyAdmission( crate::KeyAdmissionBusy::InitialCreationPlanChanged, )))`.

