Cause contracts for `LocalAdmissionRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AdmissionContextOwnerMismatch"></a>

### `AdmissionContextOwnerMismatch`


Local detection/handling phase and implementation owner:

- `AdmissionWake::bind_context` — `src/admission_wait/context.rs`. Enclosing true branch: `!registered.ptr_eq(&Arc::downgrade(context))`.


<a id="cause-AdmissionWaiterAllocation"></a>

### `AdmissionWaiterAllocation`


Local detection/handling phase and implementation owner:

- `AdmissionCancellation::subscribe` — `src/admission_wait.rs`.
