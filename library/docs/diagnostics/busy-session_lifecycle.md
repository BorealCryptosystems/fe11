Cause contracts for `SessionLifecycleBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ObjectSearchActive"></a>

### `ObjectSearchActive`


Local detection/handling phase and implementation owner:

- `Registry::check_search_available_except` — `src/session/recovery/observations.rs`. Enclosing true branch: `owner.as_ref().is_some_and(Owner::search_claimed)`.


<a id="cause-SessionLifecycleDiagnostic"></a>

### `SessionLifecycleDiagnostic`


Local detection/handling phase and implementation owner:

- `Store::loan_checked` — `src/session/lifecycle_diagnostics.rs`. Enclosing match alternative: `_`.


<a id="cause-SessionTransition"></a>

### `SessionTransition`


Local detection/handling phase and implementation owner:

- `SlotDomain::new` — `src/module/state.rs`.
- `transition` (module-level helper) — `src/session/close_admission.rs`. Enclosing match alternative: `TryLockError::WouldBlock`.
