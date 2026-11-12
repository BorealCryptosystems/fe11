Cause contracts for `ObjectCleanupBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CreatorMutation"></a>

### `CreatorMutation`


Local detection/handling phase and implementation owner:

- `CloseReservation::reserve_catalog` — `src/managed/mutations/closing.rs`. Enclosing match alternative: `_`.


<a id="cause-ObjectCatalogue"></a>

### `ObjectCatalogue`


Local detection/handling phase and implementation owner:

- `reserve_session_close` (module-level helper) — `src/managed/mutations/closing.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.
- `reserve_recovery_batch` (module-level helper) — `src/managed/mutations/closing.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.
