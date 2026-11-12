Cause contracts for `LocalAdmissionBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ModuleActivity"></a>

### `ModuleActivity`


Local detection/handling phase and implementation owner:

- `StateLock<T>::write_closing` — `src/state_lock.rs`.
- `StateLock<T>::read_with_validation` — `src/state_lock.rs`. Enclosing true branch: `validate.is_some()`.
- `StateLock<T>::read_with_validation` — `src/state_lock.rs`. Enclosing false branch: `validate.is_some()`.
- `StateLock<T>::observe` — `src/state_lock.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.
- `prepare_finalization` (module-level helper) — `src/module/finalization.rs`.


<a id="cause-ModuleDraining"></a>

### `ModuleDraining`


Local detection/handling phase and implementation owner:

- `StateLock<T>::check_admission` — `src/state_lock.rs`. Enclosing true branch: `self.draining.load(Ordering::Acquire) != permit`.
- `StateLock<T>::begin_drain` — `src/state_lock.rs`.
