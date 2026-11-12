Cause contracts for `CombinedOperationsBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-RecoveryDestinationActive"></a>

### `RecoveryDestinationActive`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_aead_recovery` — `src/advanced/recovery.rs`. Enclosing true branch: `self .session .entry .advanced_operation .load(Ordering::Acquire) != 0`.
- `AdvancedSession::install_prepared_dual` — `src/advanced/dual/api.rs`. Enclosing true branch: `recovery.is_some() && self .session .entry .advanced_operation .load(Ordering::Acquire) != 0`.

