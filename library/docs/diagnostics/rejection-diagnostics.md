Cause contracts for `DiagnosticsRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CleanupCauseNotUsed"></a>

### `CleanupCauseNotUsed`


Local detection/handling phase and implementation owner:

- `CleanupStorage::allocate` — `src/error.rs`.


<a id="cause-CleanupFailureNotUsed"></a>

### `CleanupFailureNotUsed`


Local detection/handling phase and implementation owner:

- `CleanupStorage::allocate` — `src/error.rs`.


<a id="cause-CleanupMarkerAllocation"></a>

### `CleanupMarkerAllocation`


Local detection/handling phase and implementation owner:

- `CleanupStorage::allocate` — `src/error.rs`.


<a id="cause-CleanupMarkerNotUsed"></a>

### `CleanupMarkerNotUsed`


Local detection/handling phase and implementation owner:

- `CleanupStorage::allocate` — `src/error.rs`.


<a id="cause-CleanupNotDispatched"></a>

### `CleanupNotDispatched`


Local detection/handling phase and implementation owner:

- `CleanupDiagnostic::prepare_sequence` — `src/error.rs`.


<a id="cause-CleanupStorageAccounting"></a>

### `CleanupStorageAccounting`


Local detection/handling phase and implementation owner:

- `CleanupStorage::bytes` — `src/error.rs`.


<a id="cause-CompletionDiagnosticAlreadyConsumed"></a>

### `CompletionDiagnosticAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `PreparedCompletion::take` — `src/error.rs`.
- `execute_kem` (module-level helper) — `src/crypto/kem/operations.rs`. Enclosing true branch: `completed && rv == CKR_BUFFER_TOO_SMALL && matches!(&direction, Direction::Encapsulate(_))`.
- `execute_kem` (module-level helper) — `src/crypto/kem/operations.rs`. Enclosing true branch: `!unchanged || overflow`.
- `execute_derivation` (module-level helper) — `src/crypto/derivation/operations/execution.rs`. Enclosing true branch: `!unchanged`.
- `execute_unwrap` (module-level helper) — `src/transport/operations/unwrap.rs`. Enclosing true branch: `!valid`.


<a id="cause-CompletionDiagnosticNotUsed"></a>

### `CompletionDiagnosticNotUsed`


Local detection/handling phase and implementation owner:

- `CompletionStorage::allocate` — `src/error.rs`.


<a id="cause-CompletionStorageAlreadyConsumed"></a>

### `CompletionStorageAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `PreparedCompletionStorage::take` — `src/error.rs`.


<a id="cause-PrimaryFailureNotUsed"></a>

### `PrimaryFailureNotUsed`


Local detection/handling phase and implementation owner:

- `FailurePair::allocate` — `src/error.rs`.


<a id="cause-SecondaryFailureNotUsed"></a>

### `SecondaryFailureNotUsed`


Local detection/handling phase and implementation owner:

- `FailurePair::allocate` — `src/error.rs`.


<a id="cause-SequenceCauseNotUsed"></a>

### `SequenceCauseNotUsed`


Local detection/handling phase and implementation owner:

- `CleanupDiagnostic::prepare_sequence` — `src/error.rs`.

