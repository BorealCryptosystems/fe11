Cause contracts for `CancellationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CSessionCancelUnavailable"></a>

### `CSessionCancelUnavailable`


Local detection/handling phase and implementation owner:

- `AdvancedSession::cancel` — `src/advanced/cancellation.rs`.


<a id="cause-CancellationAbsent"></a>

### `CancellationAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_cancellation` — `src/advanced/cancellation.rs`.


<a id="cause-CancellationControlAbsent"></a>

### `CancellationControlAbsent`


Local detection/handling phase and implementation owner:

- `finish` (module-level helper) — `src/advanced/cancellation.rs`.
- `finish` (module-level helper) — `src/advanced/cancellation.rs`.


<a id="cause-CancellationFlagCategory"></a>

### `CancellationFlagCategory`


Local detection/handling phase and implementation owner:

- `CancellationFlags::from_bits` — `src/advanced/cancellation.rs`. Enclosing true branch: `native & !CATEGORIES != 0`.


<a id="cause-CancellationFlagRange"></a>

### `CancellationFlagRange`


Local detection/handling phase and implementation owner:

- `CancellationFlags::from_bits` — `src/advanced/cancellation.rs`.


<a id="cause-CancellationNotPending"></a>

### `CancellationNotPending`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_cancellation` — `src/advanced/cancellation.rs`. Enclosing true branch: `!matches!(control.call, CancellationCall::Pending)`.


<a id="cause-CancellationReturnUnproven"></a>

### `CancellationReturnUnproven`


Local detection/handling phase and implementation owner:

- `finish` (module-level helper) — `src/advanced/cancellation.rs`. Enclosing true branch: `!matches!(observed.call, CancellationCall::Returned(code) if code == rv)`.

