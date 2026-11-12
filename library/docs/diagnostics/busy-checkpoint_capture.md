Cause contracts for `CheckpointCaptureBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-StateCaptureActive"></a>

### `StateCaptureActive`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `AdvancedSession::capture_control` — `src/advanced/saved_state.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/recover.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`. Enclosing true branch: `operation.capture_owner().is_some()`.

