Cause contracts for `AeadMessagesUnsupported`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DeclaredGcmMessageStateCapture"></a>

### `DeclaredGcmMessageStateCapture`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::stream_header` — `src/advanced/gcm/checkpoint.rs`. Enclosing match alternative: `InitBinding::Declared(_)`.
- `ensure_standard` (module-level helper) — `src/advanced/gcm/extension.rs`. Enclosing match alternative: `InitBinding::Declared(_)`.
- `InitBinding::layout` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `Self::Declared(_)`.
- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `InitBinding::Declared(_)`.

