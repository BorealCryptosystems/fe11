Cause contracts for `NativeProtocolsRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CmsKeyFieldAccounting"></a>

### `CmsKeyFieldAccounting`


Local detection/handling phase and implementation owner:

- `cms_with_bindings` (module-level helper) — `src/native_protocol.rs`.


<a id="cause-NativeKipMacLengthDiffersFromRequestedLength"></a>

### `NativeKipMacLengthDiffersFromRequestedLength`


Local detection/handling phase and implementation owner:

- `Session::compute_native_kip_mac_with_diagnostics` — `src/native_protocol/api.rs`. Enclosing false branch: `result.as_bytes().len() == requested_bytes`.


<a id="cause-ProtocolScalarAbiWidth"></a>

### `ProtocolScalarAbiWidth`


Local detection/handling phase and implementation owner:

- `put` (module-level helper) — `src/native_protocol.rs`.


<a id="cause-SingleCmsCallRequiresOneInput"></a>

### `SingleCmsCallRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::sign_native_cms_with_diagnostics` — `src/native_protocol/api.rs`. Enclosing true branch: `parts.len() != 1`.
- `Session::verify_native_cms_with_diagnostics` — `src/native_protocol/api.rs`. Enclosing true branch: `parts.len() != 1`.
