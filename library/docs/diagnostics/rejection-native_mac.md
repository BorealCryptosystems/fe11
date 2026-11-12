Cause contracts for `NativeMacRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-MacOutputLengthRepresentation"></a>

### `MacOutputLengthRepresentation`

Detected while converting the length selected by native MAC parameters into
usize. This parameter-size calculation makes no native call and produces no
valid output-size value on failure. Correct the caller-selected representable
parameters before a new request; waiting or changing a buffer cannot repair the
numeric representation. No algorithm or mechanism fallback is selected.


Local detection/handling phase and implementation owner:

- `NativeMacParameters<'_>::expected_output_bytes` — `src/native_mac.rs`.


<a id="cause-MacParameterNativeScalarWidth"></a>

### `MacParameterNativeScalarWidth`


Local detection/handling phase and implementation owner:

- `native_scalar` (module-level helper) — `src/native_mac.rs`.


<a id="cause-NativeMacOutputLengthDiffersFromSelectedParameters"></a>

### `NativeMacOutputLengthDiffersFromSelectedParameters`

Detected by the publication callback after native MAC output was produced,
when its byte length differs from the explicit parameter contract. The public
NativeMac value is withheld; the enclosing execution/publication diagnostic
retains the completed effect. Do not pad, truncate or replay the MAC operation.
Preserve the entire returned error rather than reducing it to this local cause.


Local detection/handling phase and implementation owner:

- `Session::compute_native_mac_with_diagnostics` — `src/native_mac.rs`. Enclosing true branch: `expected.is_some_and(|length| result.as_bytes().len() != length)`.


<a id="cause-SinglePartMacRequiresOneInput"></a>

### `SinglePartMacRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::compute_native_mac_with_diagnostics` — `src/native_mac.rs`. Enclosing true branch: `parts.len() != 1`.
- `Session::verify_native_mac_with_diagnostics` — `src/native_mac.rs`. Enclosing true branch: `parts.len() != 1`.
- `Session::verify_signature_native_mac` — `src/native_mac.rs`. Enclosing true branch: `parts.len() != 1`.
- `crate::AdvancedSession::verify_signature_native_mac` — `src/native_mac.rs`. Enclosing true branch: `parts.len() != 1`.
