Cause contracts for `NativeSignatureRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-SignatureParameterScalarAbiWidth"></a>

### `SignatureParameterScalarAbiWidth`


Local detection/handling phase and implementation owner:

- `put` (module-level helper) — `src/native_signature.rs`.


<a id="cause-SingleVerificationRequiresOneInput"></a>

### `SingleVerificationRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::verify_native_at_init_with_diagnostics` — `src/native_verification.rs`. Enclosing true branch: `parts.len() != 1`.


<a id="cause-SinglePartSignatureRequiresOneInput"></a>

### `SinglePartSignatureRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing true branch: `!multipart && parts.len() != 1`.
- `Session::sign_native_with_diagnostics` — `src/native_signature/api.rs`. Enclosing true branch: `parts.len() != 1`.


<a id="cause-SinglePartVerificationRequiresOneInput"></a>

### `SinglePartVerificationRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing true branch: `!multipart && parts.len() != 1`.
- `Session::verify_native_with_diagnostics` — `src/native_signature/api.rs`. Enclosing true branch: `parts.len() != 1`.
- `Session::verify_signature_native` — `src/native_signature/api.rs`. Enclosing true branch: `parts.len() != 1`.
- `crate::AdvancedSession::verify_signature_native` — `src/native_signature/api.rs`. Enclosing true branch: `parts.len() != 1`.
