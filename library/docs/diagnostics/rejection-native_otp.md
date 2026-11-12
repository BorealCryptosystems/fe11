Cause contracts for `NativeOtpRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-OtpOutputIsNotABoundedContiguousNativeGraph"></a>

### `OtpOutputIsNotABoundedContiguousNativeGraph`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/native_otp.rs`.


<a id="cause-OtpScalarAbiWidth"></a>

### `OtpScalarAbiWidth`


Local detection/handling phase and implementation owner:

- `write` (module-level helper) — `src/native_otp.rs`.
- `with_parameters` (module-level helper) — `src/native_otp.rs`. Enclosing true branch: `let Some(value) = value`.


<a id="cause-OtpValueAccounting"></a>

### `OtpValueAccounting`


Local detection/handling phase and implementation owner:

- `with_parameters` (module-level helper) — `src/native_otp.rs`.


<a id="cause-CallerOtpParameterCountBound"></a>

### `CallerOtpParameterCountBound`


Local detection/handling phase and implementation owner:

- `with_parameters` (module-level helper) — `src/native_otp.rs`. Enclosing true branch: `parameters.len() > parameter_limits.maximum_parameters`.


<a id="cause-CallerOtpValueByteBound"></a>

### `CallerOtpValueByteBound`


Local detection/handling phase and implementation owner:

- `with_parameters` (module-level helper) — `src/native_otp.rs`. Enclosing true branch: `values > parameter_limits.maximum_value_bytes`.
