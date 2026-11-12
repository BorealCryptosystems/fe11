Cause contracts for `InputBoundsRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-LengthBound"></a>

### `LengthBound`


Local detection/handling phase and implementation owner:

- `count_reason` (module-level helper) — `src/bounds.rs`. Enclosing true branch: `value == fe11_sys::CK_UNAVAILABLE_INFORMATION || n > limit`.

This shared bound also checks native buffer capacities, including during an
inventory. Only the inventory child's proven logical byte-quota failures are
reported as `InventoryByteQuota`; sentinel, conversion and returned-capacity
handling are unchanged.


<a id="cause-LengthConversion"></a>

### `LengthConversion`


Local detection/handling phase and implementation owner:

- `count_reason` (module-level helper) — `src/bounds.rs`.
- `ck_length` (module-level helper) — `src/bounds.rs`.
- `NativeOutputSize::buffer_too_small` — `src/error/output_size.rs`.

