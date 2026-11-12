Cause contracts for `NativeTransportRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-SkipjackSharedPGExtent"></a>

### `SkipjackSharedPGExtent`


Local detection/handling phase and implementation owner:

- `encode` (module-level helper) — `src/native_transport/encoding.rs`. Enclosing true branch: `p.prime.len() != p.base.len()`.


<a id="cause-HistoricalTransportMechanismLayoutMismatch"></a>

### `HistoricalTransportMechanismLayoutMismatch`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::invoke` — `src/native_transport/encoding.rs`. Enclosing true branch: `contract.mechanism_number() != kind as u64`.


<a id="cause-TransportFixedParameterExtent"></a>

### `TransportFixedParameterExtent`


Local detection/handling phase and implementation owner:

- `encode` (module-level helper) — `src/native_transport/encoding.rs`. Enclosing true branch: `bytes.is_some_and(|b| b.len() != mechanism.bytes) || (bytes.is_none() && !mechanism.optional)`.


<a id="cause-TransportScalarAbiWidth"></a>

### `TransportScalarAbiWidth`


Local detection/handling phase and implementation owner:

- `scalar` (module-level helper) — `src/native_transport/encoding.rs`.
