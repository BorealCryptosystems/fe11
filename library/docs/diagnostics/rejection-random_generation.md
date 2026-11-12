Cause contracts for `RandomGenerationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGenerateRandomUnavailable"></a>

### `CGenerateRandomUnavailable`


Local detection/handling phase and implementation owner:

- `Session::generate_random_prepared` — `src/random.rs`.


<a id="cause-CSeedRandomUnavailable"></a>

### `CSeedRandomUnavailable`


Local detection/handling phase and implementation owner:

- `Session::seed_random` — `src/random.rs`.


<a id="cause-CWaitForSlotEventUnavailable"></a>

### `CWaitForSlotEventUnavailable`


Local detection/handling phase and implementation owner:

- `Module::slot_event` — `src/random.rs`.


<a id="cause-NativeSeedInputChanged"></a>

### `NativeSeedInputChanged`


Local detection/handling phase and implementation owner:

- `Session::seed_random` — `src/random.rs`. Enclosing true branch: `sequence.termination_known() && body.data.seed.as_slice() != expected.as_slice()`.


<a id="cause-RandomOutputAccounting"></a>

### `RandomOutputAccounting`


Local detection/handling phase and implementation owner:

- `RandomOutput::prepare` — `src/random.rs`.
- `RandomOutput::prepare` — `src/random.rs`.
- `RandomOutput::prepare` — `src/random.rs`.


<a id="cause-SecretBufferAccounting"></a>

### `SecretBufferAccounting`


Local detection/handling phase and implementation owner:

- `SecretBytes::bind_prepaid` — `src/random.rs`.


<a id="cause-SecretBufferAllocation"></a>

### `SecretBufferAllocation`


Local detection/handling phase and implementation owner:

- `SecretBytes::new` — `src/random.rs`.


<a id="cause-SecretBufferAlreadyCredited"></a>

### `SecretBufferAlreadyCredited`


Local detection/handling phase and implementation owner:

- `SecretBytes::bind_prepaid` — `src/random.rs`. Enclosing true branch: `self.credit.is_some()`.
- `SecretBytes::bind_prepaid_payload` — `src/random.rs`. Enclosing true branch: `self.credit.is_some()`.


<a id="cause-SecretLengthExceedsCapacity"></a>

### `SecretLengthExceedsCapacity`


Local detection/handling phase and implementation owner:

- `SecretBytes::truncate` — `src/random.rs`. Enclosing true branch: `length > self.length`.


<a id="cause-SeedOwnershipAccounting"></a>

### `SeedOwnershipAccounting`


Local detection/handling phase and implementation owner:

- `Session::seed_random` — `src/random.rs`.
- `Session::seed_random` — `src/random.rs`.


<a id="cause-SlotEventGenerationAllocation"></a>

### `SlotEventGenerationAllocation`


Local detection/handling phase and implementation owner:

No direct construction site is present in the current sources. This public
variant remains available; the common error contract still governs handling.

