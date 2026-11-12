Cause contracts for `NativeLoadingBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DifferentNativeGenerationOrInitializerActive"></a>

### `DifferentNativeGenerationOrInitializerActive`


Local detection/handling phase and implementation owner:

- `reserve_successor` (module-level helper) — `src/native/image_reservation.rs`. Enclosing true branch: `image.generation != lease.generation || image.attempts != 0`.


<a id="cause-NativeImageFinalizing"></a>

### `NativeImageFinalizing`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `image.finalizing`.


<a id="cause-NativeImageInitializationAttemptActive"></a>

### `NativeImageInitializationAttemptActive`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `image.attempts != 0`.


<a id="cause-NativeImageInitializing"></a>

### `NativeImageInitializing`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `let Some(image) = images.entries.get_mut(&address)`.


<a id="cause-NativeInitializationAttemptActive"></a>

### `NativeInitializationAttemptActive`


Local detection/handling phase and implementation owner:

- `reserve_finalize` (module-level helper) — `src/native/image_reservation.rs`. Enclosing true branch: `image.attempts != 0`.

