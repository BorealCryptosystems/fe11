Cause contracts for `ObjectCleanupRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AbandonedReaderSnapshotAllocation"></a>

### `AbandonedReaderSnapshotAllocation`


Local detection/handling phase and implementation owner:

- `reserve_session_close` (module-level helper) — `src/managed/mutations/closing.rs`. Enclosing true branch: `!state.native.is_uncertain()`.


<a id="cause-CoordinationVectorStorageAccounting"></a>

### `CoordinationVectorStorageAccounting`


Local detection/handling phase and implementation owner:

- `CloseBuffers::bytes` — `src/managed/mutations/close_storage.rs`.
- `bytes` (module-level helper) — `src/managed/mutations/possession/storage.rs`.


<a id="cause-CreatorActivityCount"></a>

### `CreatorActivityCount`


Local detection/handling phase and implementation owner:

- `CloseBuffers::requested_bytes` — `src/managed/mutations/close_storage.rs`.
- `CloseBuffers::allocate` — `src/managed/mutations/close_storage.rs`.


<a id="cause-CreatorCloseBudgetOwner"></a>

### `CreatorCloseBudgetOwner`


Local detection/handling phase and implementation owner:

- `CloseResident::plan` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `!registered.ptr_eq(&Arc::downgrade(&wake))`.


<a id="cause-CreatorCloseCapacityNotPrepared"></a>

### `CreatorCloseCapacityNotPrepared`


Local detection/handling phase and implementation owner:

- `CloseBuffers::destination` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `self.destinations.len() == self.destinations.capacity()`.
- `CloseBuffers::resource` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `self.resources.len() == self.resources.capacity()`.
- `CloseReservation::protect` — `src/managed/mutations/closing.rs`. Enclosing true branch: `buffers.permits.len() == buffers.permits.capacity()`.
- `CloseReservation::protect` — `src/managed/mutations/closing.rs`. Enclosing true branch: `buffers.permits.len() == buffers.permits.capacity()`.
- `CreationTicket::prepare_group` — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `pending.close.remaining() < capacity`.


<a id="cause-CreatorClosePreparationAlreadyPresent"></a>

### `CreatorClosePreparationAlreadyPresent`


Local detection/handling phase and implementation owner:

- `reserve_session_close` (module-level helper) — `src/managed/mutations/closing.rs`. Enclosing true branch: `outer.is_some()`.
- `reserve_recovery_batch` (module-level helper) — `src/managed/mutations/closing.rs`. Enclosing true branch: `outer.is_some()`.


<a id="cause-CreatorCloseTicketExhausted"></a>

### `CreatorCloseTicketExhausted`


Local detection/handling phase and implementation owner:

- `CloseResident::borrow` — `src/managed/mutations/close_storage.rs`.
- `ClosePlan::commit` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `replace`.


<a id="cause-CreatorParticipantCount"></a>

### `CreatorParticipantCount`


Local detection/handling phase and implementation owner:

- `CloseResident::plan` — `src/managed/mutations/close_storage.rs`.
- `ClosePlan::commit` — `src/managed/mutations/close_storage.rs`.
- `ClosePlan::commit` — `src/managed/mutations/close_storage.rs`.


<a id="cause-CreatorParticipantReservationExhausted"></a>

### `CreatorParticipantReservationExhausted`


Local detection/handling phase and implementation owner:

- `CloseParticipants::split` — `src/managed/mutations/close_storage.rs`.
- `CloseParticipants::take` — `src/managed/mutations/close_storage.rs`.
- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`. Enclosing true branch: `count < keys.len()`.


<a id="cause-CreatorReservationCount"></a>

### `CreatorReservationCount`


Local detection/handling phase and implementation owner:

- `CloseReservation::reserve_catalog` — `src/managed/mutations/closing.rs`. Enclosing match alternative: `Some((uid, count)) if scope.owns_uid(*uid)`.


<a id="cause-CreatorSnapshotAllocation"></a>

### `CreatorSnapshotAllocation`


Local detection/handling phase and implementation owner:

- `CloseBuffers::allocate` — `src/managed/mutations/close_storage.rs`.
- `CloseBuffers::allocate` — `src/managed/mutations/close_storage.rs`.
- `CloseBuffers::allocate` — `src/managed/mutations/close_storage.rs`.
- `CloseReservation::prepare_entry` — `src/managed/mutations/closing.rs`. Enclosing true branch: `self.loans.len() == self.loans.capacity()`.
- `reserve_session_close` (module-level helper) — `src/managed/mutations/closing.rs`.
- `reserve_recovery_batch` (module-level helper) — `src/managed/mutations/closing.rs`.


<a id="cause-ForeignCreatorCloseCredit"></a>

### `ForeignCreatorCloseCredit`


Local detection/handling phase and implementation owner:

- `CloseAllocation::bind` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `!self .owner .byte_wake .get() .is_some_and(|registered| registered.ptr_eq(&Arc::downgrade(&wake)))`.


<a id="cause-ForeignCreatorClosePreparation"></a>

### `ForeignCreatorClosePreparation`


Local detection/handling phase and implementation owner:

- `ClosePlan::commit` — `src/managed/mutations/close_storage.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.owner, &prepared.owner)`.


<a id="cause-MutationCleanupOwnerAbsent"></a>

### `MutationCleanupOwnerAbsent`


Local detection/handling phase and implementation owner:

- `cleanup_failed_mutation` (module-level helper) — `src/managed/mutations/recovery.rs`.


<a id="cause-ReferenceCloseStorageAccounting"></a>

### `ReferenceCloseStorageAccounting`


Local detection/handling phase and implementation owner:

- `CloseResident::reserve_reference_and_payload` — `src/managed/mutations/close_storage.rs`.
- `CloseResident::reserve_reference_and_payload` — `src/managed/mutations/close_storage.rs`.


<a id="cause-UnknownCreatorCloseAbsent"></a>

### `UnknownCreatorCloseAbsent`


Local detection/handling phase and implementation owner:

- `CloseReservation::protect_for_close` — `src/managed/mutations/closing.rs`.


<a id="cause-UnknownCreatorCloseAllocation"></a>

### `UnknownCreatorCloseAllocation`


Local detection/handling phase and implementation owner:

- `reserve_session_close` (module-level helper) — `src/managed/mutations/closing.rs`.


<a id="cause-UnknownCreatorCloseCount"></a>

### `UnknownCreatorCloseCount`


Local detection/handling phase and implementation owner:

- `reserve_session_close` (module-level helper) — `src/managed/mutations/closing.rs`.
