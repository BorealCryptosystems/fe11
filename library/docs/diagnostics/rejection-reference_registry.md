Cause contracts for `ReferenceRegistryRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ActivityContextNotifierAbsent"></a>

### `ActivityContextNotifierAbsent`


Local detection/handling phase and implementation owner:

- `PreparedReader::wait_available_in_context` — `src/registry.rs`.


<a id="cause-ActivityContextNotifierMismatch"></a>

### `ActivityContextNotifierMismatch`


Local detection/handling phase and implementation owner:

- `Activity::bind_context_wake` — `src/registry/activity.rs`. Enclosing match alternative: `Some(current) if !current.ptr_eq(&expected)`.


<a id="cause-ActivityOwnerStorageAccounting"></a>

### `ActivityOwnerStorageAccounting`


Local detection/handling phase and implementation owner:

- `Activity::prepare_reader_storage` — `src/registry/activity.rs`.
- `Activity::prepare_reader_storage` — `src/registry/activity.rs`.


<a id="cause-ActivityStorageAccounting"></a>

### `ActivityStorageAccounting`


Local detection/handling phase and implementation owner:

- `Activity::allocation_bytes` — `src/registry/activity.rs`.
- `ReferenceAdmission<'_>::reserve` — `src/session/references.rs`. Enclosing match alternative: `ControlledReference::Acquired(mut reservation)`.
- `ReferenceAdmission<'_>::references_with_storage` — `src/session/references.rs`. Enclosing match alternative: `ControlledReference::Acquired(mut reservation)`.


<a id="cause-ForeignOrBorrowedObjectWriter"></a>

### `ForeignOrBorrowedObjectWriter`


Local detection/handling phase and implementation owner:

- `WritePermit::bind_owner` — `src/registry.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignOrExhaustedReferenceReservation"></a>

### `ForeignOrExhaustedReferenceReservation`


Local detection/handling phase and implementation owner:

- `Reservation<T>::prepare_close` — `src/registry.rs`. Enclosing true branch: `self.close.is_some() || participants.remaining() != self.remaining`.
- `Reservation<T>::insert` — `src/registry.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.registry, &registry.0) || self.remaining == 0`.
- `ManagedReferences::check` — `src/session/references.rs`. Enclosing true branch: `self.uid != session.uid || !self .entry .ptr_eq(&std::sync::Arc::downgrade(&session.entry)) || !access.owns_session(session) || !self.managed.same_registry(&access.managed) || !self.objects.same_registry(&access.objects)`.
- `ReferenceAdmission<'_>::into_prepaid_managed_retained` — `src/session/references.rs`. Enclosing true branch: `!candidate.managed.matches_reservation(reservation, count)`.
- `ReferenceAdmission<'_>::check` — `src/session/references.rs`. Enclosing true branch: `!access.owns_session(self.session) || !self.managed.same_registry(&access.managed) || !self.objects.same_registry(&access.objects)`.


<a id="cause-ForeignWriterTransferActivity"></a>

### `ForeignWriterTransferActivity`


Local detection/handling phase and implementation owner:

- `PreparedReader::transfer_writer` — `src/registry.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.activity, activity)`.


<a id="cause-LiveReferenceAllocation"></a>

### `LiveReferenceAllocation`


Local detection/handling phase and implementation owner:

- `Registry<T>::live` — `src/registry.rs`.


<a id="cause-LiveRegistryBoundaryAbsent"></a>

### `LiveRegistryBoundaryAbsent`


Local detection/handling phase and implementation owner:

- `Registry<NativeIdentity>::visit_native_identities` — `src/registry/visit.rs`.


<a id="cause-LiveRegistryCursorAbsent"></a>

### `LiveRegistryCursorAbsent`


Local detection/handling phase and implementation owner:

- `Registry<NativeIdentity>::visit_native_identities` — `src/registry/visit.rs`. Enclosing false branch: `entries .items .get(index) .is_some_and(|value| Weak::ptr_eq(value, &cursor))`.


<a id="cause-ObjectActivityAllocation"></a>

### `ObjectActivityAllocation`


Local detection/handling phase and implementation owner:

- `Activity::prepare_reader_storage` — `src/registry/activity.rs`.
- `selection_activity_in_context` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.
- `publish_catalog` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ObjectActivityCount"></a>

### `ObjectActivityCount`


Local detection/handling phase and implementation owner:

- `PreparedReader::acquire_ready` — `src/registry.rs`.
- `PreparedReader::acquire_ready` — `src/registry.rs`.
- `ReadPermit::duplicate` — `src/registry.rs`.
- `ReadPermit::duplicate` — `src/registry.rs`. Enclosing true branch: `let Some(uid) = self.owner`.
- `ActivityState::operation_writer_available` — `src/registry/activity.rs`. Enclosing true branch: `Some(owner.uid) == borrowed_uid`.
- `Activity::prepare_reader_storage` — `src/registry/activity.rs`. Enclosing true branch: `let Some(owner) = state.owned.iter_mut().find(|owner| owner.uid == uid)`.
- `Activity::prepare_reader_storage` — `src/registry/activity.rs`.
- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing true branch: `reader_allowed(owner.uid)`.


<a id="cause-ObjectActivityOwner"></a>

### `ObjectActivityOwner`


Local detection/handling phase and implementation owner:

- `PreparedReader::acquire_ready` — `src/registry.rs`.
- `WritePermit::bind_owner` — `src/registry.rs`. Enclosing true branch: `uid == 0`.
- `ReadPermit::duplicate` — `src/registry.rs`. Enclosing true branch: `let Some(uid) = self.owner`.
- `Activity::prepare_reader_storage` — `src/registry/activity.rs`. Enclosing true branch: `uid == 0`.
- `Activity::write_for_close_with_abandoned` — `src/registry/activity.rs`. Enclosing true branch: `uid == 0`.
- `Activity::write_for_operation_admitted` — `src/registry/activity.rs`. Enclosing true branch: `uid == 0`.
- `Admission::new` — `src/advanced/admission/preparation.rs`. Enclosing match alternative: `InitialResource::Selection(index)`.


<a id="cause-ObjectReaderSlotAlreadyOccupied"></a>

### `ObjectReaderSlotAlreadyOccupied`


Local detection/handling phase and implementation owner:

- `PreparedReader::acquire_into` — `src/registry.rs`. Enclosing true branch: `retained.is_some()`.


<a id="cause-ObjectWriteOwnershipState"></a>

### `ObjectWriteOwnershipState`


Local detection/handling phase and implementation owner:

- `WritePermit::bind_owner` — `src/registry.rs`. Enclosing true branch: `state.poisoned || !state.writer || state.readers != 0`.


<a id="cause-ObjectWriterCount"></a>

### `ObjectWriterCount`


Local detection/handling phase and implementation owner:

- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing match alternative: `Some((owner, count)) if writer_allowed(owner)`.


<a id="cause-PreparedKeyReaderAbsent"></a>

### `PreparedKeyReaderAbsent`


Local detection/handling phase and implementation owner:

- `ReadPermit::take_prepared` — `src/registry.rs`.


<a id="cause-PreparedKeyReaderAttributionLost"></a>

### `PreparedKeyReaderAttributionLost`


Local detection/handling phase and implementation owner:

- `ReadPermit::take_prepared` — `src/registry.rs`. Enclosing true branch: `state.writer || state.readers == 0 || !state .owned .iter() .any(|owner| owner.uid == uid && owner.readers != 0)`.


<a id="cause-ReferenceActivityPreparationAbsent"></a>

### `ReferenceActivityPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Reservation<T>::begin_observation` — `src/registry.rs`.
- `Reservation<T>::activity_credit` — `src/registry.rs`.


<a id="cause-ReferenceActivityPreparationAlreadyPresent"></a>

### `ReferenceActivityPreparationAlreadyPresent`


Local detection/handling phase and implementation owner:

- `Reservation<T>::prepare_activities` — `src/registry.rs`. Enclosing true branch: `self.activity_credit.is_some()`.


<a id="cause-ReferenceAllocation"></a>

### `ReferenceAllocation`


Local detection/handling phase and implementation owner:

- `Registry<T>::try_reserve` — `src/registry.rs`.


<a id="cause-ReferenceCountOverflow"></a>

### `ReferenceCountOverflow`


Local detection/handling phase and implementation owner:

- `Registry<T>::try_reserve` — `src/registry.rs`.
- `Registry<T>::try_reserve` — `src/registry.rs`.


<a id="cause-ReferenceQuotaExceeded"></a>

### `ReferenceQuotaExceeded`


Local detection/handling phase and implementation owner:

- `Registry<T>::reserve_controlled` — `src/registry.rs`. Enclosing true branch: `state.maximum.is_some_and(|maximum| n > maximum)`.


<a id="cause-RevocationSnapshotAlreadyPopulated"></a>

### `RevocationSnapshotAlreadyPopulated`


Local detection/handling phase and implementation owner:

- `Registry<T>::copy_live_matching` — `src/registry.rs`. Enclosing true branch: `!destination.is_empty() || !rejected.is_empty()`.


<a id="cause-TransferredWriterAttribution"></a>

### `TransferredWriterAttribution`


Local detection/handling phase and implementation owner:

- `Activity::acquire_write_owners` — `src/registry/activity.rs`. Enclosing true branch: `!state.base_writer`.


<a id="cause-UnknownCreatorCapacityNotPrepared"></a>

### `UnknownCreatorCapacityNotPrepared`


Local detection/handling phase and implementation owner:

- `Reservation<T>::reference_lifetime_for` — `src/registry.rs`. Enclosing true branch: `unknown`.


<a id="cause-WriterTransferAttributionAbsent"></a>

### `WriterTransferAttributionAbsent`


Local detection/handling phase and implementation owner:

- `PreparedReader::transfer_writer` — `src/registry.rs`.


<a id="cause-WriterTransferCount"></a>

### `WriterTransferCount`


Local detection/handling phase and implementation owner:

- `PreparedReader::transfer_writer` — `src/registry.rs`.


<a id="cause-WriterTransferState"></a>

### `WriterTransferState`


Local detection/handling phase and implementation owner:

- `PreparedReader::transfer_writer` — `src/registry.rs`. Enclosing true branch: `state.poisoned || !state.writer || state.readers != 0`.
