Cause contracts for `RestorationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CSetOperationStateUnavailable"></a>

### `CSetOperationStateUnavailable`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `s.native.table.C_SetOperationState.is_none()`.
- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `s.native.table.C_SetOperationState.is_none()`.
- `Call::resolve` — `src/advanced/state_io/resolved_call.rs`. Enclosing match alternative: `Phase::Restore`.


<a id="cause-BlockCipherDestinationReferenceProfile"></a>

### `BlockCipherDestinationReferenceProfile`


Local detection/handling phase and implementation owner:

- `BoundKeys::from_record_retained` — `src/advanced/restoration_keys.rs`. Enclosing match alternative: `_`.


<a id="cause-CaptureRecordIsNotAnActiveCryptographicOperation"></a>

### `CaptureRecordIsNotAnActiveCryptographicOperation`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::detached` — `src/advanced/reconstruction.rs`. Enclosing true branch: `record.capture`.


<a id="cause-CheckpointDestinationRoles"></a>

### `CheckpointDestinationRoles`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::check_binding` — `src/advanced/reconstruction.rs`. Enclosing true branch: `surplus`.
- `check_keys` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing match alternative: `_`.


<a id="cause-DestinationContinuationAlreadyBound"></a>

### `DestinationContinuationAlreadyBound`


Local detection/handling phase and implementation owner:

- `DestinationContinuation::bind` — `src/advanced/reconstruction.rs`.


<a id="cause-DetachedContinuationAssociation"></a>

### `DetachedContinuationAssociation`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::detached` — `src/advanced/reconstruction.rs`. Enclosing true branch: `capacity != record.capacity || record.function.name() != record.descriptor.phase.name()`.


<a id="cause-DetachedReconstructedCapacity"></a>

### `DetachedReconstructedCapacity`


Local detection/handling phase and implementation owner:

- `finish_detached` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing true branch: `actual != record.capacity`.


<a id="cause-DetachedReconstructionOwner"></a>

### `DetachedReconstructionOwner`


Local detection/handling phase and implementation owner:

- `finish_detached` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing match alternative: `_`.


<a id="cause-DuplicateKeyCandidateAlreadyOccupied"></a>

### `DuplicateKeyCandidateAlreadyOccupied`


Local detection/handling phase and implementation owner:

- `BoundKeys::duplicate_retained` — `src/advanced/restoration_keys.rs`. Enclosing true branch: `candidate.is_some()`.


<a id="cause-ForeignOrConsumedReplacementTicket"></a>

### `ForeignOrConsumedReplacementTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != self.session.uid || !Arc::ptr_eq(&ticket.owner, &self.session.inner)`.
- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != self.session.uid || !Arc::ptr_eq(&ticket.owner, &self.session.inner)`.


<a id="cause-ForeignOrConsumedRestorationTicket"></a>

### `ForeignOrConsumedRestorationTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != self.session.uid || !Arc::ptr_eq(&ticket.owner, &self.session.inner)`.
- `check` (module-level helper) — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner)`.


<a id="cause-GenericMessageArchiveBodyAbsent"></a>

### `GenericMessageArchiveBodyAbsent`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::native_checkpoint` — `src/advanced/reconstruction.rs`.
- `Prepared<'a>::imported` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `descriptor.family == record::Family::NativeMessages`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family == Family::NativeMessages`.


<a id="cause-GenericMessageDestinationPreparationRequired"></a>

### `GenericMessageDestinationPreparationRequired`


Local detection/handling phase and implementation owner:

- `Plan<'a>::new` — `src/advanced/reconstruction/plan.rs`. Enclosing match alternative: `record::Family::NativeMessages`.


<a id="cause-GenericMessageReconstructionFamily"></a>

### `GenericMessageReconstructionFamily`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::native_checkpoint` — `src/advanced/reconstruction.rs`. Enclosing true branch: `descriptor.family != Family::NativeMessages`.


<a id="cause-ReconstructionAuthenticationKey"></a>

### `ReconstructionAuthenticationKey`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::check_binding` — `src/advanced/reconstruction.rs`. Enclosing match alternative: `PreparedBody::Messages(_)`.


<a id="cause-ReconstructionCandidateAbsent"></a>

### `ReconstructionCandidateAbsent`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::bind_retained` — `src/advanced/reconstruction.rs`.


<a id="cause-ReconstructionCipherKey"></a>

### `ReconstructionCipherKey`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::check_binding` — `src/advanced/reconstruction.rs`. Enclosing match alternative: `PreparedBody::AeadMessages(_)`.
- `PreparedContinuation::check_binding` — `src/advanced/reconstruction.rs`. Enclosing match alternative: `PreparedBody::Dual(body)`.


<a id="cause-ReconstructionKeysAbsent"></a>

### `ReconstructionKeysAbsent`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::bind_retained` — `src/advanced/reconstruction.rs`.


<a id="cause-ReconstructionMetadata"></a>

### `ReconstructionMetadata`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::allocation_bytes` — `src/advanced/reconstruction.rs`.
- `Unbound<'_>::allocated_bytes` — `src/advanced/reconstruction.rs`.


<a id="cause-ReconstructionOutputCapacity"></a>

### `ReconstructionOutputCapacity`

Detected when copying stored result bytes into locally prepared reconstruction
storage whose capacity is too small. The failed bounds check occurs before that
copy and makes no native call. Reject the inconsistent prepared/archive pair;
preserve any restore failure owner and do not truncate the stored result or
re-execute the operation that originally produced it.


Local detection/handling phase and implementation owner:

- `output` (module-level helper) — `src/advanced/reconstruction.rs`.


<a id="cause-ReconstructionStorageFamilyChanged"></a>

### `ReconstructionStorageFamilyChanged`


Local detection/handling phase and implementation owner:

- `Plan<'a>::bind` — `src/advanced/reconstruction/plan.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordDestinationKeyRoles"></a>

### `RecordDestinationKeyRoles`


Local detection/handling phase and implementation owner:

- `BoundKeys::from_record_retained` — `src/advanced/restoration_keys.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordKeyCandidateAlreadyOccupied"></a>

### `RecordKeyCandidateAlreadyOccupied`


Local detection/handling phase and implementation owner:

- `BoundKeys::from_record_retained` — `src/advanced/restoration_keys.rs`. Enclosing true branch: `candidate.is_some()`.


<a id="cause-RecordMechanismWidth"></a>

### `RecordMechanismWidth`


Local detection/handling phase and implementation owner:

- `BoundKeys::from_record_retained` — `src/advanced/restoration_keys.rs`.


<a id="cause-RecordValidationAccounting"></a>

### `RecordValidationAccounting`


Local detection/handling phase and implementation owner:

- `ParsedRecord::parse` — `src/advanced/record_import.rs`.
- `ParsedRecord::parse` — `src/advanced/record_import.rs`.


<a id="cause-RecoveryDestinationKeyAbsent"></a>

### `RecoveryDestinationKeyAbsent`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::check_binding` — `src/advanced/reconstruction.rs`. Enclosing match alternative: `PreparedBody::Recover(_)`.


<a id="cause-RecoveryPreparationFamily"></a>

### `RecoveryPreparationFamily`


Local detection/handling phase and implementation owner:

- `PreparedContinuation::into_dual_recovery` — `src/advanced/reconstruction.rs`.
- `PreparedContinuation::into_aead_recovery` — `src/advanced/reconstruction.rs`.


<a id="cause-RecoveryValidationCapacity"></a>

### `RecoveryValidationCapacity`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::aead_recovery` — `src/advanced/reconstruction.rs`. Enclosing true branch: `capture`.
- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `let Some(v) = &validation`.
- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `v.maximum() != section .messages .len() .checked_add(1) .ok_or(Error::Rejected(crate::RejectionReason::Restoration( crate::RestorationRejection::RecoveryValidationCapacity, )))?`.


<a id="cause-RestorationInitializationAccounting"></a>

### `RestorationInitializationAccounting`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`.


<a id="cause-RestorationInitializationCapacity"></a>

### `RestorationInitializationCapacity`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`.


<a id="cause-RestorationInitializationOwnerMismatch"></a>

### `RestorationInitializationOwnerMismatch`


Local detection/handling phase and implementation owner:

- `check_initialization` (module-level helper) — `src/advanced/restoration.rs`. Enclosing match alternative: `(OperationBody::NativeMessages(_), _, _) | (_, Some(_), _) | (_, _, Some(_))`.


<a id="cause-RestorationKeyStorageAccounting"></a>

### `RestorationKeyStorageAccounting`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`.


<a id="cause-RestorationPublicationStorageAbsent"></a>

### `RestorationPublicationStorageAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::finish_restore_detachment` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestorationStorageSize"></a>

### `RestorationStorageSize`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`.


<a id="cause-RestorationTransferAbsent"></a>

### `RestorationTransferAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_restore_detachment` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `op.restore_transfer().is_none()`.
- `AdvancedSession::finish_restore_detachment` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestorationTransferCeiling"></a>

### `RestorationTransferCeiling`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_restore_detachment` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestorationTransferProvenanceAbsent"></a>

### `RestorationTransferProvenanceAbsent`


Local detection/handling phase and implementation owner:

- `PreparedDestination::prepare_binding` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestorationTransferUncertain"></a>

### `RestorationTransferUncertain`


Local detection/handling phase and implementation owner:

- `AdvancedSession::finish_restore_detachment` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `transfer.get_id.retains_native_memory()`.


<a id="cause-RestoreJoinedStorageAbsent"></a>

### `RestoreJoinedStorageAbsent`


Local detection/handling phase and implementation owner:

- `PreparedDestination::prepare_at_epoch` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestoreKeyMechanismPolicy"></a>

### `RestoreKeyMechanismPolicy`


Local detection/handling phase and implementation owner:

- `StateRestoreKey<'a>::symmetric` — `src/advanced/restoration_keys.rs`. Enclosing true branch: `!compatible`.


<a id="cause-RestoreNativeStorageAbsent"></a>

### `RestoreNativeStorageAbsent`


Local detection/handling phase and implementation owner:

- `PreparedDestination::prepare_at_epoch` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestoreSymmetricReferenceRequired"></a>

### `RestoreSymmetricReferenceRequired`


Local detection/handling phase and implementation owner:

- `StateRestoreKey<'a>::symmetric` — `src/advanced/restoration_keys.rs`.


<a id="cause-RestoreTransferDestinationKeyRoles"></a>

### `RestoreTransferDestinationKeyRoles`


Local detection/handling phase and implementation owner:

- `PreparedDestination::prepare_binding` — `src/advanced/restoration_transfer.rs`. Enclosing match alternative: `_`.


<a id="cause-SavedStateConsumed"></a>

### `SavedStateConsumed`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`.


<a id="cause-SavedStateContextMismatch"></a>

### `SavedStateContextMismatch`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `!Arc::ptr_eq(&owner, &self.session.inner) || !Arc::ptr_eq(&input.snapshot, &self.session.snapshot)`.


<a id="cause-SavedStateModuleAbsent"></a>

### `SavedStateModuleAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`.


<a id="cause-SignatureMessageAbsent"></a>

### `SignatureMessageAbsent`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::new` — `src/advanced/reconstruction.rs`. Enclosing true branch: `descriptor.family == Family::Signature`.
- `validate` (module-level helper) — `src/advanced/record/signature.rs`.
- `Destination<'a>::imported` — `src/advanced/signature/binding.rs`.
- `RecordPlan<'a>::new` — `src/advanced/signature/checkpoint.rs`.


<a id="cause-SignatureParametersAbsent"></a>

### `SignatureParametersAbsent`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::new` — `src/advanced/reconstruction.rs`. Enclosing true branch: `descriptor.family == Family::Signature`.
- `Destination<'a>::imported` — `src/advanced/signature/binding.rs`.
- `RecordPlan<'a>::new` — `src/advanced/signature/checkpoint.rs`.
- `SignatureOperation::write_checkpoint_messages` — `src/advanced/signature/checkpoint.rs`.
- `SignatureOperation::snapshot_shape` — `src/advanced/signature/snapshot.rs`.


<a id="cause-StaleReplacementTicket"></a>

### `StaleReplacementTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `diagnostics.is_none()`.
- `AdvancedSession::start_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `op.id != ticket.id`.


<a id="cause-StaleRestorationTicket"></a>

### `StaleRestorationTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_state_restore` — `src/advanced/restoration.rs`. Enclosing true branch: `control.id != ticket.id`.
- `check` (module-level helper) — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `op.restore_owner().map(|c| c.id) != Some(ticket.id)`.


<a id="cause-TerminalAuthenticationAbsent"></a>

### `TerminalAuthenticationAbsent`


Local detection/handling phase and implementation owner:

- `finish_detached` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing match alternative: `OperationBody::Dual(body)`.


<a id="cause-TerminalFamily"></a>

### `TerminalFamily`


Local detection/handling phase and implementation owner:

- `finish_detached` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing match alternative: `_`.


<a id="cause-TerminalMessageAbsent"></a>

### `TerminalMessageAbsent`


Local detection/handling phase and implementation owner:

- `finish_detached` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing true branch: `let Some(valid) = record.terminal`.


<a id="cause-TerminalReportAbsent"></a>

### `TerminalReportAbsent`


Local detection/handling phase and implementation owner:

- `finish_detached` (module-level helper) — `src/advanced/reconstruction.rs`. Enclosing true branch: `let Some(valid) = record.terminal`.
- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`.


<a id="cause-TransferStorageAccounting"></a>

### `TransferStorageAccounting`


Local detection/handling phase and implementation owner:

- `total` (module-level helper) — `src/advanced/reconstruction/resources.rs`.
- `prepare` (module-level helper) — `src/advanced/restoration_transfer/preparation.rs`.
- `prepare` (module-level helper) — `src/advanced/restoration_transfer/preparation.rs`.
