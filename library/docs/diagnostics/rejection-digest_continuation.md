Cause contracts for `DigestContinuationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AdvancedInputAllocation"></a>

### `AdvancedInputAllocation`


Local detection/handling phase and implementation owner:

- `Storage::allocate_with_output` — `src/advanced/digest/snapshot.rs`.
- `Storage::allocate_with_output` — `src/advanced/digest/snapshot.rs`.


<a id="cause-AsynchronousResultIdentity"></a>

### `AsynchronousResultIdentity`


Local detection/handling phase and implementation owner:

- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `op.frame.completion.pValue != op.frame.output.as_mut().as_mut_ptr().cast() || rv == CKR_OK && op.frame.completion.ulValue as u128 > op.frame.output.capacity() as u128`.
- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `result.ulVersion != 0 || result.pValue != op.frame.output.as_mut().as_mut_ptr().cast() || result.ulValue as u128 > op.frame.output.capacity() as u128`.


<a id="cause-AsynchronousResultVersion"></a>

### `AsynchronousResultVersion`


Local detection/handling phase and implementation owner:

- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `op.frame.completion.ulVersion != 0`.
- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `rv == CKR_OK && matches!(op.step, Step::Single | Step::Final) && op.frame.completion.ulVersion != 0`.


<a id="cause-CallerDrivenDigestRequiresASynchronousSession"></a>

### `CallerDrivenDigestRequiresASynchronousSession`


Local detection/handling phase and implementation owner:

- `synchronous` (module-level helper) — `src/advanced/digest/control.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.


<a id="cause-CallerDrivenDigestResultOwner"></a>

### `CallerDrivenDigestResultOwner`


Local detection/handling phase and implementation owner:

- `Session::finish_digest` — `src/advanced/digest/control.rs`. Enclosing match alternative: `_`.


<a id="cause-ConsumedDigestTicket"></a>

### `ConsumedDigestTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::digest_output_requirement` — `src/advanced/digest/control.rs`. Enclosing true branch: `self.id == 0`.


<a id="cause-DeclarationOnATypedDigest"></a>

### `DeclarationOnATypedDigest`


Local detection/handling phase and implementation owner:

- `captured_contract` (module-level helper) — `src/advanced/digest/extension.rs`. Enclosing false branch: `supplied.is_none()`.


<a id="cause-DeclarationWithoutDigestExtension"></a>

### `DeclarationWithoutDigestExtension`


Local detection/handling phase and implementation owner:

- `import_contract` (module-level helper) — `src/advanced/digest/extension.rs`. Enclosing false branch: `supplied.is_none()`.


<a id="cause-DigestOidAccounting"></a>

### `DigestOidAccounting`


Local detection/handling phase and implementation owner:

- `DigestFrame::allocation_bytes_with_oid` — `src/advanced/digest.rs`.


<a id="cause-DigestOidSelection"></a>

### `DigestOidSelection`


Local detection/handling phase and implementation owner:

- `DigestFrame::allocation_bytes_with_oid` — `src/advanced/digest.rs`. Enclosing true branch: `selection.has_oid() != oid.is_some()`.
- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `selection.has_oid() != message.params.digest_oid.is_some()`.


<a id="cause-DigestContinuationTicketUnavailable"></a>

### `DigestContinuationTicketUnavailable`


Local detection/handling phase and implementation owner:

- `Session::take_digest_ticket` — `src/advanced/digest/control.rs`. Enclosing true branch: `body.observer != super::Observer::Session`.


<a id="cause-DigestDeclarationFamily"></a>

### `DigestDeclarationFamily`


Local detection/handling phase and implementation owner:

- `import_contract` (module-level helper) — `src/advanced/digest/extension.rs`. Enclosing false branch: `supplied.is_none()`.


<a id="cause-DigestDestinationDeclarationAbsentOrUnexpected"></a>

### `DigestDestinationDeclarationAbsentOrUnexpected`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::check_binding` — `src/advanced/digest/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestDestinationDeclarationMismatch"></a>

### `DigestDestinationDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `check_declaration` (module-level helper) — `src/advanced/digest/extension.rs`. Enclosing true branch: `contract.mechanism_number() != mechanism || contract.constants_edition() != edition || contract.mutates_key()`.


<a id="cause-DigestExtensionAsynchronousModeOrInitReplayIsUnavailable"></a>

### `DigestExtensionAsynchronousModeOrInitReplayIsUnavailable`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `graph.is_some() && (pending || step == Step::Init)`.


<a id="cause-DigestExtensionGraphSelection"></a>

### `DigestExtensionGraphSelection`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/digest/preparation.rs`. Enclosing match alternative: `(DigestSelection::Extension { .. }, None) | (_, Some(_))`.


<a id="cause-DigestExtensionNotCapturable"></a>

### `DigestExtensionNotCapturable`


Local detection/handling phase and implementation owner:

- `DigestOperation::extension_snapshot_shape` — `src/advanced/digest/extension_snapshot.rs`. Enclosing true branch: `!matches!( self.step, Step::Single | Step::Update(_) | Step::Final | Step::OutputRequired { .. } ) || self.activity.pending() || self.activity.inactive() || !self.frame.unchanged()`.


<a id="cause-DigestExtensionParametersAbsent"></a>

### `DigestExtensionParametersAbsent`


Local detection/handling phase and implementation owner:

- `DigestOperation::extension_snapshot_shape` — `src/advanced/digest/extension_snapshot.rs`.


<a id="cause-DigestExtensionSelection"></a>

### `DigestExtensionSelection`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/digest/preparation.rs`. Enclosing true branch: `request.contract.native_mechanism() != mechanism || oid.is_some()`.


<a id="cause-DigestExtensionSnapshotAccounting"></a>

### `DigestExtensionSnapshotAccounting`


Local detection/handling phase and implementation owner:

- `overflow` (module-level helper) — `src/advanced/digest/extension_snapshot.rs`.


<a id="cause-DigestExtensionSnapshotChanged"></a>

### `DigestExtensionSnapshotChanged`


Local detection/handling phase and implementation owner:

- `Packet::copy_from` — `src/advanced/digest/extension_snapshot.rs`. Enclosing true branch: `source.extension_snapshot_shape()? != self.shape`.


<a id="cause-DigestExtensionSnapshotTrailingBytes"></a>

### `DigestExtensionSnapshotTrailingBytes`


Local detection/handling phase and implementation owner:

- `Packet::materialize` — `src/advanced/digest/extension_snapshot.rs`. Enclosing true branch: `parts.bytes.len() != self.shape.output_length`.


<a id="cause-DigestFacadeObserverChanged"></a>

### `DigestFacadeObserverChanged`


Local detection/handling phase and implementation owner:

- `retain_on_error` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing true branch: `body.observer != super::Observer::Ticket`.


<a id="cause-DigestFacadeOwnerChanged"></a>

### `DigestFacadeOwnerChanged`


Local detection/handling phase and implementation owner:

- `retain_on_error` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing true branch: `result.is_err() && ticket.id != 0`.


<a id="cause-DigestFunctionsUnavailable"></a>

### `DigestFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/digest/preparation.rs`. Enclosing true branch: `state.native.table.C_DigestInit.is_none() || match selection.route() { MessageRoute::Single => state.native.table.C_Digest.is_none(), MessageRoute::Multipart => { state.native.table.C_DigestUpdate.is_none() || state.native.table.C_DigestFinal.is_none() } }`.


<a id="cause-DigestGraphAccounting"></a>

### `DigestGraphAccounting`


Local detection/handling phase and implementation owner:

- `DigestFrame::allocation_bytes_with_oid` — `src/advanced/digest.rs`.
- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`.


<a id="cause-DigestHasNoContextAuthenticationRole"></a>

### `DigestHasNoContextAuthenticationRole`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing true branch: `authentication.is_some()`.


<a id="cause-DigestImportRequiresADestinationAbiDeclaration"></a>

### `DigestImportRequiresADestinationAbiDeclaration`


Local detection/handling phase and implementation owner:

- `import_contract` (module-level helper) — `src/advanced/digest/extension.rs`. Enclosing true branch: `parameters.caller_asserted`.


<a id="cause-DigestInjectionStorageSize"></a>

### `DigestInjectionStorageSize`


Local detection/handling phase and implementation owner:

- `PreparedInput::prepare` — `src/advanced/digest/control.rs`.
- `PreparedInput::prepare` — `src/advanced/digest/control.rs`. Enclosing match alternative: `Input::Bytes(bytes, _)`.


<a id="cause-DigestInputCompletionUnproven"></a>

### `DigestInputCompletionUnproven`


Local detection/handling phase and implementation owner:

- `inject` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing match alternative: `Ok(())`.


<a id="cause-DigestInputFunctionUnavailable"></a>

### `DigestInputFunctionUnavailable`


Local detection/handling phase and implementation owner:

- `ResolvedInput<'a>::prepare` — `src/advanced/digest/control/injection.rs`.
- `validate_injection` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestInputPhase"></a>

### `DigestInputPhase`


Local detection/handling phase and implementation owner:

- `validate_injection` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing true branch: `body.activity.pending() || body.activity.inactive() || !matches!(body.step, Step::Update(_) | Step::Final)`.


<a id="cause-DigestInputPreparation"></a>

### `DigestInputPreparation`


Local detection/handling phase and implementation owner:

- `PreparedInput::bind_retained` — `src/advanced/digest/control.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestInputRetirementCount"></a>

### `DigestInputRetirementCount`


Local detection/handling phase and implementation owner:

- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing match alternative: `Step::Update(index)`.


<a id="cause-DigestInputSize"></a>

### `DigestInputSize`


Local detection/handling phase and implementation owner:

- `DigestFrame::allocation_bytes` — `src/advanced/digest.rs`.


<a id="cause-DigestMechanismWidth"></a>

### `DigestMechanismWidth`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_checkpoint` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `11 | 12`.


<a id="cause-DigestNativeParameterIdentity"></a>

### `DigestNativeParameterIdentity`


Local detection/handling phase and implementation owner:

- `complete_step` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `!op.frame.unchanged()`.


<a id="cause-DigestOperationNotJoinable"></a>

### `DigestOperationNotJoinable`


Local detection/handling phase and implementation owner:

- `DigestOperation::joined_capacity` — `src/advanced/digest.rs`. Enclosing true branch: `!self.activity.pending()`.


<a id="cause-DigestOperationStorageSize"></a>

### `DigestOperationStorageSize`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/digest/preparation.rs`.
- `start_retained` (module-level helper) — `src/advanced/digest/preparation.rs`.


<a id="cause-DigestOutputCapacity"></a>

### `DigestOutputCapacity`

Detected after native digest Single/Final succeeded but its returned length
does not fit the owned output. The digest enters Failed, retains Active native
activity, and marks the runtime uncertain. Inputs/output and any key or native
parameter owners remain retained by the operation. No typed buffer request was
produced. Do not resize, replay or restart this digest; its existing owner's
completion-aware cleanup must establish release, and may remain unavailable.


Local detection/handling phase and implementation owner:

- `complete_step` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `rv == CKR_OK && matches!(op.step, Step::Single | Step::Final)`.


<a id="cause-DigestOutputDescriptorAbsent"></a>

### `DigestOutputDescriptorAbsent`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`.


<a id="cause-DigestOutputIsNotAwaitingStorage"></a>

### `DigestOutputIsNotAwaitingStorage`


Local detection/handling phase and implementation owner:

- `super::DigestOperation::digest_output_preparation` — `src/advanced/digest/extension.rs`.


<a id="cause-DigestOutputWaitingPhase"></a>

### `DigestOutputWaitingPhase`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `pending || !matches!(step, Step::Single | Step::Final) || descriptor.input.is_open()`.


<a id="cause-DigestPendingOutputOwner"></a>

### `DigestPendingOutputOwner`


Local detection/handling phase and implementation owner:

- `super::DigestOperation::digest_output_preparation` — `src/advanced/digest/extension.rs`. Enclosing true branch: `self.activity.pending()`.


<a id="cause-DigestReaderRetirementOccupied"></a>

### `DigestReaderRetirementOccupied`


Local detection/handling phase and implementation owner:

- `PreparedInput::bind_retained` — `src/advanced/digest/control.rs`. Enclosing true branch: `retired_reader.is_some()`.


<a id="cause-DigestReconstructionAccounting"></a>

### `DigestReconstructionAccounting`


Local detection/handling phase and implementation owner:

- `RecordStorage<'_>::allocated_bytes` — `src/advanced/digest/snapshot.rs`.


<a id="cause-DigestReplacementStorage"></a>

### `DigestReplacementStorage`


Local detection/handling phase and implementation owner:

- `super::DigestOperation::attach_digest_output` — `src/advanced/digest/extension.rs`. Enclosing true branch: `output.capacity() < capacity`.


<a id="cause-DigestRequiredCapacityWidth"></a>

### `DigestRequiredCapacityWidth`


Local detection/handling phase and implementation owner:

- `complete_step` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `size.is_some() && matches!(op.step, Step::Single | Step::Final)`.


<a id="cause-DigestResultContractMismatch"></a>

### `DigestResultContractMismatch`


Local detection/handling phase and implementation owner:

- `finish` (module-level helper) — `src/advanced/digest/control.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestRetirementAccounting"></a>

### `DigestRetirementAccounting`


Local detection/handling phase and implementation owner:

- `Storage::metadata_bytes` — `src/advanced/digest/snapshot.rs`.


<a id="cause-DigestSnapshotMetadataAccounting"></a>

### `DigestSnapshotMetadataAccounting`


Local detection/handling phase and implementation owner:

- `Storage::temporary_bytes` — `src/advanced/digest/snapshot.rs`.


<a id="cause-DigestSnapshotPartCount"></a>

### `DigestSnapshotPartCount`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `target.as_slice().len() != source.len()`.
- `Storage::allocate_with_output` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `parts.len() == count`.
- `Storage::allocate_with_output` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `parts.len() != count`.


<a id="cause-DigestSnapshotStorageAccounting"></a>

### `DigestSnapshotStorageAccounting`


Local detection/handling phase and implementation owner:

- `Storage::allocated_bytes` — `src/advanced/digest/snapshot.rs`.
- `Storage::allocated_bytes` — `src/advanced/digest/snapshot.rs`.
- `Storage::allocated_bytes` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `let Some((value, witness)) = &self.oid`.


<a id="cause-DigestStorageSize"></a>

### `DigestStorageSize`


Local detection/handling phase and implementation owner:

- `DigestFrame::allocation_bytes` — `src/advanced/digest.rs`.


<a id="cause-DuplicateOperationCompletion"></a>

### `DuplicateOperationCompletion`


Local detection/handling phase and implementation owner:

- `complete_step` (module-level helper) — `src/advanced/digest.rs`. Enclosing match alternative: `_`.


<a id="cause-ExtensionDigestAsynchronousModeUnavailable"></a>

### `ExtensionDigestAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing true branch: `session.entry.mode != crate::AdvancedSessionMode::Synchronous`.


<a id="cause-ExtensionDigestFacadeIncomplete"></a>

### `ExtensionDigestFacadeIncomplete`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing match alternative: `Ok(_)`.


<a id="cause-ExtensionDigestFacadeRoute"></a>

### `ExtensionDigestFacadeRoute`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-ExtensionDigestRequiresParameterOutputOwner"></a>

### `ExtensionDigestRequiresParameterOutputOwner`


Local detection/handling phase and implementation owner:

- `DigestSelection::result` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `Self::Extension { .. }`.


<a id="cause-ExtensionDigestResultOwner"></a>

### `ExtensionDigestResultOwner`


Local detection/handling phase and implementation owner:

- `Session::finish_extension_digest_stream` — `src/advanced/digest/control.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeDigestInputChanged"></a>

### `NativeDigestInputChanged`


Local detection/handling phase and implementation owner:

- `inject` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing true branch: `!native.data.unchanged()`.


<a id="cause-NativeDigestResultOwner"></a>

### `NativeDigestResultOwner`


Local detection/handling phase and implementation owner:

- `Session::finish_native_digest` — `src/advanced/digest/control.rs`. Enclosing match alternative: `_`.


<a id="cause-OperationFailedExplicitCleanupRequired"></a>

### `OperationFailedExplicitCleanupRequired`


Local detection/handling phase and implementation owner:

- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `op.step == Step::Failed`.


<a id="cause-OperationMetadataLength"></a>

### `OperationMetadataLength`


Local detection/handling phase and implementation owner:

- `DigestFrame::metadata_bytes_for_count` — `src/advanced/digest.rs`.


<a id="cause-OperationNotActive"></a>

### `OperationNotActive`


Local detection/handling phase and implementation owner:

- `function` (module-level helper) — `src/advanced/digest.rs`. Enclosing match alternative: `_`.
- `Call::resolve` — `src/advanced/digest/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-ReconstructionDigestMessageAbsent"></a>

### `ReconstructionDigestMessageAbsent`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`.


<a id="cause-ReconstructionDigestPhase"></a>

### `ReconstructionDigestPhase`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordDigestMechanism"></a>

### `RecordDigestMechanism`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_checkpoint` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `2`.


<a id="cause-RecordDigestParameterMechanism"></a>

### `RecordDigestParameterMechanism`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_descriptor` — `src/advanced/digest/selection.rs`. Enclosing true branch: `descriptor.mechanism != CKM_SHA512_T as u64 || descriptor.cipher_options.is_some()`.


<a id="cause-RecordDigestParameterWidth"></a>

### `RecordDigestParameterWidth`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_descriptor` — `src/advanced/digest/selection.rs`. Enclosing true branch: `selection.length() != descriptor.size`.


<a id="cause-RecordDigestProfile"></a>

### `RecordDigestProfile`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_checkpoint` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordDigestWidth"></a>

### `RecordDigestWidth`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_checkpoint` — `src/advanced/digest/selection.rs`. Enclosing true branch: `selection.length() != size`.


<a id="cause-RecordNativeDigestMechanism"></a>

### `RecordNativeDigestMechanism`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_checkpoint` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `3`.
- `DigestSelection::from_checkpoint` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `4`.


<a id="cause-RecordParameterizedDigestProfile"></a>

### `RecordParameterizedDigestProfile`


Local detection/handling phase and implementation owner:

- `DigestSelection::from_descriptor` — `src/advanced/digest/selection.rs`. Enclosing match alternative: `_`.


<a id="cause-SingleDigestInputCount"></a>

### `SingleDigestInputCount`


Local detection/handling phase and implementation owner:

- `DigestFrame::allocation_bytes` — `src/advanced/digest.rs`. Enclosing true branch: `selection.route() == MessageRoute::Single && parts.len() != 1`.
- `RecordPlan<'a>::new` — `src/advanced/digest/snapshot.rs`. Enclosing true branch: `selection.route() == crate::advanced::MessageRoute::Single && count != usize::from(message.state != record::MessageState::Finished)`.


<a id="cause-StaleDigestFacadeTicket"></a>

### `StaleDigestFacadeTicket`


Local detection/handling phase and implementation owner:

- `retain_on_error` (module-level helper) — `src/advanced/digest/batch.rs`. Enclosing true branch: `operation.id != ticket.id`.


<a id="cause-UncopiedDigestSnapshot"></a>

### `UncopiedDigestSnapshot`


Local detection/handling phase and implementation owner:

- `Packet::materialize` — `src/advanced/digest/extension_snapshot.rs`.
