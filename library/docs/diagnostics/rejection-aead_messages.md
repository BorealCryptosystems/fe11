Cause contracts for `AeadMessagesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AeadInitDescriptorMutation"></a>

### `AeadInitDescriptorMutation`


Local detection/handling phase and implementation owner:

- `validate_binding_storage` (module-level helper) — `src/advanced/gcm/storage.rs`. Enclosing true branch: `!mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0`.


<a id="cause-AeadInitHasNoParameters"></a>

### `AeadInitHasNoParameters`


Local detection/handling phase and implementation owner:

- `InitBinding::reference` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `Self::WithoutParameters`.


<a id="cause-AeadInitSeedAbsent"></a>

### `AeadInitSeedAbsent`


Local detection/handling phase and implementation owner:

- `InitBinding::reference` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `Self::Shared { prepared_message: InitReference::Seed, seed, .. }`.


<a id="cause-AeadInitSelectionRepresentation"></a>

### `AeadInitSelectionRepresentation`


Local detection/handling phase and implementation owner:

- `start_inner` (module-level helper) — `src/advanced/gcm/initialization.rs`. Enclosing true branch: `kind.stream() || parameters.origin.kind() != kind`.


<a id="cause-AeadInitTagRepresentation"></a>

### `AeadInitTagRepresentation`


Local detection/handling phase and implementation owner:

- `start_inner` (module-level helper) — `src/advanced/gcm/initialization.rs`. Enclosing true branch: `!decrypt && parameters.expected_tag.is_some() || parameters .expected_tag .is_some_and(|tag| parameters.origin.tag_bytes().ok() != Some(tag.len()))`.


<a id="cause-AeadCallerFedRefusal"></a>

### `AeadCallerFedRefusal`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::refuse_message` — `src/advanced/gcm/result.rs`.


<a id="cause-AeadCallerFedStreamRequired"></a>

### `AeadCallerFedStreamRequired`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/gcm/submission.rs`.


<a id="cause-AeadCapacityRestoreOutputs"></a>

### `AeadCapacityRestoreOutputs`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `let Some(output) = self.messages.aead_batch().and_then(|state| state.output)`.


<a id="cause-AeadCapacityRestorePrefix"></a>

### `AeadCapacityRestorePrefix`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `output.prepared`.


<a id="cause-AeadCapacityRestoreRow"></a>

### `AeadCapacityRestoreRow`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `let Some(output) = self.messages.aead_batch().and_then(|state| state.output)`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `let Some(output) = self.messages.aead_batch().and_then(|state| state.output)`.


<a id="cause-AeadCompatibilityOutputLength"></a>

### `AeadCompatibilityOutputLength`

Detected while computing the compatibility request's output allocation from
data length and tag length, before starting its message owner. Checked addition
overflow means that no representable output size exists for this request.
Reduce/correct the caller's request before a new preparation; waiting, increasing
memory credits or truncating the length cannot repair it. This sizing check
does not dispatch encryption/decryption.


Local detection/handling phase and implementation owner:

- `complete_single_message` (module-level helper) — `src/advanced/gcm/completion.rs`.


<a id="cause-AeadDiagnosticNotUsed"></a>

### `AeadDiagnosticNotUsed`


Local detection/handling phase and implementation owner:

- `Input::restored` — `src/advanced/gcm/input.rs`.


<a id="cause-AeadFinalTagRepresentation"></a>

### `AeadFinalTagRepresentation`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `(!body.decrypt && expected_tag.is_some()) || (body.decrypt && expected_tag.is_none() && frame.expected_tag.is_none()) || expected_tag.is_some_and(|tag| frame.origin.tag_bytes().ok() != Some(tag.len()))`.


<a id="cause-AeadFixedBitsAbiWidth"></a>

### `AeadFixedBitsAbiWidth`


Local detection/handling phase and implementation owner:

- `NativeParameters::new` — `src/advanced/aead_parameters.rs`.


<a id="cause-AeadInputCeiling"></a>

### `AeadInputCeiling`


Local detection/handling phase and implementation owner:

- `submit` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `total > limits.maximum_total_bytes`.


<a id="cause-AeadInputMetadataOverflow"></a>

### `AeadInputMetadataOverflow`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`.
- `AeadStoragePlan::push` — `src/advanced/gcm/storage.rs`.


<a id="cause-AeadInputSizeOverflow"></a>

### `AeadInputSizeOverflow`


Local detection/handling phase and implementation owner:

- `submit` (module-level helper) — `src/advanced/gcm/submission.rs`.


<a id="cause-AeadInvocationDiagnosticsAlreadyInstalled"></a>

### `AeadInvocationDiagnosticsAlreadyInstalled`


Local detection/handling phase and implementation owner:

- `start_shared_messages` (module-level helper) — `src/advanced/gcm/preparation.rs`. Enclosing true branch: `diagnostics.is_some()`.


<a id="cause-AeadIsNotWaitingForStorage"></a>

### `AeadIsNotWaitingForStorage`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::output_preparation` — `src/advanced/gcm/output.rs`.


<a id="cause-AeadMechanismMutation"></a>

### `AeadMechanismMutation`


Local detection/handling phase and implementation owner:

- `validate_binding_storage` (module-level helper) — `src/advanced/gcm/storage.rs`. Enclosing true branch: `mechanism.mechanism != kind.mechanism()`.


<a id="cause-AeadMessageInitInputBytesMutation"></a>

### `AeadMessageInitInputBytesMutation`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::finish_step` — `src/advanced/gcm/completion.rs`. Enclosing true branch: `!input_nonce || expected_tag .is_some_and(|expected| tag.as_slice() != expected.as_slice())`.
- `AeadMessageOperation::inspect_returned_boundary` — `src/advanced/gcm/validation.rs`. Enclosing true branch: `!input_nonce || expected_tag.is_some_and(|expected| tag.as_slice() != expected.as_slice())`.


<a id="cause-AeadMessageAlreadyPublished"></a>

### `AeadMessageAlreadyPublished`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::result` — `src/advanced/gcm/result.rs`.


<a id="cause-AeadMessageAsynchronousOutputIdentity"></a>

### `AeadMessageAsynchronousOutputIdentity`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::drive_inner` — `src/advanced/gcm/progression.rs`. Enclosing true branch: `self.completion.ulVersion != 0 || self.completion.pValue != pointer || rv == CKR_OK && self.completion.ulValue as u128 > (out.capacity() - frame.used) as u128`.
- `AeadMessageOperation::drive_inner` — `src/advanced/gcm/progression.rs`. Enclosing true branch: `self.completion.ulVersion != 0 || self.completion.pValue != pointer || self.completion.ulValue as usize > out.capacity() - frame.used`.


<a id="cause-AeadMessageBatchCeiling"></a>

### `AeadMessageBatchCeiling`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`. Enclosing true branch: `count > limits.maximum_parts || total > limits.maximum_total_bytes`.
- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `requested_parts > ceilings.maximum_parts || requested_bytes > ceilings.maximum_total_bytes`.


<a id="cause-AeadMessageDecryptNonceMutation"></a>

### `AeadMessageDecryptNonceMutation`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::validate_frame` — `src/advanced/gcm/validation.rs`. Enclosing true branch: `nonce.as_slice() != frame.origin.iv()`.


<a id="cause-AeadMessageDecryptParameters"></a>

### `AeadMessageDecryptParameters`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.decrypt() && request.tag.map_or(true, |tag| tag.len() != tag_bytes)`.
- `InputAccounting::validate` — `src/advanced/gcm/storage.rs`. Enclosing true branch: `requests.decrypt() && request.tag.map_or(true, |tag| { request.nonce.tag_bytes().ok() != Some(tag.len()) })`.
- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `expected.len() != tag`.


<a id="cause-AeadMessageFailedExplicitCleanupRequired"></a>

### `AeadMessageFailedExplicitCleanupRequired`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::drive_inner` — `src/advanced/gcm/progression.rs`. Enclosing true branch: `self.step == AeadStep::Failed`.


<a id="cause-AeadMessageGeneratedFixedBitsMutation"></a>

### `AeadMessageGeneratedFixedBitsMutation`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::validate_frame` — `src/advanced/gcm/validation.rs`. Enclosing true branch: `!frame.origin.fixed_bits_unchanged(nonce.as_slice())`.


<a id="cause-AeadMessageGeneratedNonceChanged"></a>

### `AeadMessageGeneratedNonceChanged`


Local detection/handling phase and implementation owner:

- `observe_generated_nonce` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing true branch: `prior.as_slice() != nonce`.


<a id="cause-AeadMessageGeneratedNonceLength"></a>

### `AeadMessageGeneratedNonceLength`


Local detection/handling phase and implementation owner:

- `observe_generated_nonce` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing true branch: `storage.capacity() != nonce.len()`.


<a id="cause-AeadMessageInputOverflow"></a>

### `AeadMessageInputOverflow`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`.
- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`.
- `data_length` (module-level helper) — `src/advanced/gcm/snapshot/record_plan.rs`.


<a id="cause-AeadMessageKeyReferenceSelection"></a>

### `AeadMessageKeyReferenceSelection`


Local detection/handling phase and implementation owner:

- `check_message_key` (module-level helper) — `src/advanced/gcm/validation.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadMessageLengthOverflow"></a>

### `AeadMessageLengthOverflow`


Local detection/handling phase and implementation owner:

- `Request<'_>::data_len` — `src/advanced/gcm/input.rs`.
- `super::Frame::accepted_after` — `src/advanced/gcm/input.rs`.


<a id="cause-AeadMessageMechanism"></a>

### `AeadMessageMechanism`


Local detection/handling phase and implementation owner:

- `CipherKind::from_mechanism` — `src/advanced/aead_parameters.rs`. Enclosing false branch: `mechanism == CKM_SALSA20_POLY1305 as u64`.


<a id="cause-AeadMessageMessageCheckpointUnavailable"></a>

### `AeadMessageMessageCheckpointUnavailable`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`. Enclosing true branch: `self.input.is_some() || self.pending() && !recovery || self.step == AeadStep::Failed || !matches!(self.outcome, AeadOutcome::Nominal)`.


<a id="cause-AeadMessageMessageCount"></a>

### `AeadMessageMessageCount`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.len() == 0 || self.len() > limits.maximum_parts`.
- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `messages.len() == 0 || messages.len() > ceilings.maximum_parts`.


<a id="cause-AeadMessageMessageFunctionsUnavailable"></a>

### `AeadMessageMessageFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/gcm/resolved_call.rs`.
- `check_message_key` (module-level helper) — `src/advanced/gcm/validation.rs`. Enclosing true branch: `!available`.


<a id="cause-AeadMessageNativeTagMutation"></a>

### `AeadMessageNativeTagMutation`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::validate_frame` — `src/advanced/gcm/validation.rs`. Enclosing true branch: `frame .expected_tag .as_ref() .is_some_and(|expected| tag.as_slice() != expected.as_slice())`.


<a id="cause-AeadMessageNotActive"></a>

### `AeadMessageNotActive`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::function` — `src/advanced/gcm/operation.rs`. Enclosing match alternative: `_`.
- `Call::resolve` — `src/advanced/gcm/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadMessageNotCapturable"></a>

### `AeadMessageNotCapturable`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `self.input.is_some() || !self.retired_queued.is_empty() || self.pending() || !matches!(self.outcome, AeadOutcome::Nominal) || matches!( self.step, AeadStep::Init | AeadStep::Done | AeadStep::Failed )`.


<a id="cause-AeadMessageNotComplete"></a>

### `AeadMessageNotComplete`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::result` — `src/advanced/gcm/result.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-AeadMessageOperationNotJoinable"></a>

### `AeadMessageOperationNotJoinable`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::joined_capacity` — `src/advanced/gcm/rejoin.rs`. Enclosing true branch: `!self.pending() || !self.decrypt`.


<a id="cause-AeadMessageOutputProgression"></a>

### `AeadMessageOutputProgression`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::joined_capacity` — `src/advanced/gcm/rejoin.rs`.


<a id="cause-AeadMessageOutputShape"></a>

### `AeadMessageOutputShape`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`. Enclosing true branch: `outputs.len() != self.frames.len()`.


<a id="cause-AeadMessageOutputsAbsent"></a>

### `AeadMessageOutputsAbsent`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`.
- `PreparedAead::restore_row` — `src/advanced/gcm/initialization.rs`.
- `AeadMessageOperation::joined_capacity` — `src/advanced/gcm/rejoin.rs`.
- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`.
- `AeadMessageOperation::describe_snapshot` — `src/advanced/gcm/snapshot.rs`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`.
- `PreparedSnapshot::copy_from` — `src/advanced/gcm/snapshot.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`.


<a id="cause-AeadMessagePartOverflow"></a>

### `AeadMessagePartOverflow`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`.


<a id="cause-AeadMessageProvidedNonceMutation"></a>

### `AeadMessageProvidedNonceMutation`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::validate_frame` — `src/advanced/gcm/validation.rs`. Enclosing true branch: `nonce.as_slice() != frame.origin.iv()`.


<a id="cause-AeadMessageResultWithheldAfterFailure"></a>

### `AeadMessageResultWithheldAfterFailure`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::result` — `src/advanced/gcm/result.rs`. Enclosing true branch: `matches!(self.outcome, AeadOutcome::Closing { .. })`.


<a id="cause-AeadMessageSelectionTagRepresentation"></a>

### `AeadMessageSelectionTagRepresentation`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `message.origin.kind() != body.kind || (!body.decrypt && message.expected_tag.is_some()) || (body.decrypt && matches!(submission, Submission::Single { .. }) && message.expected_tag.is_none()) || message .expected_tag .is_some_and(|tag| message.origin.tag_bytes().ok() != Some(tag.len()))`.


<a id="cause-AeadMessageTicketUnavailable"></a>

### `AeadMessageTicketUnavailable`


Local detection/handling phase and implementation owner:

- `Session::take_aead_message_ticket` — `src/advanced/gcm/ticket.rs`. Enclosing true branch: `body.observer != Observer::Session`.


<a id="cause-AeadMessageUnexpectedGeneratedNonce"></a>

### `AeadMessageUnexpectedGeneratedNonce`


Local detection/handling phase and implementation owner:

- `observe_generated_nonce` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing match alternative: `GeneratedNonce::NotGenerated`.


<a id="cause-AeadNativeLengthWidth"></a>

### `AeadNativeLengthWidth`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::finish_step` — `src/advanced/gcm/completion.rs`. Enclosing true branch: `let Some(index) = output`.


<a id="cause-AeadNativeParameterIdentity"></a>

### `AeadNativeParameterIdentity`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::validate_frame` — `src/advanced/gcm/validation.rs`. Enclosing true branch: `!frame.params.unchanged( &frame.origin, frame.expected, nonce.as_slice().as_ptr().cast_mut(), tag.as_slice().as_ptr().cast_mut(), )?`.


<a id="cause-AeadOutputAlreadyPublished"></a>

### `AeadOutputAlreadyPublished`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/gcm/submission.rs`.


<a id="cause-AeadOutputCallAbsent"></a>

### `AeadOutputCallAbsent`


Local detection/handling phase and implementation owner:

- `Pending::new` — `src/advanced/gcm/output.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadOutputCapacityOverflow"></a>

### `AeadOutputCapacityOverflow`

Detected while preparing replacement storage for a retained AEAD output
request: already used bytes plus the requested capacity overflow usize.
The existing frame and output request stay owned; no replacement is attached
by this arithmetic check and no native call is issued. Select a representable
capacity through the same owner's output-preparation API, if that owner still
admits replacement. Do not discard previously retained output or replay an
authenticated message to avoid the accumulated length.


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::output_preparation` — `src/advanced/gcm/output.rs`.


<a id="cause-AeadOutputStillReferencedByPendingCall"></a>

### `AeadOutputStillReferencedByPendingCall`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::output_preparation` — `src/advanced/gcm/output.rs`. Enclosing true branch: `self.pending()`.


<a id="cause-AeadOutputsAbsent"></a>

### `AeadOutputsAbsent`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::output_preparation` — `src/advanced/gcm/output.rs`.


<a id="cause-AeadPreparedMessageIndex"></a>

### `AeadPreparedMessageIndex`


Local detection/handling phase and implementation owner:

- `InitBinding::reference` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `Self::Shared { prepared_message: InitReference::Message(index), .. }`.


<a id="cause-AeadPreparedOutputWidth"></a>

### `AeadPreparedOutputWidth`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::attach_output` — `src/advanced/gcm/output.rs`. Enclosing true branch: `replacement.capacity() != total || replacement.as_slice().len() != total`.


<a id="cause-AeadQueuedFragmentCount"></a>

### `AeadQueuedFragmentCount`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::queued_fragments` — `src/advanced/gcm/queued_input.rs`. Enclosing true branch: `frame.inputs.len() != frame.layout.lengths().len()`.


<a id="cause-AeadQueuedFragmentWidth"></a>

### `AeadQueuedFragmentWidth`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::queued_fragments` — `src/advanced/gcm/queued_input.rs`. Enclosing true branch: `bytes.as_slice().len() != *expected && !(part < consumed && bytes.as_slice().is_empty())`.


<a id="cause-AeadQueuedInputTransition"></a>

### `AeadQueuedInputTransition`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::queued_after_success` — `src/advanced/gcm/progression.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadQueuedRowAbsent"></a>

### `AeadQueuedRowAbsent`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::queued_fragments` — `src/advanced/gcm/queued_input.rs`.
- `AeadMessageOperation::check_queued_retirement` — `src/advanced/gcm/queued_input.rs`.


<a id="cause-AeadRecordedFixedBits"></a>

### `AeadRecordedFixedBits`


Local detection/handling phase and implementation owner:

- `RecordSelection<'a>::new` — `src/advanced/aead_parameters.rs`.


<a id="cause-AeadRecordedGenerator"></a>

### `AeadRecordedGenerator`


Local detection/handling phase and implementation owner:

- `RecordSelection<'a>::new` — `src/advanced/aead_parameters.rs`.


<a id="cause-AeadRecordedInitialNonce"></a>

### `AeadRecordedInitialNonce`


Local detection/handling phase and implementation owner:

- `RecordSelection<'a>::new` — `src/advanced/aead_parameters.rs`. Enclosing false branch: `kind.stream()`.


<a id="cause-AeadRefusalPhase"></a>

### `AeadRefusalPhase`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::refuse_message` — `src/advanced/gcm/result.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadReportCountOverflow"></a>

### `AeadReportCountOverflow`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `submission.message().is_some()`.


<a id="cause-AeadResultMetadataOverflow"></a>

### `AeadResultMetadataOverflow`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`.
- `AeadStoragePlan::empty` — `src/advanced/gcm/storage.rs`.


<a id="cause-AeadRetainedOutputRange"></a>

### `AeadRetainedOutputRange`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::finish_step` — `src/advanced/gcm/completion.rs`. Enclosing true branch: `let Some(index) = output`.
- `AeadMessageOperation::output_preparation` — `src/advanced/gcm/output.rs`.


<a id="cause-AeadRetirementAllocation"></a>

### `AeadRetirementAllocation`


Local detection/handling phase and implementation owner:

- `Storage::allocate` — `src/advanced/gcm/queued_input.rs`.


<a id="cause-AeadRetirementMetadataOverflow"></a>

### `AeadRetirementMetadataOverflow`


Local detection/handling phase and implementation owner:

- `metadata` (module-level helper) — `src/advanced/gcm/queued_input.rs`.


<a id="cause-AeadRetirementPoolAbsent"></a>

### `AeadRetirementPoolAbsent`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::check_queued_retirement` — `src/advanced/gcm/queued_input.rs`.


<a id="cause-AeadRetirementSlotAbsent"></a>

### `AeadRetirementSlotAbsent`


Local detection/handling phase and implementation owner:

- `Pool::check` — `src/advanced/gcm/queued_input.rs`. Enclosing false branch: `self.slots.get(index).is_some_and(Option::is_some)`.


<a id="cause-AeadRetirementStorageOverflow"></a>

### `AeadRetirementStorageOverflow`


Local detection/handling phase and implementation owner:

- `Storage::required_bytes` — `src/advanced/gcm/queued_input.rs`.
- `Storage::allocated_bytes` — `src/advanced/gcm/queued_input.rs`.


<a id="cause-AeadReturnedInputNotRetired"></a>

### `AeadReturnedInputNotRetired`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::input_submission` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.retired_fragment.is_some() || self.retired_output.is_some()`.
- `AeadMessageOperation::complete_input` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.retired_fragment.is_some() || self.retired_output.is_some()`.


<a id="cause-AeadReturnedStorageNotRetired"></a>

### `AeadReturnedStorageNotRetired`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::refuse_message` — `src/advanced/gcm/result.rs`. Enclosing true branch: `self.retired_fragment.is_some() || self.retired_output.is_some()`.


<a id="cause-AeadRowCountOverflow"></a>

### `AeadRowCountOverflow`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/gcm/submission.rs`.


<a id="cause-AeadSharedInitDescriptorMutation"></a>

### `AeadSharedInitDescriptorMutation`


Local detection/handling phase and implementation owner:

- `validate_binding_storage` (module-level helper) — `src/advanced/gcm/storage.rs`. Enclosing true branch: `mechanism.pParameter != params.pointer() || mechanism.ulParameterLen != params.size() || !params.unchanged( origin, declared_length, nonce.as_slice().as_ptr().cast_mut(), tag.as_slice().as_ptr().cast_mut(), )?`.


<a id="cause-AeadSnapshotInitIndex"></a>

### `AeadSnapshotInitIndex`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `*index >= self.frames.len()`.
- `PreparedSnapshot::copy_from` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `let ( InitBinding::Shared { nonce: prior_nonce, tag: prior_tag, prepared_message: prior_index, .. }, InitBinding::Shared { params, nonce, tag, prepared_message, .. }, ) = (&source.init, &mut self.body.init)`.


<a id="cause-AeadSnapshotAccounting"></a>

### `AeadSnapshotAccounting`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`.
- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`.
- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`.
- `bytes` (module-level helper) — `src/advanced/gcm/snapshot.rs`.
- `StorageMetadata::admit` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `Retention::Captured { owner, .. }`.
- `Storage::owner_bytes` — `src/advanced/gcm/snapshot.rs`.
- `Frame::snapshot_bytes` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing match alternative: `Self::Aead(frame)`.
- `Storage<'_>::allocated_bytes` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing match alternative: `Self::Aead { shape, buffers }`.


<a id="cause-AeadSnapshotAllocation"></a>

### `AeadSnapshotAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/advanced/gcm/snapshot.rs`.


<a id="cause-AeadSnapshotShapeChanged"></a>

### `AeadSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing true branch: `shape != planned`.
- `PreparedAead::restore_row` — `src/advanced/gcm/initialization.rs`.
- `PreparedAead::restore_row` — `src/advanced/gcm/initialization.rs`.
- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `self.frames.is_empty() || self.frames.len() != outputs.len()`.
- `AeadMessageOperation::describe_snapshot` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `self.frames.len() != outputs.len() || !metadata.descriptions.is_empty() || metadata.descriptions.capacity() < self.frames.len()`.
- `Shape::describe_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `requests.len() != self.rows || requests.kind() != self.kind || requests.decrypt() != self.decrypt`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `requests.len() != self.shape.rows`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `let Some(tag) = request.tag`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `offset != frame.inputs[0].as_slice().len()`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `frame.inputs.len() != request.parts.len()`.
- `PreparedSnapshot::copy_from` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `self.shape != source.snapshot_shape(entry)?`.
- `PreparedSnapshot::copy_from` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `target.inputs.len() != original.inputs.len()`.
- `copy_request` (module-level helper) — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `destination.as_slice().len() != source.len()`.
- `Shape::allocate` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `metadata.descriptions.len() != self.rows || metadata.layout.len() != self.rows`.
- `Storage::bind` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `Some((nonce, tag))`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.decrypt`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing false branch: `self.shape.route == MessageRoute::Single`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single && offset != frame.inputs[0].as_slice().len()`.


<a id="cause-AeadSnapshotTagShapeChanged"></a>

### `AeadSnapshotTagShapeChanged`


Local detection/handling phase and implementation owner:

- `PreparedSnapshot::copy_from` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadStorageAlreadyBound"></a>

### `AeadStorageAlreadyBound`


Local detection/handling phase and implementation owner:

- `StorageMetadata::admit` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `Retention::Admitted { .. }`.


<a id="cause-AeadStorageNotBound"></a>

### `AeadStorageNotBound`


Local detection/handling phase and implementation owner:

- `StorageMetadata::into_owner` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `Retention::Record`.


<a id="cause-AeadStorageOverflow"></a>

### `AeadStorageOverflow`


Local detection/handling phase and implementation owner:

- `start_shared_messages` (module-level helper) — `src/advanced/gcm/preparation.rs`.
- `PreparedSnapshot::fill_request` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `storage_sum` (module-level helper) — `src/advanced/gcm/storage.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.


<a id="cause-AeadStorageShapeChanged"></a>

### `AeadStorageShapeChanged`


Local detection/handling phase and implementation owner:

- `start_shared_messages` (module-level helper) — `src/advanced/gcm/preparation.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadStreamInitCapturePending"></a>

### `AeadStreamInitCapturePending`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::snapshot_shape` — `src/advanced/gcm/snapshot.rs`. Enclosing match alternative: `InitBinding::Shared { nonce, tag, prepared_message, .. }`.
- `PreparedSnapshot::copy_from` — `src/advanced/gcm/snapshot.rs`. Enclosing true branch: `let ( InitBinding::Shared { nonce: prior_nonce, tag: prior_tag, prepared_message: prior_index, .. }, InitBinding::Shared { params, nonce, tag, prepared_message, .. }, ) = (&source.init, &mut self.body.init)`.


<a id="cause-AeadStreamCheckpointBoundary"></a>

### `AeadStreamCheckpointBoundary`


Local detection/handling phase and implementation owner:

- `unavailable` (module-level helper) — `src/advanced/gcm/checkpoint.rs`.


<a id="cause-AeadStreamFragmentAbsent"></a>

### `AeadStreamFragmentAbsent`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::current_input_bytes` — `src/advanced/gcm/input.rs`.
- `AeadMessageOperation::input_submission` — `src/advanced/gcm/input.rs`.
- `AeadMessageOperation::terminal_input` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.input.is_some()`.


<a id="cause-AeadStreamIsNotAwaitingInput"></a>

### `AeadStreamIsNotAwaitingInput`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `!input.state.is_open() || input.state.retained_submission || input.fragment.is_some() || body.retired_fragment.is_some() || body.retired_output.is_some() || !matches!(body.outcome, AeadOutcome::Nominal) || !matches!(body.step, AeadStep::Ready | AeadStep::Receive(_))`.


<a id="cause-AeadStreamReconstruction"></a>

### `AeadStreamReconstruction`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/gcm/checkpoint/reconstruction.rs`.


<a id="cause-AeadStreamRefusalPhase"></a>

### `AeadStreamRefusalPhase`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::finish_step` — `src/advanced/gcm/completion.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadStreamRowShape"></a>

### `AeadStreamRowShape`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `body.frames.len() != outputs.entries.len()`.


<a id="cause-AeadStreamSnapshotShapeChanged"></a>

### `AeadStreamSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/gcm/checkpoint/capture.rs`.


<a id="cause-AeadSubmissionRoute"></a>

### `AeadSubmissionRoute`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `!matches`.


<a id="cause-AeadTableAllocation"></a>

### `AeadTableAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/advanced/gcm/submission/storage.rs`.


<a id="cause-AeadTableSizeOverflow"></a>

### `AeadTableSizeOverflow`


Local detection/handling phase and implementation owner:

- `vector_bytes` (module-level helper) — `src/advanced/gcm/submission/storage.rs`.
- `Tables::requested` — `src/advanced/gcm/submission/storage.rs`.


<a id="cause-AeadTicketAlreadyTransferred"></a>

### `AeadTicketAlreadyTransferred`


Local detection/handling phase and implementation owner:

- `park_locked` (module-level helper) — `src/advanced/gcm/ticket.rs`. Enclosing true branch: `body.observer != Observer::Ticket`.


<a id="cause-CcmMacLength"></a>

### `CcmMacLength`


Local detection/handling phase and implementation owner:

- `Selection::tag_bytes` — `src/advanced/aead_parameters.rs`. Enclosing match alternative: `Self::Ccm { .. }`.
- `RecordSelection<'a>::tag_bytes` — `src/advanced/aead_parameters.rs`. Enclosing match alternative: `CipherKind::Ccm`.
- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`. Enclosing true branch: `!matches!(mac_length, 4 | 6 | 8 | 10 | 12 | 14 | 16)`.


<a id="cause-CcmGeneratorAbiWidth"></a>

### `CcmGeneratorAbiWidth`


Local detection/handling phase and implementation owner:

- `Selection::generator` — `src/advanced/aead_parameters.rs`. Enclosing match alternative: `Self::Ccm { nonce, .. }`.
- `validate_ccm_fields` (module-level helper) — `src/symmetric/ccm.rs`.


<a id="cause-CcmRecordedMacAlignment"></a>

### `CcmRecordedMacAlignment`


Local detection/handling phase and implementation owner:

- `RecordSelection<'a>::new` — `src/advanced/aead_parameters.rs`. Enclosing true branch: `kind == CipherKind::Ccm && parameters.tag_bits % 8 != 0`.


<a id="cause-CcmRetainedSelectionAccounting"></a>

### `CcmRetainedSelectionAccounting`


Local detection/handling phase and implementation owner:

- `Session::ccm_message_buffers` — `src/advanced/ccm.rs`.
- `Session::classic_ccm` — `src/symmetric/ccm.rs`.


<a id="cause-MessageResultExceedsAdmittedCapacity"></a>

### `MessageResultExceedsAdmittedCapacity`


Local detection/handling phase and implementation owner:

- `complete_single_message` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing true branch: `length > bytes.capacity()`.


<a id="cause-MessageResultLengthOverflow"></a>

### `MessageResultLengthOverflow`


Local detection/handling phase and implementation owner:

- `complete_single_message` (module-level helper) — `src/advanced/gcm/completion.rs`.


<a id="cause-CallerFedAeadStreamRequired"></a>

### `CallerFedAeadStreamRequired`


Local detection/handling phase and implementation owner:

- `OperationTicket::aead_message_progress` — `src/advanced/gcm/stream_api.rs`.


<a id="cause-CheckpointGcmResultRange"></a>

### `CheckpointGcmResultRange`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`. Enclosing false branch: `recovery && state != MessageState::Finished`.


<a id="cause-CheckpointGeneratedNonceUnknown"></a>

### `CheckpointGeneratedNonceUnknown`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`. Enclosing false branch: `state == MessageState::Planned`.


<a id="cause-ConsumedAeadMessageTicket"></a>

### `ConsumedAeadMessageTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::aead_message_progress` — `src/advanced/gcm/stream_api.rs`. Enclosing true branch: `self.id == 0`.


<a id="cause-DeclaredGcmInitDescriptorMutation"></a>

### `DeclaredGcmInitDescriptorMutation`


Local detection/handling phase and implementation owner:

- `validate_binding_storage` (module-level helper) — `src/advanced/gcm/storage.rs`. Enclosing false branch: `kind == CipherKind::Gcm && declared.unchanged(mechanism)`.


<a id="cause-DeclaredGcmInitDispatch"></a>

### `DeclaredGcmInitDispatch`


Local detection/handling phase and implementation owner:

- `validate_binding_storage` (module-level helper) — `src/advanced/gcm/storage.rs`. Enclosing match alternative: `InitBinding::Declared(_)`.


<a id="cause-DeclaredGcmNativeKeyReference"></a>

### `DeclaredGcmNativeKeyReference`


Local detection/handling phase and implementation owner:

- `start_inner` (module-level helper) — `src/advanced/gcm/initialization.rs`. Enclosing true branch: `let Some((contract, _)) = declared`.


<a id="cause-DeclaredGcmResultOwnership"></a>

### `DeclaredGcmResultOwnership`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::result` — `src/advanced/gcm/result.rs`. Enclosing true branch: `matches!(self.init, InitBinding::Declared(_))`.


<a id="cause-DeclaredInitHasNoStandardSeed"></a>

### `DeclaredInitHasNoStandardSeed`


Local detection/handling phase and implementation owner:

- `InitBinding::reference` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `Self::Declared(_)`.


<a id="cause-DecryptionTagAbsent"></a>

### `DecryptionTagAbsent`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`. Enclosing true branch: `recovery`.


<a id="cause-DuplicateGcmCompletion"></a>

### `DuplicateGcmCompletion`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::advance_after_success` — `src/advanced/gcm/progression.rs`. Enclosing match alternative: `_`.


<a id="cause-EmptyAeadMessageSequence"></a>

### `EmptyAeadMessageSequence`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate_init` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.len() == 0`.
- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`.


<a id="cause-EmptyStreamAeadSequence"></a>

### `EmptyStreamAeadSequence`


Local detection/handling phase and implementation owner:

- `AdvancedSession::encrypt_stream_aead_messages` — `src/advanced/stream_aead.rs`.
- `AdvancedSession::decrypt_stream_aead_messages` — `src/advanced/stream_aead.rs`.


<a id="cause-FinishAeadMessageBeforeItsParent"></a>

### `FinishAeadMessageBeforeItsParent`


Local detection/handling phase and implementation owner:

- `finish` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `check_owner(&operation, session, ticket.id)?.step != AeadStep::Ready`.


<a id="cause-ForeignGcmMessageDeclaration"></a>

### `ForeignGcmMessageDeclaration`


Local detection/handling phase and implementation owner:

- `GcmMessageExtension::check` — `src/advanced/gcm/extension.rs`. Enclosing true branch: `!self.owner.ptr_eq(&Arc::downgrade(&session.inner))`.


<a id="cause-ForeignOrConsumedAeadStreamTicket"></a>

### `ForeignOrConsumedAeadStreamTicket`


Local detection/handling phase and implementation owner:

- `ticket_owner` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0`.


<a id="cause-ForeignOrConsumedAeadTicket"></a>

### `ForeignOrConsumedAeadTicket`


Local detection/handling phase and implementation owner:

- `Session::poll_aead` — `src/advanced/gcm/stream_api.rs`. Enclosing true branch: `!std::sync::Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0`.
- `park_locked` (module-level helper) — `src/advanced/gcm/ticket.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.


<a id="cause-MessageExtensionMechanismAbiWidth"></a>

### `MessageExtensionMechanismAbiWidth`


Local detection/handling phase and implementation owner:

- `Module::declare_gcm_message_extension` — `src/advanced/gcm/extension.rs`.


<a id="cause-MessageInterfaceUnavailable"></a>

### `MessageInterfaceUnavailable`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::drive_inner` — `src/advanced/gcm/progression.rs`.
- `check_message_key` (module-level helper) — `src/advanced/gcm/validation.rs`.
- `AdvancedSession::check_signature_functions` — `src/advanced/messages/api.rs`.
- `MacOperation::drive_inner` — `src/advanced/messages/progression.rs`.


<a id="cause-MixedAeadMessageMechanisms"></a>

### `MixedAeadMessageMechanisms`


Local detection/handling phase and implementation owner:

- `Scalars::compare` — `src/advanced/aead_parameters.rs`. Enclosing true branch: `self.kind != next.kind`.


<a id="cause-MixedAeadMessageSelections"></a>

### `MixedAeadMessageSelections`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate` — `src/advanced/gcm/input.rs`. Enclosing true branch: `request.nonce.kind() != self.kind()`.


<a id="cause-QueuedAeadCapacityCall"></a>

### `QueuedAeadCapacityCall`


Local detection/handling phase and implementation owner:

- `Pending::batch_record` — `src/advanced/gcm/output.rs`. Enclosing true branch: `!matches!(self.call, Call::Single(_) | Call::Next(_, _))`.


<a id="cause-ReconstructionAad"></a>

### `ReconstructionAad`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`.
- `RecordPlan<'a>::allocate` — `src/advanced/gcm/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`.


<a id="cause-ReconstructionGcmPhase"></a>

### `ReconstructionGcmPhase`


Local detection/handling phase and implementation owner:

- `PreparedAead::finish_record` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `"C_EncryptMessageNext" | "C_DecryptMessageNext"`.
- `PreparedAead::finish_record` — `src/advanced/gcm/initialization.rs`. Enclosing match alternative: `_`.


<a id="cause-ReconstructionMac"></a>

### `ReconstructionMac`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `decrypt`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.decrypt`.
- `RecordPlan<'a>::bind` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.decrypt`.


<a id="cause-ReconstructionNonceWidth"></a>

### `ReconstructionNonceWidth`


Local detection/handling phase and implementation owner:

- `PreparedAead::restore_row` — `src/advanced/gcm/initialization.rs`. Enclosing true branch: `nonce.len() != out.nonce.capacity()`.


<a id="cause-ReconstructionTag"></a>

### `ReconstructionTag`


Local detection/handling phase and implementation owner:

- `PreparedAead::restore_row` — `src/advanced/gcm/initialization.rs`.


<a id="cause-ReconstructionTagWidth"></a>

### `ReconstructionTagWidth`


Local detection/handling phase and implementation owner:

- `PreparedAead::restore_row` — `src/advanced/gcm/initialization.rs`. Enclosing true branch: `tag.len() != out.tag.capacity()`.


<a id="cause-RecordGcmInitLayoutChangedWithinSequence"></a>

### `RecordGcmInitLayoutChangedWithinSequence`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `message .params .message_init .unwrap_or(MessageInitLayout::InitWithoutParameters) != init`.


<a id="cause-RecoveryRequiresAeadMessageDecryption"></a>

### `RecoveryRequiresAeadMessageDecryption`


Local detection/handling phase and implementation owner:

- `AdvancedSession::capture_aead_recovery` — `src/advanced/recovery.rs`.
- `AeadMessageOperation::write_recovery_section` — `src/advanced/gcm/checkpoint.rs`. Enclosing true branch: `!self.decrypt`.
- `AeadMessageOperation::write_messages` — `src/advanced/gcm/checkpoint.rs`. Enclosing true branch: `recovery && !self.decrypt`.


<a id="cause-SingleAeadRequestCount"></a>

### `SingleAeadRequestCount`


Local detection/handling phase and implementation owner:

- `InputAccounting::validate` — `src/advanced/gcm/storage.rs`. Enclosing true branch: `requests.len() != 1`.


<a id="cause-SingleMessageResultCount"></a>

### `SingleMessageResultCount`


Local detection/handling phase and implementation owner:

- `complete_single_message` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing true branch: `outputs.entries.len() != 1`.


<a id="cause-StaleAeadMessageOwner"></a>

### `StaleAeadMessageOwner`


Local detection/handling phase and implementation owner:

- `Session::take_aead_message_ticket` — `src/advanced/gcm/ticket.rs`. Enclosing true branch: `!Arc::ptr_eq(&held, &state.operations.get(self.uid)?)`.


<a id="cause-StaleAeadStreamTicket"></a>

### `StaleAeadStreamTicket`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/gcm/submission.rs`. Enclosing true branch: `operation.id != id`.


<a id="cause-StaleAeadTicket"></a>

### `StaleAeadTicket`


Local detection/handling phase and implementation owner:

- `park_locked` (module-level helper) — `src/advanced/gcm/ticket.rs`. Enclosing true branch: `operation.id != ticket.id`.


<a id="cause-StreamAeadMessageinitHasNoParameters"></a>

### `StreamAeadMessageinitHasNoParameters`


Local detection/handling phase and implementation owner:

- `Requests<'_>::validate_init` — `src/advanced/gcm/input.rs`. Enclosing true branch: `self.kind().stream() && layout != MessageInitLayout::InitWithoutParameters`.
- `RecordPlan<'a>::new` — `src/advanced/gcm/snapshot/record_plan.rs`. Enclosing true branch: `kind.stream() && init != MessageInitLayout::InitWithoutParameters`.


<a id="cause-StreamAeadInitialNonceAbsent"></a>

### `StreamAeadInitialNonceAbsent`


Local detection/handling phase and implementation owner:

- `RecordSelection<'a>::new` — `src/advanced/aead_parameters.rs`. Enclosing true branch: `kind.stream()`.


<a id="cause-StreamAeadRecordScalarSelection"></a>

### `StreamAeadRecordScalarSelection`


Local detection/handling phase and implementation owner:

- `RecordSelection<'a>::new` — `src/advanced/aead_parameters.rs`. Enclosing true branch: `kind.stream() && (parameters.tag_bits != 128 || parameters.iv_generator != Some(0) || parameters.iv_fixed_bits != Some(0))`.


<a id="cause-SynchronousMessageFacadeRequiresSynchronousSession"></a>

### `SynchronousMessageFacadeRequiresSynchronousSession`


Local detection/handling phase and implementation owner:

- `complete_single_message` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.


<a id="cause-SynchronousMessageSequenceDidNotComplete"></a>

### `SynchronousMessageSequenceDidNotComplete`


Local detection/handling phase and implementation owner:

- `complete_single_message` (module-level helper) — `src/advanced/gcm/completion.rs`. Enclosing match alternative: `_`.


<a id="cause-UnexpectedRestorationAuthenticationKey"></a>

### `UnexpectedRestorationAuthenticationKey`


Local detection/handling phase and implementation owner:

- `AeadMessageOperation::restore_keys` — `src/advanced/gcm/rejoin.rs`. Enclosing true branch: `keys.authentication.is_some()`.


<a id="cause-ValidationReportLength"></a>

### `ValidationReportLength`


Local detection/handling phase and implementation owner:

- `Capture::allocation_bytes` — `src/advanced/validation.rs`.
- `Capture::restore_record` — `src/advanced/validation.rs`. Enclosing true branch: `report.observations.len() == self.maximum`.
- `start_shared_messages` (module-level helper) — `src/advanced/gcm/preparation.rs`.
- `AdvancedSession::prepare_signatures` — `src/advanced/messages/api.rs`.
- `ReportStorage::allocation_bytes` — `src/advanced/validation/report_storage.rs`.

