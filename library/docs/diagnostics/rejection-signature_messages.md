Cause contracts for `SignatureMessagesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-MacTagSize"></a>

### `MacTagSize`


Local detection/handling phase and implementation owner:

- `MacOperation::record_parameters` — `src/advanced/messages/stream_capture.rs`. Enclosing match alternative: `None`.


<a id="cause-PssCheckpointParameterIdentity"></a>

### `PssCheckpointParameterIdentity`


Local detection/handling phase and implementation owner:

- `MacOperation::checkpoint_header` — `src/advanced/messages/operation.rs`. Enclosing true branch: `self .pss .as_ref() .is_some_and(|p| !p.unchanged().unwrap_or(false))`.


<a id="cause-PssMessageMechanismMismatch"></a>

### `PssMessageMechanismMismatch`


Local detection/handling phase and implementation owner:

- `Shape::for_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `selection.mechanism(crate::HashExecution::Pkcs11Combined)? != kind`.
- `Storage::bind` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `parameters .selection .mechanism(crate::HashExecution::Pkcs11Combined)? != shape.kind`.
- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `selection.mechanism(crate::HashExecution::Pkcs11Combined)? != kind`.


<a id="cause-PssNativeParameterIdentity"></a>

### `PssNativeParameterIdentity`


Local detection/handling phase and implementation owner:

- `MacOperation::finish_step` — `src/advanced/messages/progression.rs`. Enclosing true branch: `self.mechanism.mechanism != pss .selection .mechanism(crate::HashExecution::Pkcs11Combined)? || self.mechanism.pParameter != (&mut **pss as *mut CK_RSA_PKCS_PSS_PARAMS).cast() || self.mechanism.ulParameterLen != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG || !pss.unchanged()?`.


<a id="cause-PssSnapshotParameterIdentity"></a>

### `PssSnapshotParameterIdentity`


Local detection/handling phase and implementation owner:

- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self .pss .as_ref() .is_some_and(|p| !p.unchanged().unwrap_or(false))`.


<a id="cause-BufferedMessageHasStreamFragment"></a>

### `BufferedMessageHasStreamFragment`


Local detection/handling phase and implementation owner:

- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.stream_fragment.is_some()`.


<a id="cause-ConsumedMessageTicket"></a>

### `ConsumedMessageTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::message_signature_progress` — `src/advanced/messages.rs`. Enclosing true branch: `self.id == 0`.


<a id="cause-CurrentMessageFragmentAbsent"></a>

### `CurrentMessageFragmentAbsent`


Local detection/handling phase and implementation owner:

- `MacOperation::current_input_bytes` — `src/advanced/messages/operation.rs`. Enclosing match alternative: `MessageStep::Single(_) | MessageStep::StreamUpdate(_) | MessageStep::StreamLast(_)`.


<a id="cause-DuplicateMessageCompletion"></a>

### `DuplicateMessageCompletion`


Local detection/handling phase and implementation owner:

- `MacOperation::finish_step` — `src/advanced/messages/progression.rs`. Enclosing match alternative: `_`.


<a id="cause-FinishTheCurrentMessageBeforeTheParentProcess"></a>

### `FinishTheCurrentMessageBeforeTheParentProcess`


Local detection/handling phase and implementation owner:

- `finish` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `body.step != MessageStep::Ready`.
- `finish` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `!matches!(body.phase, Phase::Ready)`.


<a id="cause-ForeignOperationLeaseAdmission"></a>

### `ForeignOperationLeaseAdmission`


Local detection/handling phase and implementation owner:

- `PreparedDestination::prepare_binding` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `!admission.access().owns_session(session)`.
- `AdvancedSession::install_signatures` — `src/advanced/messages/api.rs`. Enclosing true branch: `!s.owns_session(&self.session)`.


<a id="cause-ForeignOrConsumedMessageSignatureTicket"></a>

### `ForeignOrConsumedMessageSignatureTicket`


Local detection/handling phase and implementation owner:

- `ticket_owner` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0`.


<a id="cause-MessageHmacKeyRequired"></a>

### `MessageHmacKeyRequired`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_mac_messages` — `src/advanced/messages/api.rs`.
- `AdvancedSession::begin_mac_message_stream` — `src/advanced/messages/stream_api.rs`.


<a id="cause-MessageAllocation"></a>

### `MessageAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/advanced/messages/snapshot.rs`.


<a id="cause-MessageAlreadyPublished"></a>

### `MessageAlreadyPublished`


Local detection/handling phase and implementation owner:

- `MacOperation::result` — `src/advanced/messages/operation.rs`. Enclosing true branch: `self.verify && self .signatures .as_ref() .is_some_and(|results| results.rejections.iter().any(Option::is_some))`.
- `MacOperation::result` — `src/advanced/messages/operation.rs`. Enclosing false branch: `self.verify`.


<a id="cause-MessageAsynchronousResultIdentity"></a>

### `MessageAsynchronousResultIdentity`


Local detection/handling phase and implementation owner:

- `MacOperation::drive_inner` — `src/advanced/messages/progression.rs`. Enclosing true branch: `self.completion.ulVersion != 0 || self.completion.pValue != pointer || rv == CKR_OK && self.completion.ulValue as u128 > self.signature_capacity(index)? as u128`.
- `MacOperation::drive_inner` — `src/advanced/messages/progression.rs`. Enclosing true branch: `self.completion.ulVersion != 0 || self.completion.pValue != pointer || self.completion.ulValue as u128 > self.signature_capacity(i)? as u128`.


<a id="cause-MessageByteOverflow"></a>

### `MessageByteOverflow`


Local detection/handling phase and implementation owner:

- `validate_messages` (module-level helper) — `src/advanced/messages.rs`.
- `validate_messages` (module-level helper) — `src/advanced/messages.rs`. Enclosing true branch: `let Some(expected) = expected`.
- `MacStorage::for_messages` — `src/advanced/messages.rs`.
- `MacStorage::for_messages` — `src/advanced/messages.rs`.
- `MacStorage::with_buffer_bytes` — `src/advanced/messages.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.
- `Shape::allocate_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.route == MessageRoute::Single`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `RecordPlan<'a>::allocate` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.


<a id="cause-MessageCount"></a>

### `MessageCount`


Local detection/handling phase and implementation owner:

- `validate_messages` (module-level helper) — `src/advanced/messages.rs`. Enclosing true branch: `messages.is_empty() || messages.len() > limits.maximum_parts`.
- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `messages.stream().is_none() && (messages.len() == 0 || messages.len() > ceilings.maximum_parts)`.
- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing false branch: `let Some(stream) = messages.stream()`.


<a id="cause-MessageFailedExplicitCleanupRequired"></a>

### `MessageFailedExplicitCleanupRequired`


Local detection/handling phase and implementation owner:

- `MacOperation::drive_inner` — `src/advanced/messages/progression.rs`. Enclosing true branch: `self.step == MessageStep::Failed`.


<a id="cause-MessageFunctionsUnavailable"></a>

### `MessageFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `AdvancedSession::check_signature_functions` — `src/advanced/messages/api.rs`. Enclosing true branch: `!available`.
- `Call::resolve` — `src/advanced/messages/resolved_call.rs`.


<a id="cause-MessageInputCeiling"></a>

### `MessageInputCeiling`


Local detection/handling phase and implementation owner:

- `validate_messages` (module-level helper) — `src/advanced/messages.rs`. Enclosing true branch: `parts > limits.maximum_parts || bytes > limits.maximum_total_bytes`.
- `submit` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `input_bytes .checked_add(expected.len()) .filter(|total| *total <= limits.maximum_total_bytes) .is_none()`.
- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `requested_parts > ceilings.maximum_parts || input_bytes > ceilings.maximum_total_bytes`.


<a id="cause-MessageInputStorageOverflow"></a>

### `MessageInputStorageOverflow`


Local detection/handling phase and implementation owner:

- `sum` (module-level helper) — `src/advanced/messages/input/storage.rs`.


<a id="cause-MessageMetadataOverflow"></a>

### `MessageMetadataOverflow`


Local detection/handling phase and implementation owner:

- `MacStorage::with_buffer_bytes` — `src/advanced/messages.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.


<a id="cause-MessageNativeLengthWidth"></a>

### `MessageNativeLengthWidth`


Local detection/handling phase and implementation owner:

- `MacOperation::finish_step` — `src/advanced/messages/progression.rs`. Enclosing true branch: `let Some(message) = terminal`.
- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing match alternative: `Err(_)`.


<a id="cause-MessageNativeParameterIdentity"></a>

### `MessageNativeParameterIdentity`


Local detection/handling phase and implementation owner:

- `MacOperation::finish_step` — `src/advanced/messages/progression.rs`. Enclosing true branch: `self.mechanism.mechanism != self.kind || self.pss.is_none() && (!self.mechanism.pParameter.is_null() || self.mechanism.ulParameterLen != 0)`.


<a id="cause-MessageNotActive"></a>

### `MessageNotActive`


Local detection/handling phase and implementation owner:

- `MacOperation::function` — `src/advanced/messages/operation.rs`. Enclosing match alternative: `_`.
- `Call::resolve` — `src/advanced/messages/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-MessageNotCapturable"></a>

### `MessageNotCapturable`


Local detection/handling phase and implementation owner:

- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.pending() || self.outcome.closing() || !self.outcome.valid() && !self.input.incremental || matches!( self.step, MessageStep::Init | MessageStep::Done | MessageStep::Failed )`.


<a id="cause-MessageNotComplete"></a>

### `MessageNotComplete`


Local detection/handling phase and implementation owner:

- `MacOperation::result` — `src/advanced/messages/operation.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-MessageOperationNotJoinable"></a>

### `MessageOperationNotJoinable`


Local detection/handling phase and implementation owner:

- `MacOperation::joined_capacity` — `src/advanced/messages/operation.rs`. Enclosing true branch: `!self.pending()`.


<a id="cause-MessageOperationStorageSize"></a>

### `MessageOperationStorageSize`


Local detection/handling phase and implementation owner:

- `AdvancedSession::prepare_signatures` — `src/advanced/messages/api.rs`.
- `AdvancedSession::prepare_signatures` — `src/advanced/messages/api.rs`.


<a id="cause-MessageOutputCallAbsent"></a>

### `MessageOutputCallAbsent`


Local detection/handling phase and implementation owner:

- `Pending::new` — `src/advanced/messages/output.rs`. Enclosing match alternative: `_`.


<a id="cause-MessagePartOverflow"></a>

### `MessagePartOverflow`


Local detection/handling phase and implementation owner:

- `validate_messages` (module-level helper) — `src/advanced/messages.rs`.
- `MacStorage::for_messages` — `src/advanced/messages.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.
- `Shape::for_request` — `src/advanced/messages/snapshot.rs`.
- `Shape::for_request` — `src/advanced/messages/snapshot.rs`.
- `Shape::for_request` — `src/advanced/messages/snapshot.rs`.


<a id="cause-MessagePreparedOutputWidth"></a>

### `MessagePreparedOutputWidth`


Local detection/handling phase and implementation owner:

- `MacOperation::attach_output` — `src/advanced/messages/output.rs`. Enclosing true branch: `output.capacity() != capacity`.


<a id="cause-MessageReportCountOverflow"></a>

### `MessageReportCountOverflow`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `submission.starts_message()`.


<a id="cause-MessageResultMetadata"></a>

### `MessageResultMetadata`


Local detection/handling phase and implementation owner:

- `MacStorage::with_buffer_bytes` — `src/advanced/messages.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.


<a id="cause-MessageResultWithheldAfterFailure"></a>

### `MessageResultWithheldAfterFailure`


Local detection/handling phase and implementation owner:

- `MacOperation::result` — `src/advanced/messages/operation.rs`. Enclosing true branch: `self.outcome.closing()`.


<a id="cause-MessageResultsAbsent"></a>

### `MessageResultsAbsent`


Local detection/handling phase and implementation owner:

- `MacOperation::write_terminal_messages` — `src/advanced/messages/operation.rs`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`.
- `MacOperation::describe_snapshot` — `src/advanced/messages/snapshot.rs`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `let Some(expected) = expected`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`.


<a id="cause-MessageRowCountOverflow"></a>

### `MessageRowCountOverflow`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/messages/input.rs`.


<a id="cause-MessageSignatureCount"></a>

### `MessageSignatureCount`


Local detection/handling phase and implementation owner:

- `validate_messages` (module-level helper) — `src/advanced/messages.rs`. Enclosing true branch: `expected.is_some_and(|e| e.len() != messages.len())`.
- `MacStorage::for_messages` — `src/advanced/messages.rs`. Enclosing true branch: `expected.is_some_and(|values| values.len() != messages.len())`.


<a id="cause-MessageSignatureIsNotWaitingForStorage"></a>

### `MessageSignatureIsNotWaitingForStorage`


Local detection/handling phase and implementation owner:

- `MacOperation::output_preparation` — `src/advanced/messages/output.rs`.


<a id="cause-MessageSignatureStorageAbsent"></a>

### `MessageSignatureStorageAbsent`


Local detection/handling phase and implementation owner:

- `MacOperation::signature_capacity` — `src/advanced/messages/operation.rs`.
- `MacOperation::attach_output` — `src/advanced/messages/output.rs`.


<a id="cause-MessageSignatureStreamIsNotAwaitingInput"></a>

### `MessageSignatureStreamIsNotAwaitingInput`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `!body.input.incremental || !body.input.is_open() || body.outcome.closing() || body.stream_fragment.is_some() || !body.released.is_empty() || body.input.retained_submission || !matches!(body.step, MessageStep::Ready | MessageStep::Receive(_))`.


<a id="cause-MessageSignatureStreamRowShape"></a>

### `MessageSignatureStreamRowShape`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `body.inputs.len() != body.layouts.len() || body.inputs.len() != outputs.len() || body.inputs.len() != body.lengths.len()`.


<a id="cause-MessageSignatureSubmissionRoute"></a>

### `MessageSignatureSubmissionRoute`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `!matches || submission.terminal() && body.verify != submission.expected().is_some()`.


<a id="cause-MessageSignatureTicketRequired"></a>

### `MessageSignatureTicketRequired`


Local detection/handling phase and implementation owner:

- `OperationTicket::message_signature_progress` — `src/advanced/messages.rs`. Enclosing match alternative: `_`.
- `check_owner` (module-level helper) — `src/advanced/messages/input.rs`.


<a id="cause-MessageSignaturesAlreadyPublished"></a>

### `MessageSignaturesAlreadyPublished`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/messages/input.rs`.


<a id="cause-MessageSnapshotAccounting"></a>

### `MessageSnapshotAccounting`


Local detection/handling phase and implementation owner:

- `Shape::request_bytes` — `src/advanced/messages/snapshot.rs`.
- `Shape::allocation_bytes` — `src/advanced/messages/snapshot.rs`.
- `Shape::temporary_bytes` — `src/advanced/messages/snapshot.rs`.
- `sum` (module-level helper) — `src/advanced/messages/snapshot.rs`.
- `vector_bytes` (module-level helper) — `src/advanced/messages/snapshot.rs`.
- `Storage::metadata_bytes` — `src/advanced/messages/snapshot.rs`.


<a id="cause-MessageSnapshotRowCount"></a>

### `MessageSnapshotRowCount`


Local detection/handling phase and implementation owner:

- `Storage::allocate` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `layout.len() != shape.rows`.


<a id="cause-MessageStreamActiveRowAbsent"></a>

### `MessageStreamActiveRowAbsent`


Local detection/handling phase and implementation owner:

- `MacOperation::write_stream_messages` — `src/advanced/messages/stream_capture.rs`.


<a id="cause-MessageStreamCapturePhase"></a>

### `MessageStreamCapturePhase`


Local detection/handling phase and implementation owner:

- `MacOperation::stream_boundary` — `src/advanced/messages/stream_capture.rs`. Enclosing match alternative: `_`.


<a id="cause-MessageStreamCaptureShape"></a>

### `MessageStreamCaptureShape`


Local detection/handling phase and implementation owner:

- `MacOperation::write_stream_messages` — `src/advanced/messages/stream_capture.rs`.


<a id="cause-MessageStreamFragmentAbsent"></a>

### `MessageStreamFragmentAbsent`


Local detection/handling phase and implementation owner:

- `MacOperation::write_stream_messages` — `src/advanced/messages/stream_capture.rs`. Enclosing true branch: `!finished && boundary.has_fragment()`.


<a id="cause-MessageStreamReconstructionFragment"></a>

### `MessageStreamReconstructionFragment`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `streaming`.


<a id="cause-MessageStreamReconstructionSize"></a>

### `MessageStreamReconstructionSize`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `target.as_slice().len() != part.len()`.


<a id="cause-MessageStreamRepeatedFragment"></a>

### `MessageStreamRepeatedFragment`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `fragment.replace(size).is_some()`.


<a id="cause-MessageStreamResultsAbsent"></a>

### `MessageStreamResultsAbsent`


Local detection/handling phase and implementation owner:

- `MacOperation::write_stream_messages` — `src/advanced/messages/stream_capture.rs`.


<a id="cause-MessageStreamSnapshotFragment"></a>

### `MessageStreamSnapshotFragment`


Local detection/handling phase and implementation owner:

- `PreparedSnapshot::copy_from` — `src/advanced/messages/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-MessageStreamSnapshotRow"></a>

### `MessageStreamSnapshotRow`


Local detection/handling phase and implementation owner:

- `MacOperation::describe_snapshot` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `!inputs.is_empty() || !fragments.lengths().is_empty()`.


<a id="cause-MessageStreamSnapshotShape"></a>

### `MessageStreamSnapshotShape`


Local detection/handling phase and implementation owner:

- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `expected != self.stream_fragment.as_ref().map(Buffer::capacity) || self.inputs.iter().any(|row| !row.is_empty()) || self.layouts.iter().any(|row| !row.lengths().is_empty())`.


<a id="cause-MessageVectorAllocation"></a>

### `MessageVectorAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/advanced/messages/input/storage.rs`.


<a id="cause-MessageVectorStorageOverflow"></a>

### `MessageVectorStorageOverflow`


Local detection/handling phase and implementation owner:

- `vector_bytes` (module-level helper) — `src/advanced/messages/input/storage.rs`.
- `Tables::requested_bytes` — `src/advanced/messages/input/storage.rs`.


<a id="cause-ReconstructionExpectedSignature"></a>

### `ReconstructionExpectedSignature`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing false branch: `streaming`.
- `RecordPlan<'a>::allocate` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing false branch: `streaming`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing false branch: `streaming`.


<a id="cause-ReconstructionMechanismWidth"></a>

### `ReconstructionMechanismWidth`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/messages/snapshot/record_plan.rs`.


<a id="cause-ReconstructionSignaturePhase"></a>

### `ReconstructionSignaturePhase`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing match alternative: `"C_SignMessageNext" | "C_VerifyMessageNext"`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordPssMgfAbsent"></a>

### `RecordPssMgfAbsent`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordPssMgfWidth"></a>

### `RecordPssMgfWidth`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordPssHashAbsent"></a>

### `RecordPssHashAbsent`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordPssHashWidth"></a>

### `RecordPssHashWidth`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordPssMessagesAbsent"></a>

### `RecordPssMessagesAbsent`


Local detection/handling phase and implementation owner:

- `record_selection` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordPssParameters"></a>

### `RecordPssParameters`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`. Enclosing true branch: `selected.mechanism(crate::HashExecution::Pkcs11Combined)? as u64 != descriptor.mechanism || descriptor.profile == profile::RSA_PSS_SHA256 && selected != super::pss_profile()`.


<a id="cause-RecordPssProfile"></a>

### `RecordPssProfile`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`. Enclosing true branch: `!matches!( descriptor.profile, profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED )`.


<a id="cause-RecordPssSaltAbsent"></a>

### `RecordPssSaltAbsent`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordPssSaltWidth"></a>

### `RecordPssSaltWidth`


Local detection/handling phase and implementation owner:

- `record_parameters` (module-level helper) — `src/advanced/messages/pss.rs`.


<a id="cause-RecordMixedPssParameters"></a>

### `RecordMixedPssParameters`


Local detection/handling phase and implementation owner:

- `record_selection` (module-level helper) — `src/advanced/messages/pss.rs`. Enclosing true branch: `selected.is_some_and(|prior| prior != current)`.


<a id="cause-RestorationAuthenticationKeyRequired"></a>

### `RestorationAuthenticationKeyRequired`


Local detection/handling phase and implementation owner:

- `MacOperation::restore_keys` — `src/advanced/messages/operation.rs`.


<a id="cause-RestoreRsaReferenceRole"></a>

### `RestoreRsaReferenceRole`


Local detection/handling phase and implementation owner:

- `MacOperation::restore_keys` — `src/advanced/messages/operation.rs`. Enclosing match alternative: `_`.


<a id="cause-RestoreRsaSize"></a>

### `RestoreRsaSize`


Local detection/handling phase and implementation owner:

- `MacOperation::restore_keys` — `src/advanced/messages/operation.rs`. Enclosing true branch: `(bits / 8 + usize::from(bits % 8 != 0)) != self.size`.


<a id="cause-SignatureCheckpointShape"></a>

### `SignatureCheckpointShape`


Local detection/handling phase and implementation owner:

- `MacOperation::write_terminal_messages` — `src/advanced/messages/operation.rs`. Enclosing true branch: `self.inputs.len() != self.layouts.len() || outputs.len() != self.inputs.len()`.


<a id="cause-SignatureCheckpointUnavailable"></a>

### `SignatureCheckpointUnavailable`


Local detection/handling phase and implementation owner:

- `MacOperation::write_terminal_messages` — `src/advanced/messages/operation.rs`. Enclosing true branch: `self.pending() || self.outcome.closing() || !self.outcome.valid() && !self.input.incremental && processed.is_none() || self.step == MessageStep::Failed`.


<a id="cause-StaleMessageSignatureTicket"></a>

### `StaleMessageSignatureTicket`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/messages/input.rs`. Enclosing true branch: `operation.id != id`.


<a id="cause-StaleMessageTicket"></a>

### `StaleMessageTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::message_signature_progress` — `src/advanced/messages.rs`. Enclosing true branch: `operation.id != self.id`.


<a id="cause-StreamPhaseOnBufferedMessage"></a>

### `StreamPhaseOnBufferedMessage`


Local detection/handling phase and implementation owner:

- `MacOperation::current_input_bytes` — `src/advanced/messages/operation.rs`. Enclosing match alternative: `MessageStep::StreamUpdate(_) | MessageStep::StreamLast(_)`.


<a id="cause-UnexpectedRestorationEncryptionKey"></a>

### `UnexpectedRestorationEncryptionKey`


Local detection/handling phase and implementation owner:

- `MacOperation::restore_keys` — `src/advanced/messages/operation.rs`. Enclosing true branch: `keys.encryption.is_some()`.
