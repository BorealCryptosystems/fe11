Cause contracts for `MessageRecordRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AeadInitSeed"></a>

### `AeadInitSeed`


Local detection/handling phase and implementation owner:

- `Initial<'a>::read` — `src/advanced/record/aead_messages.rs`. Enclosing match alternative: `1`.


<a id="cause-AeadBatchOutputContinuation"></a>

### `AeadBatchOutputContinuation`


Local detection/handling phase and implementation owner:

- `State<'a>::read` — `src/advanced/record/aead_batch.rs`.


<a id="cause-AeadBatchOutputPrepared"></a>

### `AeadBatchOutputPrepared`


Local detection/handling phase and implementation owner:

- `State<'a>::read` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `reader.boolean(crate::RejectionReason::MessageRecord( crate::MessageRecordRejection::AeadBatchOutputContinuation, ))?`.


<a id="cause-AeadBatchRecordAssociation"></a>

### `AeadBatchRecordAssociation`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `!matches!( descriptor.family, Family::MessageEncrypt | Family::MessageDecrypt ) || messages.stream().is_some() || messages.output().is_some()`.


<a id="cause-AeadCapacityContinuationAssociation"></a>

### `AeadCapacityContinuationAssociation`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `detached || output.request.code != fe11_sys::CKR_BUFFER_TOO_SMALL as u64 || output.request.function != descriptor.phase.name()`.


<a id="cause-AeadCapacityContinuationPhase"></a>

### `AeadCapacityContinuationPhase`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `!valid_call || !output.prepared && remaining != output.request.previous_capacity`.


<a id="cause-AeadCapacityPrefixExceedsStorage"></a>

### `AeadCapacityPrefixExceedsStorage`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`.


<a id="cause-AeadCapacityRowAbsent"></a>

### `AeadCapacityRowAbsent`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`.


<a id="cause-AeadDeclaredInputAbsent"></a>

### `AeadDeclaredInputAbsent`


Local detection/handling phase and implementation owner:

- `State<'a>::row_layout` — `src/advanced/record/aead_batch.rs`.


<a id="cause-AeadDeclaredInputIndex"></a>

### `AeadDeclaredInputIndex`


Local detection/handling phase and implementation owner:

- `State<'a>::row_layout` — `src/advanced/record/aead_batch.rs`.
- `State<'a>::row_layout` — `src/advanced/record/aead_batch.rs`.


<a id="cause-AeadDeclaredInputRowCount"></a>

### `AeadDeclaredInputRowCount`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `self .declared .is_some_and(|bytes| bytes.len() / 8 != messages.len() || bytes.len() % 8 != 0)`.


<a id="cause-AeadDeclaredInputWidth"></a>

### `AeadDeclaredInputWidth`


Local detection/handling phase and implementation owner:

- `State<'a>::read` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `lengths`.
- `State<'a>::row_layout` — `src/advanced/record/aead_batch.rs`.
- `State<'a>::row_layout` — `src/advanced/record/aead_batch.rs`.


<a id="cause-AeadDeclaredRetainedInputAssociation"></a>

### `AeadDeclaredRetainedInputAssociation`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `retained > declared || (row.state == MessageState::Planned || descriptor.family == Family::MessageDecrypt && row.state == MessageState::Engaged) && retained != declared || row.state == MessageState::Finished && retained != 0`.


<a id="cause-AeadPreparedOutput"></a>

### `AeadPreparedOutput`


Local detection/handling phase and implementation owner:

- `Boundary::read` — `src/advanced/record/aead_messages.rs`. Enclosing match alternative: `4`.


<a id="cause-AeadPreviousOutputWidth"></a>

### `AeadPreviousOutputWidth`


Local detection/handling phase and implementation owner:

- `State<'a>::read` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `reader.boolean(crate::RejectionReason::MessageRecord( crate::MessageRecordRejection::AeadBatchOutputContinuation, ))?`.


<a id="cause-AeadRequiredOutputWidth"></a>

### `AeadRequiredOutputWidth`


Local detection/handling phase and implementation owner:

- `State<'a>::read` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `reader.boolean(crate::RejectionReason::MessageRecord( crate::MessageRecordRejection::AeadBatchOutputContinuation, ))?`.


<a id="cause-AeadRetainedInputOverflow"></a>

### `AeadRetainedInputOverflow`


Local detection/handling phase and implementation owner:

- `State<'a>::validate` — `src/advanced/record/aead_batch.rs`. Enclosing true branch: `let Some(declared) = self.row_layout(index)?.declared_input`.


<a id="cause-AeadStreamArchiveRepresentation"></a>

### `AeadStreamArchiveRepresentation`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/record/aead_messages.rs`.


<a id="cause-CipherExtensionParameters"></a>

### `CipherExtensionParameters`


Local detection/handling phase and implementation owner:

- `Parameters<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-DigestExtensionParameters"></a>

### `DigestExtensionParameters`


Local detection/handling phase and implementation owner:

- `Parameters<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-DigestOutputStorage"></a>

### `DigestOutputStorage`


Local detection/handling phase and implementation owner:

- `Parameters<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-GenericMessageBeginPresence"></a>

### `GenericMessageBeginPresence`


Local detection/handling phase and implementation owner:

- `Row<'a>::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageArchiveRepresentation"></a>

### `GenericMessageArchiveRepresentation`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageBodyOnAnotherFamily"></a>

### `GenericMessageBodyOnAnotherFamily`


Local detection/handling phase and implementation owner:

- `MessageIter<'a>::next` — `src/advanced/record/messages.rs`. Enclosing match alternative: `Self::WrongFamily`.


<a id="cause-GenericMessageCapacityPrepared"></a>

### `GenericMessageCapacityPrepared`


Local detection/handling phase and implementation owner:

- `Boundary<'a>::read` — `src/advanced/record/native_messages.rs`. Enclosing match alternative: `4`.


<a id="cause-GenericMessageDeclarationPresence"></a>

### `GenericMessageDeclarationPresence`


Local detection/handling phase and implementation owner:

- `Parameter<'a>::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageImportDeclarationMismatch"></a>

### `GenericMessageImportDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `Declaration::resolve` — `src/advanced/record/native_messages.rs`. Enclosing true branch: `contract.mechanism_number() != self.mechanism || contract.constants_edition() != self.edition || contract.mutates_key() != self.mutates_key`.


<a id="cause-GenericMessageInvalidVerdict"></a>

### `GenericMessageInvalidVerdict`


Local detection/handling phase and implementation owner:

- `Header<'a>::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageKeyEffect"></a>

### `GenericMessageKeyEffect`


Local detection/handling phase and implementation owner:

- `Declaration::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageLayoutProvenance"></a>

### `GenericMessageLayoutProvenance`


Local detection/handling phase and implementation owner:

- `Declaration::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageRefusal"></a>

### `GenericMessageRefusal`


Local detection/handling phase and implementation owner:

- `Row<'a>::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-GenericMessageWriterDeclaration"></a>

### `GenericMessageWriterDeclaration`


Local detection/handling phase and implementation owner:

- `Header<'a>::read` — `src/advanced/record/native_messages.rs`.


<a id="cause-ImportRequiresADestinationAbiDeclaration"></a>

### `ImportRequiresADestinationAbiDeclaration`


Local detection/handling phase and implementation owner:

- `Declaration::resolve` — `src/advanced/record/native_messages.rs`. Enclosing true branch: `callable || self.caller_asserted`.
- `Destination<'a>::imported` — `src/advanced/signature/binding.rs`. Enclosing true branch: `parameters.caller_asserted || descriptor.mechanism == fe11_sys::CKM_SHA512_T_HMAC_GENERAL as u64`.


<a id="cause-ImportedCallableGraphRequiresAnAssertedAbi"></a>

### `ImportedCallableGraphRequiresAnAssertedAbi`


Local detection/handling phase and implementation owner:

- `Declaration::resolve` — `src/advanced/record/native_messages.rs`. Enclosing true branch: `callable && supplied.provenance() != MechanismLayoutProvenance::CallerAssertedLayout`.


<a id="cause-MessageOutputContinuation"></a>

### `MessageOutputContinuation`


Local detection/handling phase and implementation owner:

- `Messages<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-MessageOutputContinuationAssociation"></a>

### `MessageOutputContinuationAssociation`


Local detection/handling phase and implementation owner:

- `MessageOutput::validate` — `src/advanced/record/message_output.rs`. Enclosing true branch: `detached || descriptor.family != Family::MessageSign || self.request.code != fe11_sys::CKR_BUFFER_TOO_SMALL as u64 || self.request.function != descriptor.phase.name()`.


<a id="cause-MessageOutputContinuationPhase"></a>

### `MessageOutputContinuationPhase`


Local detection/handling phase and implementation owner:

- `MessageOutput::validate` — `src/advanced/record/message_output.rs`. Enclosing true branch: `!terminal || message.produced != 0 || !self.prepared && message.expected != 0`.


<a id="cause-MessageOutputContinuationRowAbsent"></a>

### `MessageOutputContinuationRowAbsent`


Local detection/handling phase and implementation owner:

- `MessageOutput::validate` — `src/advanced/record/message_output.rs`.


<a id="cause-MessageOutputPrepared"></a>

### `MessageOutputPrepared`


Local detection/handling phase and implementation owner:

- `MessageOutput::read` — `src/advanced/record/message_output.rs`.


<a id="cause-MessagePreviousOutputWidth"></a>

### `MessagePreviousOutputWidth`


Local detection/handling phase and implementation owner:

- `MessageOutput::read` — `src/advanced/record/message_output.rs`.


<a id="cause-MessageRefusalCodeWidth"></a>

### `MessageRefusalCodeWidth`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `let Some(rejection) = rejection`.


<a id="cause-MessageRefusalCount"></a>

### `MessageRefusalCount`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `let Some(rejection) = rejection`.
- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `Some(rejection.function) == begin`.
- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-MessageRefusalDisposition"></a>

### `MessageRefusalDisposition`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-MessageRefusalPresence"></a>

### `MessageRefusalPresence`


Local detection/handling phase and implementation owner:

- `read_one` (module-level helper) — `src/advanced/record/message_rejections.rs`.


<a id="cause-MessageRefusalRepresentation"></a>

### `MessageRefusalRepresentation`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/record/message_rejections.rs`.


<a id="cause-MessageRefusalRowAbsent"></a>

### `MessageRefusalRowAbsent`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.
- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `let Some(report) = report`.


<a id="cause-MessageRepresentationOnAnotherFamily"></a>

### `MessageRepresentationOnAnotherFamily`


Local detection/handling phase and implementation owner:

- `Messages<'a>::require_typed` — `src/advanced/record/messages.rs`. Enclosing match alternative: `Self::Native(_) | Self::Aead(_)`.


<a id="cause-MessageRequiredOutputWidth"></a>

### `MessageRequiredOutputWidth`


Local detection/handling phase and implementation owner:

- `MessageOutput::read` — `src/advanced/record/message_output.rs`.


<a id="cause-MessageStreamParent"></a>

### `MessageStreamParent`


Local detection/handling phase and implementation owner:

- `Messages<'a>::read` — `src/advanced/record/messages.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordInitLayoutWithoutAeadParameters"></a>

### `RecordInitLayoutWithoutAeadParameters`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing true branch: `self.params.message_init.is_some() && self.origin == NonceOrigin::None`.


<a id="cause-RecordAggregateFragments"></a>

### `RecordAggregateFragments`


Local detection/handling phase and implementation owner:

- `Messages<'a>::write_rows` — `src/advanced/record/messages.rs`.
- `Messages<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-RecordChangedFixedInitScalars"></a>

### `RecordChangedFixedInitScalars`


Local detection/handling phase and implementation owner:

- `ordered_init` (module-level helper) — `src/advanced/record/messages.rs`. Enclosing true branch: `layout == MessageInitLayout::InitWithOwnedMessageParameters && (initial.iv_initial.map(<[u8]>::len) != current.iv_initial.map(<[u8]>::len) || initial.iv_generator != current.iv_generator || initial.iv_fixed_bits != current.iv_fixed_bits || initial.tag_bits != current.tag_bits)`.


<a id="cause-RecordCompletedNonceAbsent"></a>

### `RecordCompletedNonceAbsent`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing match alternative: `NonceOrigin::Backend if self.state == MessageState::Finished && self.params.nonce.is_none()`.


<a id="cause-RecordFinishedMessageIncomplete"></a>

### `RecordFinishedMessageIncomplete`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing match alternative: `MessageState::Finished if self.next_fragment != self.fragments.len()`.


<a id="cause-RecordFragmentCount"></a>

### `RecordFragmentCount`


Local detection/handling phase and implementation owner:

- `Message<'a>::write` — `src/advanced/record/messages.rs`.


<a id="cause-RecordFragmentIndex"></a>

### `RecordFragmentIndex`


Local detection/handling phase and implementation owner:

- `Message<'a>::write` — `src/advanced/record/messages.rs`.


<a id="cause-RecordMessageInitLayout"></a>

### `RecordMessageInitLayout`


Local detection/handling phase and implementation owner:

- `Parameters<'a>::read` — `src/advanced/record/messages.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordMessageCount"></a>

### `RecordMessageCount`


Local detection/handling phase and implementation owner:

- `Messages<'a>::write_generated_aead` — `src/advanced/record/messages.rs`. Enclosing true branch: `count == 0 || count > limits.messages`.
- `Messages<'a>::write_typed` — `src/advanced/record/messages.rs`. Enclosing true branch: `count == 0 && stream.is_none() || count > limits.messages`.
- `Messages<'a>::read` — `src/advanced/record/messages.rs`. Enclosing true branch: `count == 0 && stream.is_none()`.


<a id="cause-RecordMessageOrder"></a>

### `RecordMessageOrder`


Local detection/handling phase and implementation owner:

- `ordered` (module-level helper) — `src/advanced/record/messages.rs`. Enclosing true branch: `!valid`.


<a id="cause-RecordMessageProgression"></a>

### `RecordMessageProgression`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`.


<a id="cause-RecordMessageRoute"></a>

### `RecordMessageRoute`


Local detection/handling phase and implementation owner:

- `Message<'a>::read` — `src/advanced/record/messages.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordMessageState"></a>

### `RecordMessageState`


Local detection/handling phase and implementation owner:

- `Message<'a>::read` — `src/advanced/record/messages.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordMessageStreamAssociation"></a>

### `RecordMessageStreamAssociation`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `!matches!( descriptor.family, Family::MessageSign | Family::MessageVerify ) || !descriptor.input.incremental || descriptor.carried_messages != 0 || descriptor.cipher_options.is_some() || descriptor.digest_bits.is_some() || descriptor.phase != Function::from_name(self.boundary.function(verify))?`.


<a id="cause-RecordMessageStreamBoundary"></a>

### `RecordMessageStreamBoundary`


Local detection/handling phase and implementation owner:

- `StreamBoundary::read` — `src/advanced/record/message_stream.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordMessageStreamDisposition"></a>

### `RecordMessageStreamDisposition`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `!route_valid || self.boundary == Init && (!detached || messages.len() != 0) || detached && matches!(self.boundary, Ready | Receive) || terminal.is_some_and(|valid| self.boundary != Finish || valid == self.invalid) || descriptor.input.is_open() != (self.boundary != Finish) || self.invalid && !verify`.


<a id="cause-RecordMessageStreamInvalidResult"></a>

### `RecordMessageStreamInvalidResult`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::read` — `src/advanced/record/message_stream.rs`.


<a id="cause-RecordMessageStreamObservationAbsent"></a>

### `RecordMessageStreamObservationAbsent`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `let Some(report) = report`.


<a id="cause-RecordMessageStreamObservationAssociation"></a>

### `RecordMessageStreamObservationAssociation`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `observation.function != function || observation.message_index != Some(index)`.


<a id="cause-RecordMessageStreamOutputCounter"></a>

### `RecordMessageStreamOutputCounter`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-RecordMessageStreamOutputPhase"></a>

### `RecordMessageStreamOutputPhase`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `!self.boundary.terminal_message() || terminal.is_some()`.


<a id="cause-RecordMessageStreamProgress"></a>

### `RecordMessageStreamProgress`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-RecordMessageStreamReportCapacity"></a>

### `RecordMessageStreamReportCapacity`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `messages.len().checked_add(1) != Some(report.maximum())`.


<a id="cause-RecordMessageStreamRoute"></a>

### `RecordMessageStreamRoute`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::read` — `src/advanced/record/message_stream.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordMessageStreamRow"></a>

### `RecordMessageStreamRow`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-RecordMessageStreamRowAbsent"></a>

### `RecordMessageStreamRowAbsent`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-RecordMessageStreamSignatureResult"></a>

### `RecordMessageStreamSignatureResult`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `(finished && message.tag_or_signature != Some(message.result)) || (!finished && message.tag_or_signature.is_some())`.


<a id="cause-RecordMessageStreamSubmissionWidth"></a>

### `RecordMessageStreamSubmissionWidth`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`.


<a id="cause-RecordMessageStreamUnexpectedObservation"></a>

### `RecordMessageStreamUnexpectedObservation`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `observations.next().is_some()`.


<a id="cause-RecordMessageStreamVerificationInput"></a>

### `RecordMessageStreamVerificationInput`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `message.expected != 0 || message.produced != 0 || message.tag_or_signature.is_some() != needs_signature`.


<a id="cause-RecordMessageWidth"></a>

### `RecordMessageWidth`


Local detection/handling phase and implementation owner:

- `Messages<'a>::write_generated_aead` — `src/advanced/record/messages.rs`.
- `Messages<'a>::write_rows` — `src/advanced/record/messages.rs`.


<a id="cause-RecordMixedMessageInitLayouts"></a>

### `RecordMixedMessageInitLayouts`


Local detection/handling phase and implementation owner:

- `ordered_init` (module-level helper) — `src/advanced/record/messages.rs`. Enclosing true branch: `layout != current .message_init .unwrap_or(MessageInitLayout::InitWithoutParameters)`.


<a id="cause-RecordNonceOrigin"></a>

### `RecordNonceOrigin`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing match alternative: `NonceOrigin::None if self.params.nonce.is_some()`.
- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing match alternative: `NonceOrigin::Provided if self.params.nonce.is_none()`.
- `Message<'a>::read` — `src/advanced/record/messages.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordPlannedMessageProgressed"></a>

### `RecordPlannedMessageProgressed`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing match alternative: `MessageState::Planned if self.next_fragment != 0 || self.produced != 0`.


<a id="cause-RecordResidualRange"></a>

### `RecordResidualRange`


Local detection/handling phase and implementation owner:

- `Message<'a>::validate` — `src/advanced/record/messages.rs`. Enclosing true branch: `self .residual_start .checked_add(self.residual_length) .filter(|n| *n <= self.produced) .is_none()`.


<a id="cause-RecordSizeConversion"></a>

### `RecordSizeConversion`


Local detection/handling phase and implementation owner:

- `Message<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-SignatureRecordParameters"></a>

### `SignatureRecordParameters`


Local detection/handling phase and implementation owner:

- `Parameters<'a>::read` — `src/advanced/record/messages.rs`.


<a id="cause-TerminalMessageStreamReportAbsent"></a>

### `TerminalMessageStreamReportAbsent`


Local detection/handling phase and implementation owner:

- `MessageStream<'a>::validate` — `src/advanced/record/message_stream.rs`. Enclosing true branch: `terminal.is_some()`.
