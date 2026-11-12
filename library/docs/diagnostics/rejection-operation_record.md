Cause contracts for `OperationRecordRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AesRequiresPhaseSpecificTerminalValidation"></a>

### `AesRequiresPhaseSpecificTerminalValidation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing match alternative: `Family::CipherEncrypt | Family::CipherDecrypt | Family::Signature | Family::NativeMessages`.


<a id="cause-AsynchronousFunctionIdentity"></a>

### `AsynchronousFunctionIdentity`


Local detection/handling phase and implementation owner:

- `Function::from_name` — `src/advanced/record/functions.rs`.


<a id="cause-CipherExtensionKeyEffects"></a>

### `CipherExtensionKeyEffects`


Local detection/handling phase and implementation owner:

- `CipherExtension<'a>::read` — `src/advanced/record/cipher_extension.rs`.


<a id="cause-CipherExtensionProvenance"></a>

### `CipherExtensionProvenance`


Local detection/handling phase and implementation owner:

- `CipherExtension<'a>::read` — `src/advanced/record/cipher_extension.rs`.


<a id="cause-DigestExtensionProvenance"></a>

### `DigestExtensionProvenance`


Local detection/handling phase and implementation owner:

- `DigestExtension<'a>::read` — `src/advanced/record/digest_extension.rs`.


<a id="cause-DigestOutputCapacityWidth"></a>

### `DigestOutputCapacityWidth`

Detected while decoding/validating a saved output-capacity or returned-length
field that does not fit the destination usize/CK_ULONG representation. No native
call or live buffer negotiation occurs in this record check. Reject the archive
under the import contract; do not clamp the field, treat it as a new size request,
or assume that an import failure returns a consumed record to the caller.


Local detection/handling phase and implementation owner:

- `DigestOutput::read` — `src/advanced/record/digest_output.rs`.


<a id="cause-FailedAesOwnerHasNoTerminalResult"></a>

### `FailedAesOwnerHasNoTerminalResult`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `!valid`.


<a id="cause-FailedRecoveryMustNotContainATerminalResult"></a>

### `FailedRecoveryMustNotContainATerminalResult`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `!valid`.


<a id="cause-InvalidTerminalPlaintextDisclosure"></a>

### `InvalidTerminalPlaintextDisclosure`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `!valid && (!m.result.is_empty() || m.produced != 0 || m.residual_start != 0 || m.residual_length != 0)`.


<a id="cause-ReconstructionRequiresEncodedGraph"></a>

### `ReconstructionRequiresEncodedGraph`


Local detection/handling phase and implementation owner:

- `Graph<'a>::encoded` — `src/advanced/record/signature.rs`. Enclosing match alternative: `Self::Live(_)`.


<a id="cause-RecordByteCeiling"></a>

### `RecordByteCeiling`


Local detection/handling phase and implementation owner:

- `Reader<'a>::bytes` — `src/advanced/record.rs`. Enclosing true branch: `n > maximum`.
- `decode_with` (module-level helper) — `src/advanced/record.rs`. Enclosing true branch: `bytes.len() > limits.bytes`.


<a id="cause-RecordByteLength"></a>

### `RecordByteLength`


Local detection/handling phase and implementation owner:

- `Writer<'_>::bytes` — `src/advanced/record.rs`.
- `Writer<'_>::generated_bytes` — `src/advanced/record.rs`.
- `encode_into` (module-level helper) — `src/advanced/record.rs`.
- `Writer<'_>::record_bytes` — `src/advanced/record.rs`.
- `Writer<'_>::record_bytes` — `src/advanced/record.rs`.
- `Reader<'a>::bytes` — `src/advanced/record.rs`.
- `decode_with` (module-level helper) — `src/advanced/record.rs`.


<a id="cause-RecordCipherOptionsTag"></a>

### `RecordCipherOptionsTag`


Local detection/handling phase and implementation owner:

- `OptionsTag::from_wire` — `src/advanced/record/options.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordClassWidth"></a>

### `RecordClassWidth`


Local detection/handling phase and implementation owner:

- `KeyBinding<'a>::validate` — `src/advanced/record/bindings.rs`. Enclosing true branch: `let Some(class) = self.class`.


<a id="cause-RecordContextMismatch"></a>

### `RecordContextMismatch`


Local detection/handling phase and implementation owner:

- `Context::check_destination_binding` — `src/advanced/record/bindings.rs`. Enclosing true branch: `self.module != inner.module_binding || self.label != capabilities.label || self.manufacturer != capabilities.identity.manufacturer || self.model != capabilities.identity.model || self.serial != capabilities.identity.serial`.
- `Context::check` — `src/advanced/record/bindings.rs`. Enclosing true branch: `self != expected`.


<a id="cause-RecordCount"></a>

### `RecordCount`


Local detection/handling phase and implementation owner:

- `Reader<'a>::count` — `src/advanced/record.rs`. Enclosing true branch: `n > maximum`.


<a id="cause-RecordFunctionCode"></a>

### `RecordFunctionCode`


Local detection/handling phase and implementation owner:

- `Function::from_name` — `src/advanced/record/functions.rs`.
- `Function::read` — `src/advanced/record/functions.rs`. Enclosing true branch: `code == 0 || usize::from(code) > NAMES.len()`.


<a id="cause-RecordGeneratedByteLength"></a>

### `RecordGeneratedByteLength`


Local detection/handling phase and implementation owner:

- `Writer<'_>::generated_bytes` — `src/advanced/record.rs`. Enclosing true branch: `self.position.checked_sub(start) != Some(length)`.


<a id="cause-RecordIdentityWidth"></a>

### `RecordIdentityWidth`


Local detection/handling phase and implementation owner:

- `Context::read` — `src/advanced/record/bindings.rs`.


<a id="cause-RecordIntegerWidth"></a>

### `RecordIntegerWidth`


Local detection/handling phase and implementation owner:

- `Reader<'a>::u16` — `src/advanced/record.rs`.
- `Reader<'a>::u32` — `src/advanced/record.rs`.
- `Reader<'a>::u64` — `src/advanced/record.rs`.


<a id="cause-RecordKeyRole"></a>

### `RecordKeyRole`


Local detection/handling phase and implementation owner:

- `KeyBinding<'a>::read` — `src/advanced/record/bindings.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordKeyRoleOrder"></a>

### `RecordKeyRoleOrder`


Local detection/handling phase and implementation owner:

- `KeyBindings<'a>::write` — `src/advanced/record/bindings.rs`. Enclosing true branch: `self.cipher.is_some_and(|k| k.role != KeyRole::Cipher) || self .authentication .is_some_and(|k| k.role != KeyRole::Authentication)`.
- `KeyBindings<'a>::read` — `src/advanced/record/bindings.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordKeyTypeWidth"></a>

### `RecordKeyTypeWidth`


Local detection/handling phase and implementation owner:

- `KeyBinding<'a>::validate` — `src/advanced/record/bindings.rs`. Enclosing true branch: `let Some(key_type) = self.key_type`.


<a id="cause-RecordKind"></a>

### `RecordKind`


Local detection/handling phase and implementation owner:

- `Kind::from_wire` — `src/advanced/record.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordLength"></a>

### `RecordLength`


Local detection/handling phase and implementation owner:

- `Writer<'_>::put` — `src/advanced/record.rs`.
- `encoded_size` (module-level helper) — `src/advanced/record.rs`.
- `encode_into` (module-level helper) — `src/advanced/record.rs`.


<a id="cause-RecordLimits"></a>

### `RecordLimits`


Local detection/handling phase and implementation owner:

- `Limits::validate` — `src/advanced/record.rs`. Enclosing true branch: `self.bytes < HEADER || self.bytes > isize::MAX as usize`.


<a id="cause-RecordObservationWidth"></a>

### `RecordObservationWidth`


Local detection/handling phase and implementation owner:

- `ValidationRecord<'a>::write` — `src/advanced/record/validation.rs`.


<a id="cause-RecordOption"></a>

### `RecordOption`


Local detection/handling phase and implementation owner:

- `Reader<'a>::optional_bytes` — `src/advanced/record.rs`. Enclosing match alternative: `_`.
- `Reader<'a>::optional_u64` — `src/advanced/record.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordOptionalIntegerTag"></a>

### `RecordOptionalIntegerTag`


Local detection/handling phase and implementation owner:

- `read_optional_number` (module-level helper) — `src/advanced/record/bindings.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordPayloadLength"></a>

### `RecordPayloadLength`


Local detection/handling phase and implementation owner:

- `decode_with` (module-level helper) — `src/advanced/record.rs`. Enclosing true branch: `payload != bytes.len() - HEADER`.


<a id="cause-RecordPhaseCode"></a>

### `RecordPhaseCode`


Local detection/handling phase and implementation owner:

- `Function::write_phase` — `src/advanced/record/functions.rs`.
- `Function::read_phase` — `src/advanced/record/functions.rs`. Enclosing true branch: `code == 0 || usize::from(code) > NAMES.len()`.


<a id="cause-RecordReadOverflow"></a>

### `RecordReadOverflow`


Local detection/handling phase and implementation owner:

- `Reader<'a>::take` — `src/advanced/record.rs`.


<a id="cause-RecordSessionState"></a>

### `RecordSessionState`


Local detection/handling phase and implementation owner:

- `Context::validate` — `src/advanced/record/bindings.rs`. Enclosing true branch: `!matches!(self.session_state, 0..=4)`.


<a id="cause-RecordSessionWidth"></a>

### `RecordSessionWidth`


Local detection/handling phase and implementation owner:

- `Context::required_session_state` — `src/advanced/record/bindings.rs`.


<a id="cause-RecordSizeChanged"></a>

### `RecordSizeChanged`


Local detection/handling phase and implementation owner:

- `encode_into` (module-level helper) — `src/advanced/record.rs`. Enclosing true branch: `writer.position != total`.
- `Writer<'_>::record_bytes` — `src/advanced/record.rs`. Enclosing true branch: `self.position.checked_sub(start) != Some(total)`.


<a id="cause-RecordTrailingBytes"></a>

### `RecordTrailingBytes`


Local detection/handling phase and implementation owner:

- `Reader<'a>::finish` — `src/advanced/record.rs`. Enclosing false branch: `self.position == self.bytes.len()`.


<a id="cause-RecordValidationFunction"></a>

### `RecordValidationFunction`


Local detection/handling phase and implementation owner:

- `observation_shape` (module-level helper) — `src/advanced/record/validation.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordValidationIndex"></a>

### `RecordValidationIndex`


Local detection/handling phase and implementation owner:

- `observation_shape` (module-level helper) — `src/advanced/record/validation.rs`. Enclosing true branch: `indexed != index.is_some() || index.is_some_and(|n| n >= limits.messages)`.
- `read_observation` (module-level helper) — `src/advanced/record/validation.rs`.


<a id="cause-RecordValidationMode"></a>

### `RecordValidationMode`


Local detection/handling phase and implementation owner:

- `ValidationRecord<'a>::read` — `src/advanced/record/validation.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordValidationWidth"></a>

### `RecordValidationWidth`


Local detection/handling phase and implementation owner:

- `ValidationRecord<'a>::write` — `src/advanced/record/validation.rs`.


<a id="cause-RecordVersion"></a>

### `RecordVersion`


Local detection/handling phase and implementation owner:

- `decode_with` (module-level helper) — `src/advanced/record.rs`. Enclosing true branch: `reader.take(8)? != MAGIC`.


<a id="cause-RecordWriteRange"></a>

### `RecordWriteRange`


Local detection/handling phase and implementation owner:

- `Writer<'_>::put` — `src/advanced/record.rs`. Enclosing true branch: `let Some(target) = &mut self.target`.


<a id="cause-SignatureContinuationObservation"></a>

### `SignatureContinuationObservation`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `report.maximum() != 1 || report.iter().next().is_some()`.


<a id="cause-SignatureContinuationPosition"></a>

### `SignatureContinuationPosition`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`.


<a id="cause-SignatureKeyEffect"></a>

### `SignatureKeyEffect`


Local detection/handling phase and implementation owner:

- `SignatureParameters<'a>::read` — `src/advanced/record/signature.rs`.


<a id="cause-SignatureLayoutProvenance"></a>

### `SignatureLayoutProvenance`


Local detection/handling phase and implementation owner:

- `SignatureParameters<'a>::read` — `src/advanced/record/signature.rs`.


<a id="cause-SignatureMechanismWidth"></a>

### `SignatureMechanismWidth`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`.
- `Destination<'a>::imported` — `src/advanced/signature/binding.rs`. Enclosing false branch: `parameters.caller_asserted || descriptor.mechanism == fe11_sys::CKM_SHA512_T_HMAC_GENERAL as u64`.
- `RecordPlan<'a>::bind` — `src/advanced/signature/checkpoint.rs`.


<a id="cause-SignatureOutputQuery"></a>

### `SignatureOutputQuery`


Local detection/handling phase and implementation owner:

- `SignatureParameters<'a>::read` — `src/advanced/record/signature.rs`.


<a id="cause-SignatureRecordKind"></a>

### `SignatureRecordKind`


Local detection/handling phase and implementation owner:

- `functions` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing match alternative: `_`.
- `Kind::from_profile` — `src/advanced/signature/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-SignatureRecordOperands"></a>

### `SignatureRecordOperands`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `descriptor.profile == 1 && message.tag_or_signature.is_some() || descriptor.profile == 3 && message.tag_or_signature.is_none() || descriptor.profile != 1 && (p.query || p.maximum_output != 0) || message.route == MessageRoute::Single && descriptor.input.is_open() && !matches!(p.phase, SignaturePhase::Ready)`.


<a id="cause-SignatureRecordParametersAbsent"></a>

### `SignatureRecordParametersAbsent`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`.


<a id="cause-SignatureRecordPhase"></a>

### `SignatureRecordPhase`


Local detection/handling phase and implementation owner:

- `SignatureParameters<'a>::read` — `src/advanced/record/signature.rs`. Enclosing match alternative: `_`.


<a id="cause-SignatureRecordRepresentation"></a>

### `SignatureRecordRepresentation`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`.


<a id="cause-SignatureRecordSections"></a>

### `SignatureRecordSections`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`.


<a id="cause-SignatureRecordWidth"></a>

### `SignatureRecordWidth`


Local detection/handling phase and implementation owner:

- `width` (module-level helper) — `src/advanced/record/signature.rs`.


<a id="cause-SignatureRetainedSizingResponse"></a>

### `SignatureRetainedSizingResponse`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `descriptor.profile != 1 || p.output_capacity.is_some() || descriptor.input.is_open() || p.returned_length != required as u64 || previous_capacity > p.maximum_output || !(code == CKR_BUFFER_TOO_SMALL as u64 || code == CKR_OK as u64 && p.query) || p.query && previous_capacity != 0`.


<a id="cause-SignatureReturnedLengthWidth"></a>

### `SignatureReturnedLengthWidth`

Detected while decoding/validating a saved output-capacity or returned-length
field that does not fit the destination usize/CK_ULONG representation. No native
call or live buffer negotiation occurs in this record check. Reject the archive
under the import contract; do not clamp the field, treat it as a new size request,
or assume that an import failure returns a consumed record to the caller.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`.


<a id="cause-SignatureTerminalInputOpen"></a>

### `SignatureTerminalInputOpen`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `descriptor.input.is_open()`.


<a id="cause-SignatureTerminalSizingContinuation"></a>

### `SignatureTerminalSizingContinuation`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `retained && (descriptor.profile != 1 || p.query)`.


<a id="cause-SingleSignatureReadyPhase"></a>

### `SingleSignatureReadyPhase`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `!descriptor.input.is_open() || !descriptor.input.incremental || descriptor.input.progress.submissions != 0 || descriptor.input.progress.input_bytes != 0`.


<a id="cause-SingleSignatureSubmissionCounters"></a>

### `SingleSignatureSubmissionCounters`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `message.route == MessageRoute::Single && (descriptor.input.progress.input_bytes != 0 || descriptor.input.progress.submissions != u64::from(descriptor.input.retained_submission))`.


<a id="cause-SingleSignatureUpdatePhase"></a>

### `SingleSignatureUpdatePhase`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/record/signature.rs`. Enclosing true branch: `message.route != MessageRoute::Multipart`.


<a id="cause-TerminalAeadCapacityContinuation"></a>

### `TerminalAeadCapacityContinuation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `state.output.is_some()`.


<a id="cause-TerminalCipherCorrelation"></a>

### `TerminalCipherCorrelation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `observation.function != expected || observation.message_index.is_some()`.


<a id="cause-TerminalCipherObservationAbsent"></a>

### `TerminalCipherObservationAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `self.family.is_dual()`.


<a id="cause-TerminalCipherResultLength"></a>

### `TerminalCipherResultLength`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `valid && (m.produced < min || m.produced > max || m.residual_start.checked_add(m.residual_length) != Some(m.produced))`.


<a id="cause-TerminalClassicBatch"></a>

### `TerminalClassicBatch`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `classic && messages.len() != 1`.


<a id="cause-TerminalCompletedFunction"></a>

### `TerminalCompletedFunction`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `self.phase.name() != terminal`.


<a id="cause-TerminalEmptyResult"></a>

### `TerminalEmptyResult`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`.


<a id="cause-TerminalInputLength"></a>

### `TerminalInputLength`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `self.family.is_dual()`.


<a id="cause-TerminalMessageCorrelation"></a>

### `TerminalMessageCorrelation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `observation.function != expected || observation.message_index != Some(index)`.


<a id="cause-TerminalMessageObservationAbsent"></a>

### `TerminalMessageObservationAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `self.family != Family::Digest`.


<a id="cause-TerminalMessageOutputContinuation"></a>

### `TerminalMessageOutputContinuation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `messages.output().is_some()`.


<a id="cause-TerminalMessageProgression"></a>

### `TerminalMessageProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `m.route != first.route || m.state == MessageState::Engaged`.


<a id="cause-TerminalNoncontiguousProcessedPrefix"></a>

### `TerminalNoncontiguousProcessedPrefix`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `planned_suffix`.


<a id="cause-TerminalProcessedPrefix"></a>

### `TerminalProcessedPrefix`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `finished == 0 || self.carried_messages > finished`.


<a id="cause-TerminalReportCapacity"></a>

### `TerminalReportCapacity`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing false branch: `self.family.is_dual()`.
- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `report.maximum() != maximum`.


<a id="cause-TerminalResultDisposition"></a>

### `TerminalResultDisposition`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `!valid && !matches!(self.family, Family::MessageVerify | Family::DecryptVerify) || self.active_flags != 0 || self.carried_messages > messages.len() || self.carried_messages != 0 && self.family != Family::MessageDecrypt`.


<a id="cause-TerminalUnexpectedObservation"></a>

### `TerminalUnexpectedObservation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `prior.next().is_some()`.


<a id="cause-TerminalUnfinishedResult"></a>

### `TerminalUnfinishedResult`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `valid || self.family != Family::MessageVerify`.


<a id="cause-TruncatedRecord"></a>

### `TruncatedRecord`


Local detection/handling phase and implementation owner:

- `Reader<'a>::take` — `src/advanced/record.rs`.
