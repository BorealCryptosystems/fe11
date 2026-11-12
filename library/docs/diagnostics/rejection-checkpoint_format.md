Cause contracts for `CheckpointFormatRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CallerFedAeadAsynchronousModeUnavailable"></a>

### `CallerFedAeadAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/gcm/checkpoint/reconstruction.rs`. Enclosing true branch: `pending`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `detached`.


<a id="cause-CheckpointSymmetricProfile"></a>

### `CheckpointSymmetricProfile`


Local detection/handling phase and implementation owner:

- `Descriptor::symmetric_profile` — `src/advanced/record/checkpoint/encoding.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherGraphOnAnotherRecordFamily"></a>

### `CipherGraphOnAnotherRecordFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `!self.family.is_cipher() && message.params.cipher_extension.is_some()`.


<a id="cause-CipherOptionsOnAnotherRecordFamily"></a>

### `CipherOptionsOnAnotherRecordFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::write` — `src/advanced/record/checkpoint/encoding.rs`. Enclosing true branch: `!self.family.is_cipher() && self.cipher_options.is_some()`.
- `Descriptor::read` — `src/advanced/record/checkpoint/encoding.rs`. Enclosing true branch: `!family.is_cipher() && cipher_options.is_some()`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `!self.family.is_cipher() && self.cipher_options.is_some()`.


<a id="cause-DetachedActiveMessageAbsent"></a>

### `DetachedActiveMessageAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family == Family::MessageSign && stream.boundary.terminal_message()`.
- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `matches!(phase, "C_DecryptMessage" | "C_DecryptMessageNext")`.
- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `matches!(phase, "C_SignMessage" | "C_SignMessageNext")`.


<a id="cause-DetachedCryptographicFamily"></a>

### `DetachedCryptographicFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `_`.


<a id="cause-DetachedInputLength"></a>

### `DetachedInputLength`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `matches!(phase_kind, PhaseKind::Update | PhaseKind::CipherFinal)`.


<a id="cause-DetachedMessageAbsent"></a>

### `DetachedMessageAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `Family::DigestEncrypt | Family::DecryptDigest | Family::SignEncrypt | Family::DecryptVerify`.


<a id="cause-DetachedOutputCapacity"></a>

### `DetachedOutputCapacity`

Detected while validating a detached combined-operation descriptor: deriving
its pending output capacity from input and already produced bytes overflows or
underflows. No native join or replay is performed by this record check. Reject
the inconsistent record through the import/transfer owner; do not edit lengths
to manufacture a capacity or assume the old executor has stopped.


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `matches!(phase_kind, PhaseKind::Update | PhaseKind::CipherFinal)`.


<a id="cause-DetachedOutputCeiling"></a>

### `DetachedOutputCeiling`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `n > limits.bytes`.


<a id="cause-DetachedOutputProgression"></a>

### `DetachedOutputProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `matches!(phase, "C_DecryptMessage" | "C_DecryptMessageNext")`.


<a id="cause-DigestOidOnANonDigestRecord"></a>

### `DigestOidOnANonDigestRecord`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `self.family != Family::Digest && p.digest_oid.is_some()`.


<a id="cause-DigestExtensionOnAnotherFamily"></a>

### `DigestExtensionOnAnotherFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `self.family != Family::Digest && p.digest_extension.is_some()`.


<a id="cause-DigestOutputOnAnotherFamily"></a>

### `DigestOutputOnAnotherFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family != Family::Digest && message.params.digest_output.is_some()`.


<a id="cause-DigestOutputStorageAbsent"></a>

### `DigestOutputStorageAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `self.family == Family::Digest`.


<a id="cause-DigestOutputStorageLimit"></a>

### `DigestOutputStorageLimit`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `output.capacity > limits.bytes`.


<a id="cause-DigestOutputWaitIsNotARetainedTerminal"></a>

### `DigestOutputWaitIsNotARetainedTerminal`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `terminal || self.input.is_open() || self.phase.name() != selection.terminal_function() || invalid_submission`.


<a id="cause-DigestParametersOnAnotherRecordFamily"></a>

### `DigestParametersOnAnotherRecordFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::write` — `src/advanced/record/checkpoint/encoding.rs`. Enclosing true branch: `self.digest_bits.is_some() && (self.family != Family::Digest || self.cipher_options.is_some())`.
- `Descriptor::read` — `src/advanced/record/checkpoint/encoding.rs`. Enclosing true branch: `digest_bits.is_some() && family != Family::Digest`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.digest_bits.is_some() && (self.family != Family::Digest || self.cipher_options.is_some())`.


<a id="cause-NativeBlockCipherAsynchronousModeUnavailable"></a>

### `NativeBlockCipherAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family.is_cipher()`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `detached`.


<a id="cause-NativeSignatureValidationDispatch"></a>

### `NativeSignatureValidationDispatch`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `Family::Signature | Family::NativeMessages`.


<a id="cause-RecordAeadOutput"></a>

### `RecordAeadOutput`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `!layout.output_capacity && m.expected != input || m.tag_or_signature .map_or(true, |t| t.len() != ((p.tag_bits + 7) / 8) as usize)`.
- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.state == MessageState::Finished && m.produced != declared_input`.


<a id="cause-RecordAeadParameterSelection"></a>

### `RecordAeadParameterSelection`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`.


<a id="cause-RecordAesProfile"></a>

### `RecordAesProfile`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `k.class != Some(CKO_SECRET_KEY as u64) || k.key_type != Some(CKK_AES as u64) || !(profile::AES128..=profile::AES256).contains( &crate::advanced::dual::authentication::cipher_profile(self)?, ) || self.size != 0`.


<a id="cause-RecordCcmMacAlignment"></a>

### `RecordCcmMacAlignment`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `p.tag_bits % 8 != 0`.


<a id="cause-RecordCcmFixedBits"></a>

### `RecordCcmFixedBits`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `ccm_parameters`.


<a id="cause-RecordCcmGenerator"></a>

### `RecordCcmGenerator`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `ccm_parameters`.


<a id="cause-RecordCcmInitialNonce"></a>

### `RecordCcmInitialNonce`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `ccm_parameters`.


<a id="cause-RecordCtrCounterWidthAbsent"></a>

### `RecordCtrCounterWidthAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `self.dual() && self.mechanism == CKM_AES_CTR as u64`.


<a id="cause-RecordIvFixedBitsAbsent"></a>

### `RecordIvFixedBitsAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `aead_parameters`.


<a id="cause-RecordIvGeneratorAbsent"></a>

### `RecordIvGeneratorAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `aead_parameters`.


<a id="cause-RecordInitLayoutForANonAeadMessageFamily"></a>

### `RecordInitLayoutForANonAeadMessageFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.params.message_init.is_some() && !matches!(self.family, Family::MessageEncrypt | Family::MessageDecrypt)`.


<a id="cause-RecordMacKey"></a>

### `RecordMacKey`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `k.class != Some(CKO_SECRET_KEY as u64) || !matches!(k.key_type,Some(x) if x==CKK_GENERIC_SECRET as u64||x==key_type as u64) || !self.dual() && (self.mechanism != kind as u64 || self.size != size)`.


<a id="cause-RecordMacProfile"></a>

### `RecordMacProfile`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordRsaProfile"></a>

### `RecordRsaProfile`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `k.class != Some(if self.family == Family::MessageSign { CKO_PRIVATE_KEY as u64 } else { CKO_PUBLIC_KEY as u64 }) || k.key_type != Some(CKK_RSA as u64) || self.profile == profile::RSA_PSS_SHA256 && self.mechanism != CKM_SHA256_RSA_PKCS_PSS as u64 || self.size == 0`.


<a id="cause-RecordActiveMessagePhase"></a>

### `RecordActiveMessagePhase`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `phase == PhaseKind::Final || phase == PhaseKind::SingleOrBegin && m.state != MessageState::Planned || phase == PhaseKind::Update && (m.state != MessageState::Engaged || m.next_fragment >= m.fragments.len().max(1))`.


<a id="cause-RecordBatchFinalPhase"></a>

### `RecordBatchFinalPhase`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family != Family::Digest && !self.dual() && (phase == PhaseKind::Final) != (finished == messages.len()) && !(phase == PhaseKind::Initial && self.family == Family::MessageDecrypt && self.carried_messages == messages.len())`.


<a id="cause-RecordBufferedMessageInputState"></a>

### `RecordBufferedMessageInputState`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.input.incremental || self.input.is_open() || self.input.progress.key_inputs != 0 || self.input.progress.delivered_bytes != 0`.


<a id="cause-RecordCarriedMessageUnfinished"></a>

### `RecordCarriedMessageUnfinished`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `index < self.carried_messages && m.state != MessageState::Finished`.


<a id="cause-RecordCarriedPrefix"></a>

### `RecordCarriedPrefix`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.carried_messages > messages.len() || self.carried_messages != 0 && self.family != Family::MessageDecrypt`.


<a id="cause-RecordCarriedPrefixWidth"></a>

### `RecordCarriedPrefixWidth`


Local detection/handling phase and implementation owner:

- `Descriptor::write` — `src/advanced/record/checkpoint/encoding.rs`.


<a id="cause-RecordCipherInitProgression"></a>

### `RecordCipherInitProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `PhaseKind::CipherInit if m.next_fragment != 0 || m.produced != 0`.


<a id="cause-RecordCipherMechanism"></a>

### `RecordCipherMechanism`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `!stream_aead && self.mechanism != CKM_AES_GCM as u64 && !(matches!(self.family, Family::MessageEncrypt | Family::MessageDecrypt) && self.mechanism == CKM_AES_CCM as u64) && !(self.dual() && crate::advanced::dual::cipher::non_aead(self.mechanism))`.


<a id="cause-RecordCipherNonce"></a>

### `RecordCipherNonce`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`.


<a id="cause-RecordCipherObservationAssociation"></a>

### `RecordCipherObservationAssociation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `o.function != self.cipher_final() || o.message_index.is_some()`.


<a id="cause-RecordCipherParameters"></a>

### `RecordCipherParameters`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `(aead && p.tag_bits > 128 || !aead && p.tag_bits != 0) || p.mgf.is_some() || p.salt.is_some() || !self.dual() && p.hash.is_some() || p.aad.is_some() != aead || self.dual() && self.mechanism == CKM_AES_GCM as u64 && p.aad.is_some_and(|a| a.len() as u128 > u32::MAX as u128)`.


<a id="cause-RecordClassicBatch"></a>

### `RecordClassicBatch`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `(self.family == Family::Digest || self.dual()) && messages.len() != 1`.


<a id="cause-RecordConsumedLength"></a>

### `RecordConsumedLength`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing false branch: `self.dual()`.


<a id="cause-RecordCounterWidthOnNonCtrOperation"></a>

### `RecordCounterWidthOnNonCtrOperation`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.params.counter_bits.is_some()`.


<a id="cause-RecordDescriptorFlags"></a>

### `RecordDescriptorFlags`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `self.family != Family::Digest && self.validation_requested || !self.dual() && self.active_flags != 0`.


<a id="cause-RecordDigestParameters"></a>

### `RecordDigestParameters`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`.


<a id="cause-RecordDigestPhase"></a>

### `RecordDigestPhase`


Local detection/handling phase and implementation owner:

- `Descriptor::phase_kind` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordDualMacClass"></a>

### `RecordDualMacClass`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `k.class != Some(CKO_SECRET_KEY as u64)`.


<a id="cause-RecordDualActiveState"></a>

### `RecordDualActiveState`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.active_flags != flags as u64 || phase == PhaseKind::Residual && m.residual_length == 0 || matches!( phase, PhaseKind::Update | PhaseKind::CipherInit | PhaseKind::CipherFinal ) && (m.residual_start != 0 || m.residual_length != 0)`.


<a id="cause-RecordDualCapacity"></a>

### `RecordDualCapacity`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.route != MessageRoute::Multipart || m.expected != crate::advanced::dual::output_bounds( input, self.decrypt(), self.mechanism, ((p.tag_bits + 7) / 8) as usize, )? .1`.


<a id="cause-RecordDualPhase"></a>

### `RecordDualPhase`


Local detection/handling phase and implementation owner:

- `Descriptor::phase_kind` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `self.dual()`.


<a id="cause-RecordEmptyOperation"></a>

### `RecordEmptyOperation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`.


<a id="cause-RecordExpectedMac"></a>

### `RecordExpectedMac`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.tag_or_signature.map_or(true, |t| { t.len() != dual_authentication .expect("dual selection checked above") .length() })`.


<a id="cause-RecordFinalProgression"></a>

### `RecordFinalProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `PhaseKind::Final | PhaseKind::CipherFinal | PhaseKind::Residual | PhaseKind::AuthenticationFinal if m.next_fragment != m.fragments.len()`.


<a id="cause-RecordFinalizedCipherLength"></a>

### `RecordFinalizedCipherLength`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `m.produced < min || m.produced > max || m.residual_start.checked_add(m.residual_length) != Some(m.produced)`.


<a id="cause-RecordInactiveClassicOperation"></a>

### `RecordInactiveClassicOperation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `m.state != if phase == PhaseKind::Initial { MessageState::Planned } else { MessageState::Engaged }`.


<a id="cause-RecordInitialIvAbsent"></a>

### `RecordInitialIvAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `aead_parameters`.


<a id="cause-RecordInitialProgression"></a>

### `RecordInitialProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `phase == PhaseKind::Initial && index >= self.carried_messages && (m.state != MessageState::Planned || m.next_fragment != 0 || m.produced != 0 || m.residual_start != 0 || m.residual_length != 0)`.


<a id="cause-RecordInputLength"></a>

### `RecordInputLength`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `matches!(phase, PhaseKind::Residual | PhaseKind::AuthenticationFinal)`.


<a id="cause-RecordMessageByteCounter"></a>

### `RecordMessageByteCounter`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`.


<a id="cause-RecordMessageObservationAssociation"></a>

### `RecordMessageObservationAssociation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `o.function != name || o.message_index != Some(i)`.


<a id="cause-RecordMessageOutputCounter"></a>

### `RecordMessageOutputCounter`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`.


<a id="cause-RecordMessagePhase"></a>

### `RecordMessagePhase`


Local detection/handling phase and implementation owner:

- `Descriptor::phase_kind` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing false branch: `p == next && route == MessageRoute::Multipart`.


<a id="cause-RecordMessageProgressMismatch"></a>

### `RecordMessageProgressMismatch`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.input.progress.submissions != submissions || self.input.progress.input_bytes != bytes || self.input.progress.output_bytes != output`.


<a id="cause-RecordMessageSubmissionCounter"></a>

### `RecordMessageSubmissionCounter`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`.
- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `retained_data`.


<a id="cause-RecordMessageSubmissionWidth"></a>

### `RecordMessageSubmissionWidth`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`.


<a id="cause-RecordMissingCipherObservation"></a>

### `RecordMissingCipherObservation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.dual() && matches!(phase, PhaseKind::Residual | PhaseKind::AuthenticationFinal)`.


<a id="cause-RecordMissingMessageObservation"></a>

### `RecordMissingMessageObservation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `!self.dual() && self.family != Family::Digest`.


<a id="cause-RecordMixedRoutes"></a>

### `RecordMixedRoutes`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `m.route != first.route`.


<a id="cause-RecordNativeAeadKeyProfile"></a>

### `RecordNativeAeadKeyProfile`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `self.size != 0`.


<a id="cause-RecordNonAeadNonceSelection"></a>

### `RecordNonAeadNonceSelection`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `p.iv_initial.is_some() || p.iv_generator.is_some() || p.iv_fixed_bits.is_some()`.


<a id="cause-RecordOperationFamily"></a>

### `RecordOperationFamily`


Local detection/handling phase and implementation owner:

- `Family::from_wire` — `src/advanced/record/family.rs`. Enclosing match alternative: `_`.
- `Descriptor::phase_kind` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing match alternative: `_`.
- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `!matches!(self.family, Family::MessageSign | Family::MessageVerify)`.


<a id="cause-RecordOutputPrecedesInput"></a>

### `RecordOutputPrecedesInput`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `!layout.output_capacity && m.produced > consumed`.


<a id="cause-RecordPrematureDualAuthentication"></a>

### `RecordPrematureDualAuthentication`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.tag_or_signature.is_some()`.


<a id="cause-RecordPrematureSignature"></a>

### `RecordPrematureSignature`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.tag_or_signature.is_some()`.


<a id="cause-RecordProfileKeyRoles"></a>

### `RecordProfileKeyRoles`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `keys.cipher.is_some() != cipher || keys.authentication.is_some() != auth || self.size > limits.bytes`.


<a id="cause-RecordRequiredValidationAbsent"></a>

### `RecordRequiredValidationAbsent`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.validation_requested && validation.is_none()`.


<a id="cause-RecordRetainedMessageSubmission"></a>

### `RecordRetainedMessageSubmission`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.input.retained_submission != retained_data`.


<a id="cause-RecordSignatureAssociation"></a>

### `RecordSignatureAssociation`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `m.tag_or_signature.map_or(true, |s| s.len() > limits.bytes) || signed && m.tag_or_signature != Some(m.result)`.


<a id="cause-RecordSignatureCapacity"></a>

### `RecordSignatureCapacity`


Local detection/handling phase and implementation owner:

- `Descriptor::read` — `src/advanced/record/checkpoint/encoding.rs`.


<a id="cause-RecordSignatureParameterFamily"></a>

### `RecordSignatureParameterFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::signature_parameters` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `p.digest_output.is_some() || p.cipher_extension.is_some() || p.digest_extension.is_some() || p.signature.is_some() || p.message_init.is_some() || p.counter_bits.is_some() || p.nonce.is_some() || p.aad.is_some() || p.digest_oid.is_some() || p.iv_generator.is_some() || p.iv_fixed_bits.is_some() || p.iv_initial.is_some()`.


<a id="cause-RecordSignatureParameters"></a>

### `RecordSignatureParameters`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `p.nonce.is_some() || p.aad.is_some() || m.origin != NonceOrigin::None`.
- `Descriptor::signature_parameters` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `!valid`.


<a id="cause-RecordSignatureResult"></a>

### `RecordSignatureResult`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `!signed && (m.expected != 0 || m.produced != 0) || signed && !finished && m.produced != 0`.


<a id="cause-RecordSingleDigestProgression"></a>

### `RecordSingleDigestProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `PhaseKind::SingleOrBegin if m.next_fragment != 0 || m.produced != 0`.


<a id="cause-RecordSingleMessageProgress"></a>

### `RecordSingleMessageProgress`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_message_progress` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `(MessageRoute::Single, MessageState::Engaged)`.


<a id="cause-RecordStreamAeadKeyProfile"></a>

### `RecordStreamAeadKeyProfile`


Local detection/handling phase and implementation owner:

- `Descriptor::keys` — `src/advanced/record/checkpoint/keys.rs`. Enclosing true branch: `stream_aead`.


<a id="cause-RecordStreamAeadNonce"></a>

### `RecordStreamAeadNonce`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `stream_parameters`.


<a id="cause-RecordStreamAeadParameters"></a>

### `RecordStreamAeadParameters`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `p.tag_bits != 128 || p.iv_generator != Some(0) || p.iv_fixed_bits != Some(0) || p.message_init != Some(crate::MessageInitLayout::InitWithoutParameters) || m.origin != NonceOrigin::Provided || p.nonce != Some(initial)`.


<a id="cause-RecordTokenIvDirection"></a>

### `RecordTokenIvDirection`


Local detection/handling phase and implementation owner:

- `Descriptor::read` — `src/advanced/record/checkpoint/encoding.rs`. Enclosing match alternative: `OptionsTag::TokenIv`.


<a id="cause-RecordUnexpectedResidual"></a>

### `RecordUnexpectedResidual`


Local detection/handling phase and implementation owner:

- `Descriptor::message_mode` — `src/advanced/record/checkpoint/descriptor.rs`. Enclosing true branch: `!self.dual() && (m.residual_start != 0 || m.residual_length != 0)`.


<a id="cause-RecordUnexpectedValidationObservation"></a>

### `RecordUnexpectedValidationObservation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `observations.next().is_some()`.


<a id="cause-RecordUpdateProgression"></a>

### `RecordUpdateProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing match alternative: `PhaseKind::Update if m.next_fragment >= m.fragments.len().max(usize::from(self.dual()))`.


<a id="cause-RecordValidationCapacity"></a>

### `RecordValidationCapacity`


Local detection/handling phase and implementation owner:

- `ValidationRecord<'a>::write` — `src/advanced/record/validation.rs`. Enclosing true branch: `maximum == 0 || maximum - 1 > limits.messages || observations.len() > maximum`.
- `ValidationRecord<'a>::read` — `src/advanced/record/validation.rs`. Enclosing true branch: `maximum == 0 || maximum - 1 > limits.messages`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing false branch: `self.dual()`.


<a id="cause-RecordValidationOwnerCapacity"></a>

### `RecordValidationOwnerCapacity`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `v.maximum() != maximum`.


<a id="cause-RecordValidationRequest"></a>

### `RecordValidationRequest`


Local detection/handling phase and implementation owner:

- `Descriptor::read` — `src/advanced/record/checkpoint/encoding.rs`.


<a id="cause-RecoveryCannotRetainANativeCapacityCall"></a>

### `RecoveryCannotRetainANativeCapacityCall`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_recovery` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `state.output.is_some()`.


<a id="cause-RecoveryFamilyOrOutputContinuation"></a>

### `RecoveryFamilyOrOutputContinuation`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_recovery` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family != Family::MessageDecrypt || messages.output().is_some() || messages.stream().is_some()`.


<a id="cause-RecoveryMixedRoutes"></a>

### `RecoveryMixedRoutes`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_recovery` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `route.is_some_and(|prior| prior != m.route)`.


<a id="cause-RecoveryUnauthenticatedProgression"></a>

### `RecoveryUnauthenticatedProgression`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_recovery` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `m.state == MessageState::Engaged`.


<a id="cause-SavedRecordKind"></a>

### `SavedRecordKind`


Local detection/handling phase and implementation owner:

- `SavedRecord<'a>::read_with` — `src/advanced/record/checkpoint.rs`. Enclosing true branch: `kind != Kind::Saved`.


<a id="cause-SignatureParametersOnAnotherFamily"></a>

### `SignatureParametersOnAnotherFamily`


Local detection/handling phase and implementation owner:

- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `message?.params.signature.is_some()`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `message?.params.signature.is_some()`.

