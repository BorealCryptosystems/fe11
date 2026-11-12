Cause contracts for `CipherContinuationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AeadParameterAccountingOverflow"></a>

### `AeadParameterAccountingOverflow`


Local detection/handling phase and implementation owner:

- `Selection<'a>::additional_buffer_bytes` — `src/advanced/cipher/parameters.rs`. Enclosing match alternative: `Self::Aead(p, retained)`.


<a id="cause-AeadRecordAadAbsent"></a>

### `AeadRecordAadAbsent`


Local detection/handling phase and implementation owner:

- `Selection<'a>::from_record` — `src/advanced/cipher/parameters.rs`.


<a id="cause-AeadRecordCounterField"></a>

### `AeadRecordCounterField`


Local detection/handling phase and implementation owner:

- `Selection<'a>::from_record` — `src/advanced/cipher/parameters.rs`. Enclosing true branch: `p.counter_bits.is_some()`.


<a id="cause-AeadRecordParameterCombination"></a>

### `AeadRecordParameterCombination`


Local detection/handling phase and implementation owner:

- `Selection<'a>::from_record` — `src/advanced/cipher/parameters.rs`. Enclosing match alternative: `_`.


<a id="cause-AeadRequiresASecretKey"></a>

### `AeadRequiresASecretKey`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `matches!(parameters, Selection::Aead(_, _)) && matches!(key, CipherKey::Native(CipherKeyReference::NoKey))`.


<a id="cause-AeadRestoredNonceMismatch"></a>

### `AeadRestoredNonceMismatch`


Local detection/handling phase and implementation owner:

- `Frame::restore_generated_iv` — `src/advanced/cipher/parameters.rs`. Enclosing match alternative: `Self::Aead(_)`.


<a id="cause-AeadRetainedNonceWidth"></a>

### `AeadRetainedNonceWidth`


Local detection/handling phase and implementation owner:

- `Frame::selection` — `src/advanced/cipher/parameters.rs`. Enclosing match alternative: `Native::Stream(_) if p.bytes_encoding`.


<a id="cause-AeadRetainedPrefixLengthOverflow"></a>

### `AeadRetainedPrefixLengthOverflow`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `Selection::Aead(p, _) if !direction.decrypts()`.


<a id="cause-AeadSnapshotParameterShapeChanged"></a>

### `AeadSnapshotParameterShapeChanged`


Local detection/handling phase and implementation owner:

- `Frame::fill_request` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing true branch: `frame.kind as u64 != selection.mechanism_number()`.
- `Frame::fill_snapshot` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing true branch: `target.kind != source.kind`.
- `copy_request` (module-level helper) — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing true branch: `destination.as_slice().len() != source.len()`.


<a id="cause-AesOperationRequiresAnAesKey"></a>

### `AesOperationRequiresAnAesKey`


Local detection/handling phase and implementation owner:

- `Facade::start` — `src/advanced/cipher/synchronous.rs`. Enclosing true branch: `!matches!( key.algorithm(), crate::SymmetricAlgorithm::Aes128 | crate::SymmetricAlgorithm::Aes192 | crate::SymmetricAlgorithm::Aes256 )`.
- `start` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `!matches!( key.algorithm(), SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256 )`.


<a id="cause-CcmDataLengthWidth"></a>

### `CcmDataLengthWidth`


Local detection/handling phase and implementation owner:

- `Snapshot<'a>::for_selection` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing match alternative: `super::ParameterInput::Incremental { ccm_data_length }`.


<a id="cause-CcmStreamFramingRequiresItsExactDataLength"></a>

### `CcmStreamFramingRequiresItsExactDataLength`


Local detection/handling phase and implementation owner:

- `Snapshot<'a>::for_selection` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing true branch: `matches!(parameters, Aead::Ccm { .. }) != ccm_data_length.is_some()`.


<a id="cause-CkmNullChangedTheCurrentInput"></a>

### `CkmNullChangedTheCurrentInput`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `self .frame .output .as_ref() .unwrap() .as_slice() .get(self.used..self.used + produced) != Some(expected)`.


<a id="cause-IetfNonceWidth"></a>

### `IetfNonceWidth`


Local detection/handling phase and implementation owner:

- `Frame::fill_request` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing true branch: `padded_ietf(selection)`.


<a id="cause-ArchivedCipherParametersCannotAuthorizeInit"></a>

### `ArchivedCipherParametersCannotAuthorizeInit`


Local detection/handling phase and implementation owner:

- `Source<'a>::check_start` — `src/advanced/cipher/extension.rs`.


<a id="cause-CipherCapturedRequiredCapacityOverflow"></a>

### `CipherCapturedRequiredCapacityOverflow`


Local detection/handling phase and implementation owner:

- `CipherOperation::write_checkpoint_messages` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `Some(request)`.


<a id="cause-CipherCheckpointKeyProfile"></a>

### `CipherCheckpointKeyProfile`


Local detection/handling phase and implementation owner:

- `OutputProfile::wire` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `!(0..=4).contains(&key)`.


<a id="cause-CipherCheckpointRetainsConsumedInput"></a>

### `CipherCheckpointRetainsConsumedInput`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `m.next_fragment != if terminal || d.phase.name() == direction.final_call() { m.fragments.len() } else { 0 }`.


<a id="cause-CipherCompleteInputCounterWidth"></a>

### `CipherCompleteInputCounterWidth`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `!d.input.incremental`.


<a id="cause-CipherCompleteInputSizeOverflow"></a>

### `CipherCompleteInputSizeOverflow`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `!d.input.incremental`.
- `Request<'a>::for_record` — `src/advanced/cipher/snapshot.rs`. Enclosing false branch: `incremental`.


<a id="cause-CipherContinuationUnavailable"></a>

### `CipherContinuationUnavailable`


Local detection/handling phase and implementation owner:

- `CipherOperation::capturable` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `self.pending() || matches!(self.stage, Stage::Init(_) | Stage::Failed) || self.observer == OutputObserver::Session || self.frame.output.is_none() || !self.frame.unchanged()`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.
- `CipherOperation::describe_snapshot` — `src/advanced/cipher/snapshot.rs`.
- `PreparedSnapshot::copy_from` — `src/advanced/cipher/snapshot.rs`.


<a id="cause-CipherDestinationAbiDeclarationAbsent"></a>

### `CipherDestinationAbiDeclarationAbsent`


Local detection/handling phase and implementation owner:

- `Frame::contract` — `src/advanced/cipher/extension.rs`. Enclosing match alternative: `Declaration::Unbound`.


<a id="cause-CipherDestinationAbiDeclarationMismatch"></a>

### `CipherDestinationAbiDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `Frame::check_contract` — `src/advanced/cipher/extension.rs`. Enclosing true branch: `Metadata::from_contract(contract) != self.metadata`.


<a id="cause-CipherDestinationDeclarationMismatch"></a>

### `CipherDestinationDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `check` (module-level helper) — `src/advanced/cipher/extension_binding.rs`. Enclosing true branch: `contract.native_mechanism() != expected.mechanism || contract.constants_edition() != expected.edition || contract.mutates_key() != expected.mutates_key`.


<a id="cause-CipherDestinationKeyPresenceProfile"></a>

### `CipherDestinationKeyPresenceProfile`


Local detection/handling phase and implementation owner:

- `CipherLease::check_record` — `src/advanced/cipher/lease.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherDestinationOutputCapacity"></a>

### `CipherDestinationOutputCapacity`

Detected during local cipher-record reconstruction: destination capacity,
stored result size, produced count or non-incremental output interval is
inconsistent. No native cipher call is made by this check and no reconstructed
result is published. Reject the inconsistent record/preparation; use a valid
authenticated record under the restore contract rather than resizing and replaying
the original cipher. Keep any owner returned by the failed restoration.


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `frame.output.as_ref().unwrap().capacity() != d.size || m.result.len() != m.produced || m.produced > d.size || !d.input.incremental && !profile.waiting() && selection.validates_output_interval() && m.expected != frame.maximum`.


<a id="cause-CipherExtensionDestinationAbsent"></a>

### `CipherExtensionDestinationAbsent`


Local detection/handling phase and implementation owner:

- `PreparedSnapshot::bind_extension_contract` — `src/advanced/cipher/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherExtensionGraphAlreadyPublished"></a>

### `CipherExtensionGraphAlreadyPublished`


Local detection/handling phase and implementation owner:

- `Frame::graph` — `src/advanced/cipher/extension.rs`.


<a id="cause-CipherExtensionMechanismWidth"></a>

### `CipherExtensionMechanismWidth`


Local detection/handling phase and implementation owner:

- `Source<'a>::from_record` — `src/advanced/cipher/extension.rs`.


<a id="cause-CipherExtensionParameterIdentity"></a>

### `CipherExtensionParameterIdentity`


Local detection/handling phase and implementation owner:

- `Frame::validate` — `src/advanced/cipher/extension.rs`. Enclosing true branch: `self.mechanism.mechanism != self.metadata.mechanism || self.mechanism.pParameter as usize != self.pointer || self.mechanism.ulParameterLen != self.length || !self.graph()?.unchanged()`.


<a id="cause-CipherExtensionPreparationChanged"></a>

### `CipherExtensionPreparationChanged`


Local detection/handling phase and implementation owner:

- `Frame::fill_request` — `src/advanced/cipher/extension.rs`. Enclosing true branch: `source.metadata() != self.metadata`.


<a id="cause-CipherFacadeObserverChanged"></a>

### `CipherFacadeObserverChanged`


Local detection/handling phase and implementation owner:

- `park` (module-level helper) — `src/advanced/cipher/synchronous.rs`. Enclosing true branch: `body.observer != OutputObserver::Ticket`.


<a id="cause-CipherFacadeOwnerChanged"></a>

### `CipherFacadeOwnerChanged`


Local detection/handling phase and implementation owner:

- `park` (module-level helper) — `src/advanced/cipher/synchronous.rs`.


<a id="cause-CipherFrameAccountingOverflow"></a>

### `CipherFrameAccountingOverflow`


Local detection/handling phase and implementation owner:

- `CipherStorage::for_shape` — `src/advanced/cipher.rs`.
- `CipherStorage::for_shape` — `src/advanced/cipher.rs`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.


<a id="cause-CipherGraphAbsent"></a>

### `CipherGraphAbsent`


Local detection/handling phase and implementation owner:

- `Frame::finish` — `src/advanced/cipher/extension.rs`.


<a id="cause-CipherGraphAlreadyPublished"></a>

### `CipherGraphAlreadyPublished`


Local detection/handling phase and implementation owner:

- `Frame::publish` — `src/advanced/cipher/extension.rs`.


<a id="cause-CipherGraphMetadataAccounting"></a>

### `CipherGraphMetadataAccounting`


Local detection/handling phase and implementation owner:

- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.


<a id="cause-CipherGraphPacketAbsent"></a>

### `CipherGraphPacketAbsent`


Local detection/handling phase and implementation owner:

- `CipherOperation::describe_snapshot_with_graph` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `let super::CipherFrame::Extension(frame) = &self.frame.parameters`.


<a id="cause-CipherGraphPacketUninitialized"></a>

### `CipherGraphPacketUninitialized`


Local detection/handling phase and implementation owner:

- `Packet::parameters` — `src/advanced/cipher/extension_snapshot.rs`.
- `Packet::contract` — `src/advanced/cipher/extension_snapshot.rs`.


<a id="cause-CipherGraphRecordFamily"></a>

### `CipherGraphRecordFamily`


Local detection/handling phase and implementation owner:

- `Source<'a>::from_record` — `src/advanced/cipher/extension.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherGraphRecordRoute"></a>

### `CipherGraphRecordRoute`


Local detection/handling phase and implementation owner:

- `Source<'a>::record_route` — `src/advanced/cipher/extension.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherGraphSnapshotSize"></a>

### `CipherGraphSnapshotSize`


Local detection/handling phase and implementation owner:

- `Packet::copy_from` — `src/advanced/cipher/extension_snapshot.rs`.
- `Packet::copy_from` — `src/advanced/cipher/extension_snapshot.rs`.


<a id="cause-CipherHasNoAuthenticationKeyRole"></a>

### `CipherHasNoAuthenticationKeyRole`


Local detection/handling phase and implementation owner:

- `CipherOperation::restore_keys` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `keys.authentication.is_some()`.


<a id="cause-CipherImportRequiresADestinationAbiDeclaration"></a>

### `CipherImportRequiresADestinationAbiDeclaration`


Local detection/handling phase and implementation owner:

- `import_contract` (module-level helper) — `src/advanced/cipher/extension_binding.rs`. Enclosing true branch: `extension.caller_asserted`.


<a id="cause-CipherInputChangedBeforeDispatch"></a>

### `CipherInputChangedBeforeDispatch`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `!input_unchanged`.


<a id="cause-CipherInputLayoutAllocation"></a>

### `CipherInputLayoutAllocation`


Local detection/handling phase and implementation owner:

- `InputBuffers::prepare` — `src/advanced/cipher/input.rs`.


<a id="cause-CipherInputLengthOverflow"></a>

### `CipherInputLengthOverflow`


Local detection/handling phase and implementation owner:

- `CipherStorage::for_request` — `src/advanced/cipher.rs`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`.


<a id="cause-CipherInputMetadataAccounting"></a>

### `CipherInputMetadataAccounting`


Local detection/handling phase and implementation owner:

- `submit` (module-level helper) — `src/advanced/cipher/input.rs`. Enclosing true branch: `let Some(waiting) = waiter.as_mut()`.


<a id="cause-CipherInputMetadataAllocation"></a>

### `CipherInputMetadataAllocation`


Local detection/handling phase and implementation owner:

- `InputBuffers::prepare` — `src/advanced/cipher/input.rs`.


<a id="cause-CipherInputStorageAccounting"></a>

### `CipherInputStorageAccounting`


Local detection/handling phase and implementation owner:

- `InputBuffers::prepare` — `src/advanced/cipher/input.rs`.
- `InputBuffers::prepare` — `src/advanced/cipher/input.rs`.


<a id="cause-CipherIsNotReadyForAnotherInput"></a>

### `CipherIsNotReadyForAnotherInput`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/cipher/input.rs`. Enclosing true branch: `!body.input.incremental || !body.input.is_open() || body.pending() || matches!(body.stage, Stage::Init(_) | Stage::Done | Stage::Failed) || ready && (!matches!( body.stage, Stage::Final | Stage::Query(super::OutputStep::Final) ) || !body.frame.inputs.is_empty())`.


<a id="cause-CipherIsNotWaitingForStorage"></a>

### `CipherIsNotWaitingForStorage`


Local detection/handling phase and implementation owner:

- `CipherOperation::park_observer` — `src/advanced/cipher/negotiation.rs`.
- `CipherOperation::output_preparation` — `src/advanced/cipher/negotiation.rs`.


<a id="cause-CipherMechanismWidth"></a>

### `CipherMechanismWidth`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`.
- `Snapshot<'a>::for_selection` — `src/advanced/cipher/parameters/snapshot.rs`.


<a id="cause-CipherNativeInputIdentity"></a>

### `CipherNativeInputIdentity`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `self.frame.parameters.validate_after_call().is_err() || !unchanged`.


<a id="cause-CipherNativeOutputLength"></a>

### `CipherNativeOutputLength`

Detected after a successful Single/Update/Final cipher return whose length
exceeds the available owned buffer. The cipher enters Failed, native activity
is retained as Active and the runtime is marked uncertain. Its input/output
frame and key lease stay with the operation; no invalid output is published.
This is not the Waiting output-negotiation state. Do not resize, repoll as a
new cipher call, or repeat Init. Preserve the ticket/error for the explicit
completion-aware cleanup path, which may itself refuse to release storage.


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `rv == CKR_OK && !query && !matches!(stage, Stage::Init(_))`.
- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing match alternative: `Err(_)`.


<a id="cause-CipherObservationOwnershipChanged"></a>

### `CipherObservationOwnershipChanged`


Local detection/handling phase and implementation owner:

- `CipherOperation::park_observer` — `src/advanced/cipher/negotiation.rs`. Enclosing true branch: `*request != expected || self.observer != OutputObserver::Ticket`.


<a id="cause-CipherOperationStorageSize"></a>

### `CipherOperationStorageSize`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`.
- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`.


<a id="cause-CipherOutcomeUncertain"></a>

### `CipherOutcomeUncertain`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `completion == Completion::Uncertain`.


<a id="cause-CipherOutputAbsent"></a>

### `CipherOutputAbsent`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`.
- `CipherOperation::output_preparation` — `src/advanced/cipher/negotiation.rs`.
- `CipherOperation::describe_snapshot_with_graph` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `let super::CipherFrame::Extension(frame) = &self.frame.parameters`.


<a id="cause-CipherOutputAlreadyTransferred"></a>

### `CipherOutputAlreadyTransferred`


Local detection/handling phase and implementation owner:

- `take_output` (module-level helper) — `src/advanced/cipher/input.rs`.


<a id="cause-CipherOutputCapacityOverflow"></a>

### `CipherOutputCapacityOverflow`

Detected while extending storage for a cipher in Waiting: used bytes plus
the requested capacity overflow, or a prepared replacement has the wrong extent.
No new native call or output attachment occurs at the failing check. Keep the
existing waiting operation and accumulated output. A representable replacement
can be prepared through the same resize API while its state still permits it;
a mismatched prepared extent is an internal inconsistency, not a native size
request. Waiting for credits does not repair overflow.


Local detection/handling phase and implementation owner:

- `CipherOperation::output_preparation` — `src/advanced/cipher/negotiation.rs`.
- `CipherOperation::attach_output` — `src/advanced/cipher/negotiation.rs`. Enclosing true branch: `output.as_slice().len() != total`.


<a id="cause-CipherOutputOffset"></a>

### `CipherOutputOffset`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`.


<a id="cause-CipherOutputStepUnavailable"></a>

### `CipherOutputStepUnavailable`


Local detection/handling phase and implementation owner:

- `OutputStep::from_stage` — `src/advanced/cipher/negotiation.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherOutputStillReferencedByPendingCall"></a>

### `CipherOutputStillReferencedByPendingCall`


Local detection/handling phase and implementation owner:

- `CipherOperation::output_preparation` — `src/advanced/cipher/negotiation.rs`. Enclosing true branch: `self.pending()`.


<a id="cause-CipherParameterFramingChangedOnRestoration"></a>

### `CipherParameterFramingChangedOnRestoration`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `frame.parameters.options() != d.cipher_options`.


<a id="cause-CipherQueuedInputCursor"></a>

### `CipherQueuedInputCursor`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `index != 0`.


<a id="cause-CipherReconstructedDeclarationAbsentOrUnexpected"></a>

### `CipherReconstructedDeclarationAbsentOrUnexpected`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::check_binding` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `(parameters::Frame::Extension(_), None) | (_, Some(_))`.


<a id="cause-CipherRecordIvAbsent"></a>

### `CipherRecordIvAbsent`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`.
- `Selection<'a>::from_record` — `src/advanced/cipher/parameters.rs`.


<a id="cause-CipherRecordDescriptor"></a>

### `CipherRecordDescriptor`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`.


<a id="cause-CipherRecordFamily"></a>

### `CipherRecordFamily`


Local detection/handling phase and implementation owner:

- `Direction::from_family` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherRecordInputOverflow"></a>

### `CipherRecordInputOverflow`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`.


<a id="cause-CipherRecordKeyProfile"></a>

### `CipherRecordKeyProfile`


Local detection/handling phase and implementation owner:

- `KeyProfile::read` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherRecordMessageAbsent"></a>

### `CipherRecordMessageAbsent`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`.
- `RecordPlan<'a>::new` — `src/advanced/cipher/checkpoint.rs`.


<a id="cause-CipherRecordNextFunctionOrFragment"></a>

### `CipherRecordNextFunctionOrFragment`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherRecordOffsetOverflow"></a>

### `CipherRecordOffsetOverflow`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `index < m.next_fragment`.


<a id="cause-CipherRecordOutputBounds"></a>

### `CipherRecordOutputBounds`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `!d.input.incremental && !profile.waiting() && selection.validates_output_interval() && m.expected != maximum || m.produced != m.result.len() || m.produced > d.size || matches!(profile, OutputProfile::Query | OutputProfile::SizeReported) && d.size != m.produced`.


<a id="cause-CipherRecordOutputProfile"></a>

### `CipherRecordOutputProfile`


Local detection/handling phase and implementation owner:

- `OutputProfile::read` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherRecordParameters"></a>

### `CipherRecordParameters`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`.


<a id="cause-CipherRecordProgression"></a>

### `CipherRecordProgression`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `m.state != MessageState::Engaged`.


<a id="cause-CipherRecordValidationCorrelation"></a>

### `CipherRecordValidationCorrelation`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `report.maximum() != 1 || observations.next().is_some() || if terminal { observed.map_or(true, |observation| { observation.function != terminal_function || observation.message_index.is_some() }) } else { observed.is_some() }`.


<a id="cause-CipherRequiredLengthWidth"></a>

### `CipherRequiredLengthWidth`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `!matches!(stage, Stage::Init(_)) && (rv == CKR_BUFFER_TOO_SMALL || query && rv == CKR_OK)`.


<a id="cause-CipherRestorationKeyPresenceMismatch"></a>

### `CipherRestorationKeyPresenceMismatch`


Local detection/handling phase and implementation owner:

- `CipherOperation::restore_keys` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherRestoredCapacityOffset"></a>

### `CipherRestoredCapacityOffset`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing false branch: `profile == OutputProfile::SizeReported`.


<a id="cause-CipherRestoredFragment"></a>

### `CipherRestoredFragment`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `m.next_fragment >= restored.frame.inputs.len()`.


<a id="cause-CipherRestoredFunction"></a>

### `CipherRestoredFunction`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherRestoredOffsetOverflow"></a>

### `CipherRestoredOffsetOverflow`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `(MessageRoute::Multipart, name) if name == direction.update()`.


<a id="cause-CipherRestoredRequiredCapacity"></a>

### `CipherRestoredRequiredCapacity`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `OutputProfile::SizeReported | OutputProfile::TooSmall`.


<a id="cause-CipherResultAlreadyPublished"></a>

### `CipherResultAlreadyPublished`


Local detection/handling phase and implementation owner:

- `CipherOperation::result` — `src/advanced/cipher.rs`.


<a id="cause-CipherResultIncomplete"></a>

### `CipherResultIncomplete`


Local detection/handling phase and implementation owner:

- `CipherOperation::result` — `src/advanced/cipher.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-CipherResultLengthOutsideMechanismContract"></a>

### `CipherResultLengthOutsideMechanismContract`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing match alternative: `Ok(false)`.
- `AeadMessageOperation::finish_step` — `src/advanced/gcm/completion.rs`. Enclosing true branch: `accepted.is_some_and(|bytes| bytes != frame.used as u128) || self.kind == CipherKind::Ccm && frame.used != frame.expected`.


<a id="cause-CipherRetainedOutputCounters"></a>

### `CipherRetainedOutputCounters`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `d.input .progress .output_bytes .checked_sub(d.input.progress.delivered_bytes) != Some(m.produced as u128)`.


<a id="cause-CipherRetainedOutputRange"></a>

### `CipherRetainedOutputRange`


Local detection/handling phase and implementation owner:

- `CipherOperation::write_checkpoint_messages` — `src/advanced/cipher/checkpoint.rs`.
- `CipherOperation::output_preparation` — `src/advanced/cipher/negotiation.rs`.


<a id="cause-CipherReturnedOperandsAwaitingRelease"></a>

### `CipherReturnedOperandsAwaitingRelease`


Local detection/handling phase and implementation owner:

- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `!self.returned.is_empty()`.


<a id="cause-CipherRevocationStorageSize"></a>

### `CipherRevocationStorageSize`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`.
- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-CipherSizeResultCode"></a>

### `CipherSizeResultCode`


Local detection/handling phase and implementation owner:

- `CipherOperation::output_profile` — `src/advanced/cipher/checkpoint.rs`. Enclosing match alternative: `Stage::Waiting { .. }`.


<a id="cause-CipherSnapshotAccounting"></a>

### `CipherSnapshotAccounting`


Local detection/handling phase and implementation owner:

- `Request<'a>::with_plan` — `src/advanced/cipher/snapshot.rs`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.
- `Shape::layout_bytes` — `src/advanced/cipher/snapshot.rs`.
- `Shape::allocate_layout` — `src/advanced/cipher/snapshot.rs`.
- `Storage<'_>::metadata_bytes` — `src/advanced/cipher/snapshot.rs`.
- `Storage<'_>::metadata_bytes` — `src/advanced/cipher/snapshot.rs`.
- `Storage<'_>::allocated_bytes` — `src/advanced/cipher/snapshot.rs`.
- `CipherFrame::snapshot_bytes` — `src/symmetric/cipher/snapshot.rs`.
- `Storage::allocated_bytes` — `src/symmetric/cipher/snapshot.rs`.


<a id="cause-CipherSnapshotParameterFamilyChanged"></a>

### `CipherSnapshotParameterFamilyChanged`


Local detection/handling phase and implementation owner:

- `Frame::fill_request` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing match alternative: `_`.
- `Frame::fill_snapshot` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherStreamCheckpointProgression"></a>

### `CipherStreamCheckpointProgression`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`.


<a id="cause-CipherTerminalCompletionUnproven"></a>

### `CipherTerminalCompletionUnproven`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `completion != Completion::Terminated`.


<a id="cause-CipherTerminalObservationAbsent"></a>

### `CipherTerminalObservationAbsent`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `terminal`.


<a id="cause-CipherTerminalOwnerRequiresTerminalCapture"></a>

### `CipherTerminalOwnerRequiresTerminalCapture`


Local detection/handling phase and implementation owner:

- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `self.complete()`.


<a id="cause-CipherTerminalProgression"></a>

### `CipherTerminalProgression`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `profile != OutputProfile::Buffer || m.state != MessageState::Finished || m.next_fragment != m.fragments.len() || d.phase.name() != terminal_function || d.input.is_open() || !selection.terminal_lengths( d.input.progress.input_bytes, d.input.progress.output_bytes, direction.decrypts(), d.cipher_options, )?`.


<a id="cause-CipherTicketAlreadyHeldByCaller"></a>

### `CipherTicketAlreadyHeldByCaller`


Local detection/handling phase and implementation owner:

- `CipherOperation::take_observer` — `src/advanced/cipher/negotiation.rs`. Enclosing true branch: `self.observer != OutputObserver::Session`.


<a id="cause-CipherWriterKeyAbsent"></a>

### `CipherWriterKeyAbsent`


Local detection/handling phase and implementation owner:

- `CipherOperation::writer_binding_source` — `src/advanced/cipher/extension_binding.rs`.


<a id="cause-CipherWriterPermissionAbsent"></a>

### `CipherWriterPermissionAbsent`


Local detection/handling phase and implementation owner:

- `CipherOperation::writer_binding_source` — `src/advanced/cipher/extension_binding.rs`. Enclosing true branch: `!self.extension_mutates_key() || key.writer_roles().is_none()`.
- `Source<'a>::roles` — `src/advanced/signature/binding.rs`. Enclosing match alternative: `Self::Cipher(source)`.


<a id="cause-ClassicAeadParameterMutation"></a>

### `ClassicAeadParameterMutation`


Local detection/handling phase and implementation owner:

- `AeadFrame::validate` — `src/advanced/cipher/parameters.rs`. Enclosing true branch: `!fields || self.mechanism.mechanism != self.kind || self.mechanism.pParameter != pointer || self.mechanism.ulParameterLen != length || self.iv.as_slice().get(..nonce.len()) != Some(nonce) || self.iv.as_slice()[nonce.len()..].iter().any(|b| *b != 0) || self.aad.as_slice() != self.expected_aad.as_slice()`.


<a id="cause-ClassicAeadResultDirectionMismatch"></a>

### `ClassicAeadResultDirectionMismatch`


Local detection/handling phase and implementation owner:

- `Session::classic_aead_retained` — `src/advanced/cipher/aead.rs`. Enclosing match alternative: `_`.


<a id="cause-ConsumedCipherTicket"></a>

### `ConsumedCipherTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::cipher_progress` — `src/advanced/cipher/input.rs`. Enclosing true branch: `self.id == 0`.


<a id="cause-DeclarationWithoutCipherExtension"></a>

### `DeclarationWithoutCipherExtension`


Local detection/handling phase and implementation owner:

- `captured_contract` (module-level helper) — `src/advanced/cipher/extension_binding.rs`. Enclosing false branch: `supplied.is_none()`.
- `import_contract` (module-level helper) — `src/advanced/cipher/extension_binding.rs`. Enclosing false branch: `supplied.is_none()`.


<a id="cause-DigestOidOnNonDigestOwner"></a>

### `DigestOidOnNonDigestOwner`


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `p.digest_output.is_some() || p.digest_oid.is_some() || p.digest_extension.is_some() || p.signature.is_some()`.
- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `params.digest_oid.is_some()`.


<a id="cause-ExtensionCipherFacadeIncomplete"></a>

### `ExtensionCipherFacadeIncomplete`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/cipher/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-ExtensionCipherFacadeRoute"></a>

### `ExtensionCipherFacadeRoute`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/cipher/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-ExtensionCipherRequiresAnExplicitBufferOrLengthQuery"></a>

### `ExtensionCipherRequiresAnExplicitBufferOrLengthQuery`


Local detection/handling phase and implementation owner:

- `CipherStorage::for_shape` — `src/advanced/cipher.rs`. Enclosing true branch: `matches!(selection, Selection::Extension(_)) && matches!(plan, CipherOutputPlan::MechanismBound)`.


<a id="cause-ExtensionCipherRequiresGraphSnapshotPreparation"></a>

### `ExtensionCipherRequiresGraphSnapshotPreparation`


Local detection/handling phase and implementation owner:

- `Frame::prepare_snapshot_parameters` — `src/advanced/cipher/parameters/snapshot.rs`. Enclosing match alternative: `Self::Extension(_)`.


<a id="cause-ExtensionCipherRouteDeclaration"></a>

### `ExtensionCipherRouteDeclaration`


Local detection/handling phase and implementation owner:

- `Source<'a>::check_route` — `src/advanced/cipher/extension.rs`. Enclosing true branch: `!matches`.


<a id="cause-ExtensionGraphHasNoSeparateNonceField"></a>

### `ExtensionGraphHasNoSeparateNonceField`


Local detection/handling phase and implementation owner:

- `Frame::restore_generated_iv` — `src/advanced/cipher/parameters.rs`. Enclosing match alternative: `Self::Extension(_)`.


<a id="cause-IncrementalCipherStartsWithoutQueuedInput"></a>

### `IncrementalCipherStartsWithoutQueuedInput`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `route != MessageRoute::Multipart || !parts.is_empty()`.


<a id="cause-InputPrefixRange"></a>

### `InputPrefixRange`


Local detection/handling phase and implementation owner:

- `Shadow::discard_prefix_retained` — `src/advanced/cipher/shadow.rs`. Enclosing true branch: `count > self.as_slice().len()`.


<a id="cause-LegacyAeadNonceWidth"></a>

### `LegacyAeadNonceWidth`


Local detection/handling phase and implementation owner:

- `Selection<'a>::from_record` — `src/advanced/cipher/parameters.rs`. Enclosing match alternative: `(kind, Some(CipherOptions::ChaChaIetfBytes)) if kind == CKM_CHACHA20_POLY1305 as u64 && p.tag_bits == 128`.


<a id="cause-MultipartCipherDeclarationRequired"></a>

### `MultipartCipherDeclarationRequired`


Local detection/handling phase and implementation owner:

- `begin` (module-level helper) — `src/advanced/cipher/extension_api.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeCipherAsynchronousModeUnavailable"></a>

### `NativeCipherAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `CipherOperation::drive` — `src/advanced/cipher.rs`. Enclosing true branch: `self.pending()`.
- `RecordPlan<'a>::new` — `src/advanced/cipher/checkpoint.rs`. Enclosing true branch: `pending`.
- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.


<a id="cause-NativeWriterKeyAbsent"></a>

### `NativeWriterKeyAbsent`


Local detection/handling phase and implementation owner:

- `Grant::bind` — `src/advanced/cipher/key_preparation.rs`. Enclosing match alternative: `Self::Writer(roles)`.


<a id="cause-NonAeadRecordAuthenticationFields"></a>

### `NonAeadRecordAuthenticationFields`


Local detection/handling phase and implementation owner:

- `Selection<'a>::from_record` — `src/advanced/cipher/parameters.rs`. Enclosing true branch: `p.aad.is_some() || p.tag_bits != 0`.


<a id="cause-OnlyCcmRequiresAnExplicitStreamPlaintextLength"></a>

### `OnlyCcmRequiresAnExplicitStreamPlaintextLength`


Local detection/handling phase and implementation owner:

- `begin_stream` (module-level helper) — `src/advanced/cipher/aead.rs`. Enclosing true branch: `matches!(parameters, ClassicAeadParameters::Ccm { .. }) != ccm_plaintext_length.is_some()`.


<a id="cause-RecordRouteRequiresArchivedCipherGraph"></a>

### `RecordRouteRequiresArchivedCipherGraph`


Local detection/handling phase and implementation owner:

- `Source<'a>::record_route` — `src/advanced/cipher/extension.rs`.


<a id="cause-RecordTagWidth"></a>

### `RecordTagWidth`


Local detection/handling phase and implementation owner:

- `CipherOperation::write_checkpoint_messages` — `src/advanced/cipher/checkpoint.rs`.


<a id="cause-RevocationWithoutNativeWriter"></a>

### `RevocationWithoutNativeWriter`


Local detection/handling phase and implementation owner:

- `Grant::bind` — `src/advanced/cipher/key_preparation.rs`. Enclosing true branch: `revocation.is_some()`.


<a id="cause-SelectedBlockCipherFunctionUnavailable"></a>

### `SelectedBlockCipherFunctionUnavailable`


Local detection/handling phase and implementation owner:

- `unavailable` (module-level helper) — `src/advanced/cipher/resolved_call.rs`.


<a id="cause-SelectedCipherFunctionsUnavailable"></a>

### `SelectedCipherFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/cipher/api/preparation.rs`. Enclosing true branch: `!available`.


<a id="cause-SinglePartCipherDeclarationRequired"></a>

### `SinglePartCipherDeclarationRequired`


Local detection/handling phase and implementation owner:

- `begin_single` (module-level helper) — `src/advanced/cipher/extension_api.rs`. Enclosing match alternative: `_`.


<a id="cause-StaleCipherFacadeTicket"></a>

### `StaleCipherFacadeTicket`


Local detection/handling phase and implementation owner:

- `park` (module-level helper) — `src/advanced/cipher/synchronous.rs`. Enclosing true branch: `operation.id != ticket.id`.


<a id="cause-StandaloneNativeCipherParametersRequired"></a>

### `StandaloneNativeCipherParametersRequired`


Local detection/handling phase and implementation owner:

- `CipherStorage::for_shape` — `src/advanced/cipher.rs`. Enclosing true branch: `!matches!(selection, Selection::Extension(_)) && !plain_parameters::block_cipher(mechanism) && !parameters::is_aead(mechanism)`.


<a id="cause-SynchronousAesDecryptionDidNotComplete"></a>

### `SynchronousAesDecryptionDidNotComplete`


Local detection/handling phase and implementation owner:

- `decrypt_synchronous` (module-level helper) — `src/advanced/cipher/api.rs`. Enclosing match alternative: `_`.


<a id="cause-SynchronousAesEncryptionDidNotComplete"></a>

### `SynchronousAesEncryptionDidNotComplete`


Local detection/handling phase and implementation owner:

- `encrypt_synchronous` (module-level helper) — `src/advanced/cipher/api.rs`. Enclosing match alternative: `_`.


<a id="cause-SynchronousCipherDidNotComplete"></a>

### `SynchronousCipherDidNotComplete`


Local detection/handling phase and implementation owner:

- `Session::encrypt_cipher` — `src/advanced/cipher/api.rs`. Enclosing match alternative: `_`.
- `Session::decrypt_cipher` — `src/advanced/cipher/api.rs`. Enclosing match alternative: `_`.


<a id="cause-SynchronousClassicAeadDidNotComplete"></a>

### `SynchronousClassicAeadDidNotComplete`


Local detection/handling phase and implementation owner:

- `Session::encrypt_classic_aead` — `src/advanced/cipher/aead.rs`. Enclosing match alternative: `_`.
- `Session::decrypt_classic_aead` — `src/advanced/cipher/aead.rs`. Enclosing match alternative: `_`.


<a id="cause-UnexpectedCipherGraphPacket"></a>

### `UnexpectedCipherGraphPacket`


Local detection/handling phase and implementation owner:

- `CipherOperation::describe_snapshot_with_graph` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `graph.is_some()`.

