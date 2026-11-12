Cause contracts for `ObjectPublicationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-Sp800OutputSlot"></a>

### `Sp800OutputSlot`


Local detection/handling phase and implementation owner:

- `Output::slot_handle` — `src/managed/mutations/outputs/native.rs`. Enclosing match alternative: `Self::Sp800 { data, .. }`.


<a id="cause-Sp800PublicationCapacity"></a>

### `Sp800PublicationCapacity`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_vector_output` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `publication.keys.len() == publication.keys.capacity()`.


<a id="cause-TlsOutputSlot"></a>

### `TlsOutputSlot`


Local detection/handling phase and implementation owner:

- `Output::slot_handle` — `src/managed/mutations/outputs/native.rs`. Enclosing match alternative: `Self::Tls { data, .. }`.


<a id="cause-TlsPublicationCapacity"></a>

### `TlsPublicationCapacity`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_vector_output` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `publication.keys.len() == publication.keys.capacity()`.


<a id="cause-TlsPublicationRole"></a>

### `TlsPublicationRole`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_vector_output` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Output::Tls { data, publication }`.


<a id="cause-DestinationByteAccounting"></a>

### `DestinationByteAccounting`


Local detection/handling phase and implementation owner:

- `SharedBytes::allocation_bytes` — `src/managed/mutations/identity_parts.rs`.


<a id="cause-DestinationTupleAccounting"></a>

### `DestinationTupleAccounting`


Local detection/handling phase and implementation owner:

- `PreparedParts<'a>::requested_parts` — `src/managed/mutations/identity_parts.rs`.
- `PreparedParts<'a>::allocate_parts` — `src/managed/mutations/identity_parts.rs`. Enclosing true branch: `let Some(input) = input`.


<a id="cause-GenerationOutputConsumed"></a>

### `GenerationOutputConsumed`


Local detection/handling phase and implementation owner:

- `Output::check_output_integrity` — `src/managed/mutations/outputs/native.rs`. Enclosing match alternative: `Self::Key { value, .. } | Self::Pair { value, .. } if value.is_err()`.


<a id="cause-NativeAuxiliaryOutputAbsent"></a>

### `NativeAuxiliaryOutputAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_output` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeCreationAlreadyDispatched"></a>

### `NativeCreationAlreadyDispatched`


Local detection/handling phase and implementation owner:

- `OutputsOwner::dispatch` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeDestinationOwner"></a>

### `NativeDestinationOwner`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::Destination(index)`.


<a id="cause-NativeEffectIsNotAResourceRequest"></a>

### `NativeEffectIsNotAResourceRequest`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing match alternative: `_`.
- `prepare` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing match alternative: `Need::Unwrap | Need::Kem`.


<a id="cause-NativeObjectLifetimeAbsent"></a>

### `NativeObjectLifetimeAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_native_objects` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `slot.handle != CK_INVALID_HANDLE`.


<a id="cause-NativeObjectsNotRegistered"></a>

### `NativeObjectsNotRegistered`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_native_objects` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeOutputAdmissionOwner"></a>

### `NativeOutputAdmissionOwner`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing match alternative: `(Need::Admission(index, need), Candidate::Admission(value))`.


<a id="cause-NativeOutputAdmissionState"></a>

### `NativeOutputAdmissionState`


Local detection/handling phase and implementation owner:

- `OutputsOwner::need` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputCandidateKind"></a>

### `NativeOutputCandidateKind`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputCompletionUnknown"></a>

### `NativeOutputCompletionUnknown`


Local detection/handling phase and implementation owner:

No direct construction site is present in the current sources. This public
variant remains available; the common error contract still governs handling.


<a id="cause-NativeOutputContentLayout"></a>

### `NativeOutputContentLayout`


Local detection/handling phase and implementation owner:

- `Initial::publish` — `src/managed/mutations/outputs/preparation.rs`.
- `Initial::publish` — `src/managed/mutations/outputs/preparation.rs`. Enclosing true branch: `contents.next().is_some()`.


<a id="cause-NativeOutputContentOwner"></a>

### `NativeOutputContentOwner`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::ContentReady(index)`.


<a id="cause-NativeOutputContinuationChanged"></a>

### `NativeOutputContinuationChanged`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-NativeOutputDestinationIncomplete"></a>

### `NativeOutputDestinationIncomplete`


Local detection/handling phase and implementation owner:

- `OutputsOwner::dispatch` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `!matches!(slot.state, SlotState::Ready { .. })`.


<a id="cause-NativeOutputDestinationPhase"></a>

### `NativeOutputDestinationPhase`


Local detection/handling phase and implementation owner:

- `OutputsOwner::activate_destination` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `!matches!(self.phase, Phase::DestinationReady(i) if i == index)`.


<a id="cause-NativeOutputDestinationPreparation"></a>

### `NativeOutputDestinationPreparation`


Local detection/handling phase and implementation owner:

- `OutputsOwner::activate_destination` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeOutputDestinationState"></a>

### `NativeOutputDestinationState`


Local detection/handling phase and implementation owner:

- `OutputsOwner::need` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputDispatchPhase"></a>

### `NativeOutputDispatchPhase`


Local detection/handling phase and implementation owner:

- `OutputsOwner::dispatch` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `!matches!(self.phase, Phase::NativeReady)`.


<a id="cause-NativeOutputGraphSize"></a>

### `NativeOutputGraphSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-NativeOutputLifetimeAbsent"></a>

### `NativeOutputLifetimeAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::AdmissionReady(index)`.


<a id="cause-NativeOutputListEmpty"></a>

### `NativeOutputListEmpty`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/managed/mutations/outputs/preparation.rs`. Enclosing true branch: `slots.is_empty()`.


<a id="cause-NativeOutputNeedAbsent"></a>

### `NativeOutputNeedAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`.


<a id="cause-NativeOutputOperationStopped"></a>

### `NativeOutputOperationStopped`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputOwnerAbsent"></a>

### `NativeOutputOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`.
- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing true branch: `let Need::Destination(index) = need`.
- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing true branch: `need == Need::Native`.
- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`.
- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing true branch: `registered`.


<a id="cause-NativeOutputPossessionAbsent"></a>

### `NativeOutputPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`.


<a id="cause-NativeOutputPreparationAbsent"></a>

### `NativeOutputPreparationAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::returned` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `slot.handle != CK_INVALID_HANDLE`.


<a id="cause-NativeOutputPreparationState"></a>

### `NativeOutputPreparationState`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-NativeOutputPublicationState"></a>

### `NativeOutputPublicationState`


Local detection/handling phase and implementation owner:

- `OutputsOwner::returned` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeOutputQuotaAbsent"></a>

### `NativeOutputQuotaAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::AdmissionReady(index)`.
- `OutputsOwner::returned` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeOutputReferenceIndex"></a>

### `NativeOutputReferenceIndex`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_reference` — `src/managed/mutations/outputs.rs`.


<a id="cause-NativeOutputReferenceOwner"></a>

### `NativeOutputReferenceOwner`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::Admission(index) | Phase::Content(index)`.


<a id="cause-NativeOutputReferencePreparation"></a>

### `NativeOutputReferencePreparation`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::AdmissionReady(index)`.


<a id="cause-NativeOutputReferenceUnavailable"></a>

### `NativeOutputReferenceUnavailable`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_reference` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputRestorationState"></a>

### `NativeOutputRestorationState`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_vector_output` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `let Err(error) = assembled`.


<a id="cause-NativeOutputReturnPhase"></a>

### `NativeOutputReturnPhase`


Local detection/handling phase and implementation owner:

- `OutputsOwner::returned` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `!matches!(self.phase, Phase::InFlight)`.


<a id="cause-NativeOutputSearchOwner"></a>

### `NativeOutputSearchOwner`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing match alternative: `(Need::Search(_), Candidate::Search(value))`.


<a id="cause-NativeOutputSearchPhase"></a>

### `NativeOutputSearchPhase`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing match alternative: `(Need::Search(_), Candidate::Search(value))`.


<a id="cause-NativeOutputSlot"></a>

### `NativeOutputSlot`


Local detection/handling phase and implementation owner:

- `Output::slot_handle` — `src/managed/mutations/outputs/native.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputSlotAllocation"></a>

### `NativeOutputSlotAllocation`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-NativeOutputSlotSize"></a>

### `NativeOutputSlotSize`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/managed/mutations/outputs/preparation.rs`.
- `Initial::publish` — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-NativeOutputVectorKind"></a>

### `NativeOutputVectorKind`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_vector_output` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeOutputsIncomplete"></a>

### `NativeOutputsIncomplete`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_reference` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-NativePublicationAccounting"></a>

### `NativePublicationAccounting`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/managed/mutations/outputs/preparation.rs`.
- `Initial::publish` — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-NativePublicationAllocation"></a>

### `NativePublicationAllocation`


Local detection/handling phase and implementation owner:

- `Initial::allocate` — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-NativePublicationCapacity"></a>

### `NativePublicationCapacity`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_native_objects` — `src/managed/mutations/outputs.rs`. Enclosing true branch: `objects.len() == objects.capacity()`.


<a id="cause-OutputCleanupCount"></a>

### `OutputCleanupCount`


Local detection/handling phase and implementation owner:

- `Initial::requested` — `src/managed/mutations/outputs/preparation.rs`.


<a id="cause-PairOutputSlot"></a>

### `PairOutputSlot`


Local detection/handling phase and implementation owner:

- `Output::slot_handle` — `src/managed/mutations/outputs/native.rs`. Enclosing match alternative: `Self::Pair { handles, .. }`.


<a id="cause-RequestedObservationPreparationAbsent"></a>

### `RequestedObservationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::AdmissionReady(index)`.


<a id="cause-RequestedObservationSelectionAbsent"></a>

### `RequestedObservationSelectionAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::advance` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `Phase::AdmissionReady(index)`.
- `run` (module-level helper) — `src/managed/mutations/outputs/runner.rs`. Enclosing match alternative: `Need::Admission(index, _)`.


<a id="cause-TransportOutputConsumed"></a>

### `TransportOutputConsumed`


Local detection/handling phase and implementation owner:

- `Output::check_output_integrity` — `src/managed/mutations/outputs/native.rs`. Enclosing match alternative: `Self::Transport { value, .. } if value.is_err()`.


<a id="cause-UnobservedNativeIdentityAbsent"></a>

### `UnobservedNativeIdentityAbsent`


Local detection/handling phase and implementation owner:

- `OutputsOwner::take_reference` — `src/managed/mutations/outputs.rs`. Enclosing match alternative: `SlotState::Unobserved`.
