Cause contracts for `KeyAdmissionRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AesKekAdmissionResultOwnerMismatch"></a>

### `AesKekAdmissionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `aes_kek_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-AesKeyRequired"></a>

### `AesKeyRequired`


Local detection/handling phase and implementation owner:

- `require_aes` (module-level helper) — `src/symmetric/keys.rs`. Enclosing false branch: `matches!( algorithm, SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256 )`.
- `AdvancedSession::find_aes_key` — `src/advanced/admission/api.rs`. Enclosing true branch: `!matches!( spec.algorithm, crate::SymmetricAlgorithm::Aes128 | crate::SymmetricAlgorithm::Aes192 | crate::SymmetricAlgorithm::Aes256 )`.
- `AdvancedSession::generate_aes_key` — `src/advanced/admission/generation.rs`. Enclosing true branch: `!matches!( spec.algorithm, crate::SymmetricAlgorithm::Aes128 | crate::SymmetricAlgorithm::Aes192 | crate::SymmetricAlgorithm::Aes256 )`.


<a id="cause-MlKemCreationResultOwnerMismatch"></a>

### `MlKemCreationResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `generate_kem_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-MlKemInitialPreparationChanged"></a>

### `MlKemInitialPreparationChanged`


Local detection/handling phase and implementation owner:

- `Prepared::attach_retained` — `src/advanced/admission/pair/initial.rs`. Enclosing match alternative: `_`.
- `PreparedKemPair::attach_initial_retained` — `src/crypto/kem/owned/preparation.rs`. Enclosing true branch: `!matches!(self.public, PublicState::AwaitingStorage) || candidate.public.parameter_set() != self.source.parameter_set()`.


<a id="cause-MlKemPairSpkiMismatch"></a>

### `MlKemPairSpkiMismatch`


Local detection/handling phase and implementation owner:

- `Admission::finish_terminal` — `src/advanced/admission/publication.rs`. Enclosing true branch: `let Err(cause) = result`.


<a id="cause-MlKemSelectionResultOwnerMismatch"></a>

### `MlKemSelectionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `find_kem_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-PqcAdmissionResultOwnerMismatch"></a>

### `PqcAdmissionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `pqc_pair_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-PqcInitialPreparationChanged"></a>

### `PqcInitialPreparationChanged`


Local detection/handling phase and implementation owner:

- `Prepared::attach_retained` — `src/advanced/admission/pair/initial.rs`. Enclosing match alternative: `_`.
- `PreparedPqcPair::attach_initial_retained` — `src/crypto/pqc/owned/preparation.rs`. Enclosing true branch: `!matches!(self.public, PublicState::AwaitingStorage)`.


<a id="cause-PqcPairSpkiMismatch"></a>

### `PqcPairSpkiMismatch`


Local detection/handling phase and implementation owner:

- `Admission::finish_terminal` — `src/advanced/admission/publication.rs`. Enclosing true branch: `let Err(cause) = result`.


<a id="cause-RsaTransportResultOwnerMismatch"></a>

### `RsaTransportResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `rsa_transport_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.
- `PreparedClassicalPair::finish_rsa_transport` — `src/crypto/signing/owned/transport.rs`. Enclosing true branch: `!self.is_rsa_transport()`.


<a id="cause-AdmissionAsynchronousVersion"></a>

### `AdmissionAsynchronousVersion`


Local detection/handling phase and implementation owner:

- `Admission::accept_async` — `src/advanced/admission/completion.rs`. Enclosing true branch: `result.ulVersion != 0`.


<a id="cause-AdmissionAttributesAbsent"></a>

### `AdmissionAttributesAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`.


<a id="cause-AdmissionDiagnosticByteCount"></a>

### `AdmissionDiagnosticByteCount`


Local detection/handling phase and implementation owner:

- `Storage::bind` — `src/advanced/admission/initial.rs`.


<a id="cause-AdmissionFailedExplicitCleanupRequired"></a>

### `AdmissionFailedExplicitCleanupRequired`


Local detection/handling phase and implementation owner:

- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing true branch: `self.stage == Stage::Failed`.


<a id="cause-AdmissionFramePhase"></a>

### `AdmissionFramePhase`


Local detection/handling phase and implementation owner:

- `Frames::check_stage` — `src/advanced/admission/active.rs`. Enclosing false branch: `matches`.


<a id="cause-AdmissionFunctionsUnavailable"></a>

### `AdmissionFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `require_observation_functions` (module-level helper) — `src/advanced/admission/validation.rs`. Enclosing true branch: `t.C_GetAttributeValue.is_none()`.


<a id="cause-AdmissionIncomplete"></a>

### `AdmissionIncomplete`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-AdmissionMetadataAllocation"></a>

### `AdmissionMetadataAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/advanced/admission/initial.rs`.


<a id="cause-AdmissionMetadataByteCount"></a>

### `AdmissionMetadataByteCount`


Local detection/handling phase and implementation owner:

- `handle_bytes` (module-level helper) — `src/advanced/admission/initial.rs`.
- `add` (module-level helper) — `src/advanced/admission/initial.rs`.
- `Plan<'a>::new` — `src/advanced/admission/initial.rs`. Enclosing false branch: `selectors == 0`.
- `Storage::allocated_bytes` — `src/advanced/admission/initial.rs`.
- `Storage::bind` — `src/advanced/admission/initial.rs`.
- `Admission::new` — `src/advanced/admission/preparation.rs`.
- `Admission::new` — `src/advanced/admission/preparation.rs`.
- `Admission::new` — `src/advanced/admission/preparation.rs`.
- `Admission::new` — `src/advanced/admission/preparation.rs`.
- `Admission::new` — `src/advanced/admission/preparation.rs`.
- `Admission::new` — `src/advanced/admission/preparation.rs`.


<a id="cause-AdmissionNotActive"></a>

### `AdmissionNotActive`


Local detection/handling phase and implementation owner:

- `Admission::function` — `src/advanced/admission/observation.rs`. Enclosing match alternative: `_`.


<a id="cause-AdmissionNotPending"></a>

### `AdmissionNotPending`


Local detection/handling phase and implementation owner:

- `Admission::joined_capacity` — `src/advanced/admission/rejoin.rs`. Enclosing true branch: `!self.pending`.


<a id="cause-AdmissionObservationPlanExceeded"></a>

### `AdmissionObservationPlanExceeded`


Local detection/handling phase and implementation owner:

- `ReadFrame::attach` — `src/advanced/admission/read.rs`. Enclosing true branch: `self.retained.len() == self.retained.capacity()`.
- `ReadPlans::select` — `src/advanced/admission/read/preparation.rs`.
- `ReadPlans::select` — `src/advanced/admission/read/preparation.rs`. Enclosing true branch: `!matches || kinds.next().is_some()`.


<a id="cause-AdmissionPreparationChanged"></a>

### `AdmissionPreparationChanged`


Local detection/handling phase and implementation owner:

- `PublicDerCandidate::encode` — `src/crypto/integer_key.rs`. Enclosing true branch: `length != self.need.length`.
- `Admission::attach_resource` — `src/advanced/admission/observation.rs`. Enclosing true branch: `self.pending`.
- `Admission::attach_resource` — `src/advanced/admission/observation.rs`. Enclosing match alternative: `_`.
- `Admission::attach_resource` — `src/advanced/admission/observation.rs`. Enclosing match alternative: `_`.
- `PreparedPair::attach_observation` — `src/advanced/admission/pair_policy.rs`. Enclosing match alternative: `_`.
- `PreparedClassicalPair::attach_observation` — `src/crypto/signing/owned.rs`. Enclosing true branch: `self.observation_need() != Some(candidate.need())`.
- `PreparedClassicalPair::validate` — `src/crypto/signing/owned.rs`. Enclosing true branch: `!private && matches!(&self.source, PairSource::Generation { .. })`.


<a id="cause-AdmissionProtectionObservationsAbsent"></a>

### `AdmissionProtectionObservationsAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Symmetric { spec, publication }`.


<a id="cause-AdmissionSearchFunctionsUnavailable"></a>

### `AdmissionSearchFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::key_admission_search` — `src/session/references.rs`. Enclosing true branch: `required && (state.native.table.C_FindObjectsInit.is_none() || state.native.table.C_FindObjects.is_none() || state.native.table.C_FindObjectsFinal.is_none())`.
- `check_initial_functions` (module-level helper) — `src/advanced/admission/validation.rs`. Enclosing true branch: `state.native.table.C_FindObjectsInit.is_none() || state.native.table.C_FindObjects.is_none() || state.native.table.C_FindObjectsFinal.is_none()`.
- `Admission::check_search_functions` — `src/advanced/admission/validation.rs`. Enclosing true branch: `requires_search && (s.native.table.C_FindObjectsInit.is_none() || s.native.table.C_FindObjects.is_none() || s.native.table.C_FindObjectsFinal.is_none())`.


<a id="cause-AdmissionSelectedHandleAbsent"></a>

### `AdmissionSelectedHandleAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing true branch: `self.found.len() != 1`.


<a id="cause-AgreementPairResultOwnerMismatch"></a>

### `AgreementPairResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `agreement_pair_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeDescriptorChanged"></a>

### `AttributeDescriptorChanged`


Local detection/handling phase and implementation owner:

- `ReadFrame::validate_identity` — `src/advanced/admission/read.rs`. Enclosing true branch: `self.attrs.len() != self.indices.len()`.
- `ReadFrame::validate_identity` — `src/advanced/admission/read.rs`. Enclosing true branch: `index >= self.kinds.len() || attr.r#type != self.kinds[index]`.
- `ReadFrame::validate_identity` — `src/advanced/admission/read.rs`. Enclosing true branch: `attr.pValue != pointer`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing true branch: `self.attrs.len() != self.indices.len()`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing true branch: `index >= self.kinds.len() || attr.r#type != self.kinds[index]`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing true branch: `!attr.pValue.is_null()`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing true branch: `attr.pValue != buffer.value.pointer()`.


<a id="cause-AttributeFrameAbsent"></a>

### `AttributeFrameAbsent`


Local detection/handling phase and implementation owner:

- `Admission::accept_required` — `src/advanced/admission/completion.rs`.
- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `Stage::Required | Stage::PublicMaterial | Stage::History | Stage::Allowed | Stage::Properties`.
- `Admission::attach_resource` — `src/advanced/admission/observation.rs`. Enclosing match alternative: `ResourceCandidate::Read(candidate) if self.reading_attributes()`.
- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing true branch: `name == "C_GetAttributeValue"`.
- `ReadPlans::select` — `src/advanced/admission/read/preparation.rs`. Enclosing match alternative: `_`.
- `ReadOwner::active_mut` — `src/advanced/admission/read/preparation.rs`. Enclosing match alternative: `Self::Planned(_)`.


<a id="cause-AttributeLengthExceedsAllocatedValueBuffer"></a>

### `AttributeLengthExceedsAllocatedValueBuffer`


Local detection/handling phase and implementation owner:

- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing true branch: `attr.ulValueLen as u128 > buffer.value.capacity as u128`.


<a id="cause-AttributeOwnerAbsent"></a>

### `AttributeOwnerAbsent`


Local detection/handling phase and implementation owner:

- `ReadFrame::validate_identity` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadStage::Values`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadStage::Values`.
- `ReadFrame::attach` — `src/advanced/admission/read.rs`. Enclosing match alternative: `( ReadStage::ValuesReceived { rv, accepted }, PreparedStorage::Value { mut bytes, decoded }, )`.
- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`.
- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`.
- `observe_batch` (module-level helper) — `src/attribute_values/read/runner.rs`.
- `observe_batch` (module-level helper) — `src/attribute_values/read/runner.rs`.


<a id="cause-AttributePreparationChanged"></a>

### `AttributePreparationChanged`


Local detection/handling phase and implementation owner:

- `ReadFrame::attach` — `src/advanced/admission/read.rs`. Enclosing true branch: `!self.need().is_some_and(|need| need.same(candidate.need()))`.
- `ReadFrame::attach` — `src/advanced/admission/read.rs`. Enclosing match alternative: `Slot::Accepted`.
- `ReadFrame::attach` — `src/advanced/admission/read.rs`. Enclosing match alternative: `_`.
- `ReadOwner::attach` — `src/advanced/admission/read/preparation.rs`. Enclosing true branch: `!self.need().is_some_and(|need| need.same(candidate.need()))`.
- `ReadOwner::attach` — `src/advanced/admission/read/preparation.rs`. Enclosing match alternative: `Self::Planned(_)`.
- `FlatOwner::attach` — `src/attribute_values/read/owner.rs`. Enclosing true branch: `self.need() != Some(expected)`.


<a id="cause-AttributeProjectionStorageSize"></a>

### `AttributeProjectionStorageSize`


Local detection/handling phase and implementation owner:

- `ReadFrame::take` — `src/advanced/admission/read.rs`.
- `AttributeSnapshot::from_credited_parts` — `src/attributes/owned/resident/export.rs`.
- `AttributeSnapshot::requested` — `src/attributes/owned/resident/export.rs`.
- `AttributeSnapshot::allocated_bytes` — `src/attributes/owned/resident/export.rs`.
- `AttributeSnapshot::map_retaining` — `src/attributes/owned/resident/export.rs`.
- `AttributeSnapshot::map_retaining` — `src/attributes/owned/resident/export.rs`.
- `Storage::requested` — `src/attributes/owned/resident/preparation.rs`.
- `Storage::allocated_bytes` — `src/attributes/owned/resident/preparation.rs`.


<a id="cause-AttributeReadDetachmentDeferred"></a>

### `AttributeReadDetachmentDeferred`


Local detection/handling phase and implementation owner:

- `Stage::check_detachment` — `src/advanced/admission/progression.rs`. Enclosing true branch: `matches!( self, Self::Required | Self::RequiredLocal { .. } | Self::PublicMaterial | Self::History | Self::Allowed | Self::Properties )`.


<a id="cause-AttributeReadIncomplete"></a>

### `AttributeReadIncomplete`


Local detection/handling phase and implementation owner:

- `ReadFrame::validate_identity` — `src/advanced/admission/read.rs`. Enclosing match alternative: `_`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`. Enclosing match alternative: `_`.
- `ReadFrame::take` — `src/advanced/admission/read.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-AttributeSizingOwnerShared"></a>

### `AttributeSizingOwnerShared`


Local detection/handling phase and implementation owner:

- `ReadFrame::accept` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadStage::Size`.


<a id="cause-AttributeValueAlreadyConsumed"></a>

### `AttributeValueAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `ReadFrame::take` — `src/advanced/admission/read.rs`.


<a id="cause-BaseEnvelopeAbsent"></a>

### `BaseEnvelopeAbsent`


Local detection/handling phase and implementation owner:

- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing true branch: `slot.is_none()`.


<a id="cause-BaseMechanismReportAbsent"></a>

### `BaseMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::DerivationBase(prepared)`.


<a id="cause-BaseObjectReportAbsent"></a>

### `BaseObjectReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::DerivationBase(prepared)`.


<a id="cause-ClassicalAdmissionResultOwnerMismatch"></a>

### `ClassicalAdmissionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `classical_pair_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-ClassicalMaterialIsPartOfItsStructuralObservation"></a>

### `ClassicalMaterialIsPartOfItsStructuralObservation`


Local detection/handling phase and implementation owner:

- `PreparedPair::observe_public` — `src/advanced/admission/pair_policy.rs`. Enclosing match alternative: `Self::Classical(_)`.


<a id="cause-ClassicalPairSpkiMismatch"></a>

### `ClassicalPairSpkiMismatch`


Local detection/handling phase and implementation owner:

- `Admission::finish_terminal` — `src/advanced/admission/publication.rs`. Enclosing true branch: `let Err(cause) = result`.


<a id="cause-CreationDestinationOwner"></a>

### `CreationDestinationOwner`


Local detection/handling phase and implementation owner:

- `KeyPolicy::generation_identity` — `src/advanced/admission/policy.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationDispatchStage"></a>

### `CreationDispatchStage`


Local detection/handling phase and implementation owner:

- `Generation::dispatch` — `src/advanced/admission/generation.rs`. Enclosing false branch: `stage == Stage::Destroy`.


<a id="cause-CreationTicketAbsent"></a>

### `CreationTicketAbsent`


Local detection/handling phase and implementation owner:

- `Generation::generated` — `src/advanced/admission/generation.rs`.
- `Generation::cleaned` — `src/advanced/admission/generation.rs`.


<a id="cause-CreationTicketAbsentForCleanup"></a>

### `CreationTicketAbsentForCleanup`


Local detection/handling phase and implementation owner:

- `Generation::dispatch` — `src/advanced/admission/generation.rs`. Enclosing true branch: `stage == Stage::Destroy`.


<a id="cause-DerivationBasePublicationClass"></a>

### `DerivationBasePublicationClass`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `_`.


<a id="cause-DerivationBaseResultOwnerMismatch"></a>

### `DerivationBaseResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `derivation_base_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-DestinationOwnerAbsent"></a>

### `DestinationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `CreationDestinations::finish` — `src/advanced/admission/destination.rs`.


<a id="cause-DestinationOwnerAllocation"></a>

### `DestinationOwnerAllocation`


Local detection/handling phase and implementation owner:

- `Plan<'a>::allocate` — `src/advanced/admission/destination/preparation.rs`.


<a id="cause-DestinationOwnerSize"></a>

### `DestinationOwnerSize`


Local detection/handling phase and implementation owner:

- `sum` (module-level helper) — `src/advanced/admission/destination/preparation.rs`.
- `Plan<'a>::new` — `src/advanced/admission/destination/preparation.rs`.
- `Storage::allocated_bytes` — `src/advanced/admission/destination/preparation.rs`.
- `Storage::allocated_bytes` — `src/advanced/admission/destination/preparation.rs`. Enclosing match alternative: `Slot::Prepared { evaluation, template, attrs, .. }`.


<a id="cause-DestinationPreparationState"></a>

### `DestinationPreparationState`


Local detection/handling phase and implementation owner:

- `Storage::allocated_bytes` — `src/advanced/admission/destination/preparation.rs`. Enclosing match alternative: `_`.


<a id="cause-DestinationReportAbsent"></a>

### `DestinationReportAbsent`


Local detection/handling phase and implementation owner:

- `CreationDestinations::take` — `src/advanced/admission/destination.rs`.


<a id="cause-DestinationReportIncomplete"></a>

### `DestinationReportIncomplete`


Local detection/handling phase and implementation owner:

- `CreationDestinations::take` — `src/advanced/admission/destination.rs`.
- `CreationDestinations::take` — `src/advanced/admission/destination.rs`. Enclosing match alternative: `_`.


<a id="cause-DestinationTransition"></a>

### `DestinationTransition`


Local detection/handling phase and implementation owner:

- `CreationDestinations::activate` — `src/advanced/admission/destination.rs`. Enclosing match alternative: `_`.
- `CreationDestinations::finish` — `src/advanced/admission/destination.rs`.


<a id="cause-DuplicateAdmissionCompletion"></a>

### `DuplicateAdmissionCompletion`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `_`.
- `ReadFrame::accept` — `src/advanced/admission/read.rs`. Enclosing true branch: `!matches!(self.stage, ReadStage::Size | ReadStage::Values)`.


<a id="cause-DuplicateAttribute"></a>

### `DuplicateAttribute`


Local detection/handling phase and implementation owner:

- `ObjectAdmission::validate_public_selection` — `src/object_controls.rs`. Enclosing true branch: `self.public_attributes[..index].contains(field)`.
- `PlansStorage::allocate` — `src/advanced/admission/read/preparation.rs`. Enclosing true branch: `kinds.len() != count || kinds .iter() .enumerate() .any(|(i, k)| kinds[..i].contains(k))`.
- `Recipe<'_>::validate` — `src/attributes/owned/resident/recipe.rs`. Enclosing true branch: `(0..index).any(|previous| self.field(previous) == self.field(index))`.


<a id="cause-DuplicateNativeGeneration"></a>

### `DuplicateNativeGeneration`


Local detection/handling phase and implementation owner:

- `Generation::dispatch` — `src/advanced/admission/generation.rs`. Enclosing true branch: `self.storage != StorageUse::Prepared`.


<a id="cause-FamilyInputAbsent"></a>

### `FamilyInputAbsent`


Local detection/handling phase and implementation owner:

- `Input<'_>::symmetric_metadata_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Symmetric(None)`.
- `Input<'_>::requested_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Verification(value)`.
- `Input<'_>::requested_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Base(value)`.
- `Input<'_>::requested_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Classical(value)`.
- `Input<'_>::requested_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Kem(value)`.
- `Input<'_>::requested_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Pqc(value)`.
- `Input<'_>::requested_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Agreement(value)`.
- `Input<'_>::allocate` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.
- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Symmetric`.
- `Input<'_>::generation_identity` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.
- `Input<'_>::generation_mechanism` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.
- `Input<'_>::generation_templates_as` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.


<a id="cause-GeneratedPairHandles"></a>

### `GeneratedPairHandles`


Local detection/handling phase and implementation owner:

- `Admission::after_object_observations` — `src/advanced/admission/observation.rs`. Enclosing true branch: `pair.public_handle == self.found[0]`.


<a id="cause-GenerationCandidateAbsent"></a>

### `GenerationCandidateAbsent`


Local detection/handling phase and implementation owner:

- `Prepared::transfer` — `src/advanced/admission/generation/preparation.rs`.


<a id="cause-GenerationFixedAllocationLength"></a>

### `GenerationFixedAllocationLength`


Local detection/handling phase and implementation owner:

- `stable_values` (module-level helper) — `src/advanced/admission/generation.rs`. Enclosing true branch: `owned.len() != N`.


<a id="cause-GenerationFunctionsUnavailable"></a>

### `GenerationFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `check_initial_functions` (module-level helper) — `src/advanced/admission/validation.rs`. Enclosing true branch: `!available`.


<a id="cause-GenerationInputChanged"></a>

### `GenerationInputChanged`


Local detection/handling phase and implementation owner:

- `Generation::inspect_returned_inputs` — `src/advanced/admission/generation.rs`.


<a id="cause-GenerationModuleUnavailable"></a>

### `GenerationModuleUnavailable`


Local detection/handling phase and implementation owner:

- `Publication::publish` — `src/advanced/admission/publication.rs`.


<a id="cause-GenerationOwnerAbsent"></a>

### `GenerationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `Admission::accept_async` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `Stage::Generate`.
- `Admission::function` — `src/advanced/admission/observation.rs`. Enclosing match alternative: `Stage::Generate`.
- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing true branch: `self.stage == Stage::Generate`.
- `Admission::accept_joined` — `src/advanced/admission/rejoin.rs`. Enclosing true branch: `self.stage == Stage::Generate`.
- `Admission::accept_joined` — `src/advanced/admission/rejoin.rs`. Enclosing match alternative: `Stage::Generate`.


<a id="cause-GenerationPolicy"></a>

### `GenerationPolicy`


Local detection/handling phase and implementation owner:

- `Input<'_>::generation_identity` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Verification(_)`.
- `Input<'_>::generation_mechanism` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Verification(_)`.
- `Input<'_>::generation_templates_as` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Verification(_)`.
- `KeyPolicy::generation_mechanism` — `src/advanced/admission/policy.rs`. Enclosing match alternative: `_`.
- `KeyPolicy::generation_templates_as` — `src/advanced/admission/policy.rs`. Enclosing match alternative: `_`.


<a id="cause-GenerationPublicationAbsent"></a>

### `GenerationPublicationAbsent`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `Stage::Generate`.


<a id="cause-GenerationPublicationArity"></a>

### `GenerationPublicationArity`


Local detection/handling phase and implementation owner:

- `Publication::publish` — `src/advanced/admission/publication.rs`. Enclosing true branch: `self.published != 0 || handles.len() != self.identities.iter().flatten().count()`.


<a id="cause-GenerationPublicationIncomplete"></a>

### `GenerationPublicationIncomplete`


Local detection/handling phase and implementation owner:

- `Publication::objects` — `src/advanced/admission/publication.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-GenerationRetainedMetadataSize"></a>

### `GenerationRetainedMetadataSize`


Local detection/handling phase and implementation owner:

- `sum` (module-level helper) — `src/advanced/admission/generation/preparation.rs`.
- `Plan::new` — `src/advanced/admission/generation/preparation.rs`.
- `Plan::allocate` — `src/advanced/admission/generation/preparation.rs`.


<a id="cause-GenerationStableAllocation"></a>

### `GenerationStableAllocation`


Local detection/handling phase and implementation owner:

- `scalar_storage` (module-level helper) — `src/advanced/admission/generation.rs`.


<a id="cause-GenerationTemplateArity"></a>

### `GenerationTemplateArity`


Local detection/handling phase and implementation owner:

- `Plan::allocate` — `src/advanced/admission/generation/preparation.rs`. Enclosing true branch: `usize::from(private.is_some()) + 1 != self.count`.


<a id="cause-GenerationTicketAbsent"></a>

### `GenerationTicketAbsent`


Local detection/handling phase and implementation owner:

- `Prepared::transfer` — `src/advanced/admission/generation/preparation.rs`. Enclosing true branch: `prepared.ticket.is_none()`.


<a id="cause-GenerationTicketAlreadyPrepared"></a>

### `GenerationTicketAlreadyPrepared`


Local detection/handling phase and implementation owner:

- `Prepared::prepare_ticket` — `src/advanced/admission/generation/preparation.rs`. Enclosing true branch: `self.ticket.is_some()`.


<a id="cause-HistoryObservationOwnerAbsent"></a>

### `HistoryObservationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `Stage::History`.
- `Admission::retain_history_observation` — `src/advanced/admission/validation.rs`. Enclosing match alternative: `_`.


<a id="cause-InitialFamilyPreparationChanged"></a>

### `InitialFamilyPreparationChanged`


Local detection/handling phase and implementation owner:

- `Input<'_>::allocated_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.
- `Input<'_>::bind` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.
- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Symmetric`.
- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Verification(owner)`.
- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Base { owner, slot }`.
- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing match alternative: `_`.


<a id="cause-InitialFamilySize"></a>

### `InitialFamilySize`


Local detection/handling phase and implementation owner:

- `Input<'_>::with_envelope` — `src/advanced/admission/input.rs`.


<a id="cause-IntroducedSymmetricResultOwnerMismatch"></a>

### `IntroducedSymmetricResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `introduced_symmetric_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-InvalidOrRepeatedObjectHandle"></a>

### `InvalidOrRepeatedObjectHandle`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `Err(managed::search::CollectionError::Malformed)`.
- `collection_error` (module-level helper) — `src/managed/search/owned/resident.rs`. Enclosing match alternative: `CollectionError::Malformed`.


<a id="cause-JoinedAdmissionOutputContractUnresolved"></a>

### `JoinedAdmissionOutputContractUnresolved`


Local detection/handling phase and implementation owner:

- `Admission::joined_capacity` — `src/advanced/admission/rejoin.rs`. Enclosing match alternative: `_`.
- `Admission::accept_joined` — `src/advanced/admission/rejoin.rs`. Enclosing match alternative: `_`.


<a id="cause-MechanismAdmissionReportAbsent"></a>

### `MechanismAdmissionReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::VerificationPublic { prepared, .. }`.
- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Pair(pair)`.


<a id="cause-MechanismProjectionAbsent"></a>

### `MechanismProjectionAbsent`


Local detection/handling phase and implementation owner:

- `ReadFrame::take_mechanisms` — `src/advanced/admission/read.rs`. Enclosing match alternative: `_`.
- `LegacyOwner::result` — `src/attributes/owned/resident.rs`. Enclosing false branch: `self.values.len() != 1 || self.kinds.len() != 1`.


<a id="cause-MechanismProjectionAllocation"></a>

### `MechanismProjectionAllocation`


Local detection/handling phase and implementation owner:

- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Value { length, decode_mechanisms, .. }`.


<a id="cause-MechanismProjectionPhase"></a>

### `MechanismProjectionPhase`


Local detection/handling phase and implementation owner:

- `ReadFrame::take_mechanisms` — `src/advanced/admission/read.rs`. Enclosing true branch: `!self.decode_mechanisms || !matches!(self.stage, ReadStage::Consumed)`.


<a id="cause-MechanismProjectionStorageSize"></a>

### `MechanismProjectionStorageSize`


Local detection/handling phase and implementation owner:

- `decoded_bytes` (module-level helper) — `src/advanced/admission/read.rs`.
- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Value { length, decode_mechanisms, .. }`.
- `ReadFrame::attach` — `src/advanced/admission/read.rs`. Enclosing true branch: `self.decode_mechanisms`.
- `MechanismValues::decode_prepared` — `src/attributes/owned/resident/export.rs`.
- `MechanismCopy::prepare` — `src/attributes/owned/resident/export.rs`.
- `MechanismCopy::prepare` — `src/attributes/owned/resident/export.rs`.


<a id="cause-ObjectAdmissionMetadataByteCount"></a>

### `ObjectAdmissionMetadataByteCount`


Local detection/handling phase and implementation owner:

- `Admission::new` — `src/advanced/admission/preparation.rs`.


<a id="cause-ObjectAdmissionReportAbsent"></a>

### `ObjectAdmissionReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Symmetric { spec, publication }`.
- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::VerificationPublic { prepared, .. }`.
- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Pair(pair)`.


<a id="cause-ObjectReportAbsent"></a>

### `ObjectReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::complete_object_observations` — `src/advanced/admission/completion.rs`.


<a id="cause-ObjectSearchDetachmentDeferred"></a>

### `ObjectSearchDetachmentDeferred`


Local detection/handling phase and implementation owner:

- `Stage::check_detachment` — `src/advanced/admission/progression.rs`. Enclosing true branch: `self == Self::Find`.


<a id="cause-OwnedAttributeAllocation"></a>

### `OwnedAttributeAllocation`


Local detection/handling phase and implementation owner:

- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Sizes(plan)`.
- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Value { length, decode_mechanisms, .. }`.
- `prepare_frame` (module-level helper) — `src/advanced/admission/read/preparation.rs`.


<a id="cause-OwnedAttributeMetadata"></a>

### `OwnedAttributeMetadata`


Local detection/handling phase and implementation owner:

- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Sizes(plan)`.
- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Sizes(plan)`.
- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Value { length, decode_mechanisms, .. }`.
- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `ReadNeed::Sizes(plan)`.
- `ReadPlans::requested_bytes` — `src/advanced/admission/read/preparation.rs`. Enclosing true branch: `count != 0`.
- `prepare_frame` (module-level helper) — `src/advanced/admission/read/preparation.rs`.
- `prepare_frame` (module-level helper) — `src/advanced/admission/read/preparation.rs`.
- `prepare_frame` (module-level helper) — `src/advanced/admission/read/preparation.rs`.
- `plan_bytes` (module-level helper) — `src/advanced/admission/read/preparation.rs`.
- `PlansStorage::allocated_bytes` — `src/advanced/admission/read/preparation.rs`.
- `Recipe<'a>::shape` — `src/advanced/admission/read/recipe.rs`.


<a id="cause-OwnedAttributeMetadataAllocation"></a>

### `OwnedAttributeMetadataAllocation`


Local detection/handling phase and implementation owner:

- `PlansStorage::allocate` — `src/advanced/admission/read/preparation.rs`.


<a id="cause-OwnedAttributeRequest"></a>

### `OwnedAttributeRequest`


Local detection/handling phase and implementation owner:

- `Recipe<'a>::shape` — `src/advanced/admission/read/recipe.rs`. Enclosing true branch: `count == 0 && matches!(self.kind, Kind::Required)`.


<a id="cause-PairEnvelopeAbsent"></a>

### `PairEnvelopeAbsent`


Local detection/handling phase and implementation owner:

- `Candidate::finish` — `src/advanced/admission/input.rs`. Enclosing true branch: `frame.is_none()`.
- `PairFrameStorage::finish` — `src/advanced/admission/pair.rs`.


<a id="cause-PairFamilyAbsent"></a>

### `PairFamilyAbsent`


Local detection/handling phase and implementation owner:

- `PairFrameStorage::finish` — `src/advanced/admission/pair.rs`.


<a id="cause-PairHistoryOwnerAbsent"></a>

### `PairHistoryOwnerAbsent`


Local detection/handling phase and implementation owner:

- `PreparedPair::observe_history` — `src/advanced/admission/pair_policy.rs`. Enclosing match alternative: `_`.


<a id="cause-PairInitialCandidateAbsent"></a>

### `PairInitialCandidateAbsent`


Local detection/handling phase and implementation owner:

- `Prepared::attach_retained` — `src/advanced/admission/pair/initial.rs`.
- `PreparedKemPair::attach_initial_retained` — `src/crypto/kem/owned/preparation.rs`.
- `PreparedPqcPair::attach_initial_retained` — `src/crypto/pqc/owned/preparation.rs`.


<a id="cause-PairInitialPreparationAbsent"></a>

### `PairInitialPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Prepared::attach_retained` — `src/advanced/admission/pair/initial.rs`. Enclosing match alternative: `_`.


<a id="cause-PairInitialPreparationChanged"></a>

### `PairInitialPreparationChanged`


Local detection/handling phase and implementation owner:

- `Plan::bind` — `src/advanced/admission/pair/initial.rs`. Enclosing match alternative: `_`.
- `Prepared::attach_retained` — `src/advanced/admission/pair/initial.rs`. Enclosing match alternative: `_`.


<a id="cause-PairOwnerStorageAccounting"></a>

### `PairOwnerStorageAccounting`


Local detection/handling phase and implementation owner:

- `PairFrame::requested_bytes` — `src/advanced/admission/pair.rs`.
- `PairFrameStorage::finish` — `src/advanced/admission/pair.rs`. Enclosing true branch: `candidate.family_inline != family.credited_inline_bytes()`.


<a id="cause-PairPublicObservationsAbsent"></a>

### `PairPublicObservationsAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Pair(pair)`.


<a id="cause-PreparedEmptySelectorAbsent"></a>

### `PreparedEmptySelectorAbsent`


Local detection/handling phase and implementation owner:

- `Admission::new` — `src/advanced/admission/preparation.rs`. Enclosing true branch: `initial.primary.is_none() && initial.empty_template.is_none()`.


<a id="cause-PrivateMaterialReadIsNotAnAdmission"></a>

### `PrivateMaterialReadIsNotAnAdmission`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing true branch: `pair.private`.


<a id="cause-PrivateSearchSelectorAbsent"></a>

### `PrivateSearchSelectorAbsent`


Local detection/handling phase and implementation owner:

- `Frames::activate_private_search` — `src/advanced/admission/active.rs`.


<a id="cause-PublicMaterialOwnerAbsent"></a>

### `PublicMaterialOwnerAbsent`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicMechanismAdmissionReportAbsent"></a>

### `PublicMechanismAdmissionReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Pair(pair)`.


<a id="cause-PublicObjectAdmissionReportAbsent"></a>

### `PublicObjectAdmissionReportAbsent`


Local detection/handling phase and implementation owner:

- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Pair(pair)`.


<a id="cause-SearchPreparationChanged"></a>

### `SearchPreparationChanged`


Local detection/handling phase and implementation owner:

- `Admission::attach_resource` — `src/advanced/admission/observation.rs`. Enclosing match alternative: `ResourceCandidate::Search(candidate) if self.stage == Stage::Find`.
- `Admission::attach_resource` — `src/advanced/admission/observation.rs`. Enclosing true branch: `need != candidate.need()`.
- `SearchCollection::attach` — `src/managed/search/preparation.rs`. Enclosing true branch: `prepared.need.retained != self.handles.len() || prepared.storage.capacity() < prepared.need.capacity || !prepared.storage.is_empty()`.
- `SearchCollection::attach` — `src/managed/search/preparation.rs`. Enclosing true branch: `current.capacity() >= prepared.need.capacity`.


<a id="cause-SearchResponseAcceptanceChanged"></a>

### `SearchResponseAcceptanceChanged`


Local detection/handling phase and implementation owner:

- `Admission::finish` — `src/advanced/admission/completion.rs`. Enclosing match alternative: `_`.


<a id="cause-SessionCloseDuringAdmissionExplicitCleanupRequired"></a>

### `SessionCloseDuringAdmissionExplicitCleanupRequired`


Local detection/handling phase and implementation owner:

- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing true branch: `self.active_categories() != 0`.


<a id="cause-SessionCloseDuringAdmissionRediscover"></a>

### `SessionCloseDuringAdmissionRediscover`


Local detection/handling phase and implementation owner:

- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing false branch: `self.active_categories() != 0`.
- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing true branch: `self.generation.is_none() && self.close_epoch != session.snapshot.domain.close_epoch.load(Ordering::Acquire)`.


<a id="cause-SymmetricAdmissionMetadataByteCount"></a>

### `SymmetricAdmissionMetadataByteCount`


Local detection/handling phase and implementation owner:

- `Input<'_>::symmetric_metadata_bytes` — `src/advanced/admission/input.rs`. Enclosing match alternative: `Self::Symmetric(Some(value))`.


<a id="cause-SymmetricAdmissionResultOwnerMismatch"></a>

### `SymmetricAdmissionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `symmetric_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-SymmetricMechanismReportAbsent"></a>

### `SymmetricMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'_>::finish_observed` — `src/transport/operations.rs`. Enclosing match alternative: `(Self::Symmetric(spec), KeyEvidence::Key(evidence))`.
- `Admission::publish` — `src/advanced/admission/publication.rs`. Enclosing match alternative: `KeyPolicy::Symmetric { spec, publication }`.


<a id="cause-SynchronousAdmissionPendingExplicitCloseRequired"></a>

### `SynchronousAdmissionPendingExplicitCloseRequired`


Local detection/handling phase and implementation owner:

- `synchronous_pending` (module-level helper) — `src/advanced/admission/synchronous.rs`.


<a id="cause-TransportSigningResultOwnerMismatch"></a>

### `TransportSigningResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `transport_signing_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.
- `PreparedClassicalPair::finish_transport` — `src/crypto/signing/owned/transport.rs`. Enclosing match alternative: `_`.


<a id="cause-VerificationSelectionResultOwnerMismatch"></a>

### `VerificationSelectionResultOwnerMismatch`


Local detection/handling phase and implementation owner:

- `verification_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing match alternative: `_`.
