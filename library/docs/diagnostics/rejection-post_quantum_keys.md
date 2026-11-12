Cause contracts for `PostQuantumKeysRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CVerifySignatureUnavailable"></a>

### `CVerifySignatureUnavailable`


Local detection/handling phase and implementation owner:

- `Input<'a>::prepare` — `src/crypto/pqc/verify_signature.rs`. Enclosing match alternative: `Self::Single(message)`.


<a id="cause-CVerifySignatureFinalUnavailable"></a>

### `CVerifySignatureFinalUnavailable`


Local detection/handling phase and implementation owner:

- `Input<'a>::prepare` — `src/crypto/pqc/verify_signature.rs`. Enclosing match alternative: `Self::Multipart(parts)`.


<a id="cause-CVerifySignatureInitUnavailable"></a>

### `CVerifySignatureInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`.


<a id="cause-CVerifySignatureUpdateUnavailable"></a>

### `CVerifySignatureUpdateUnavailable`


Local detection/handling phase and implementation owner:

- `Input<'a>::prepare` — `src/crypto/pqc/verify_signature.rs`. Enclosing match alternative: `Self::Multipart(parts)`.


<a id="cause-MlDsaImportedKeyFamily"></a>

### `MlDsaImportedKeyFamily`


Local detection/handling phase and implementation owner:

- `Session::admit_imported_pqc_signing_key` — `src/crypto/pqc/imported.rs`.


<a id="cause-PqcVerifysignatureCompletionUnproven"></a>

### `PqcVerifysignatureCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`. Enclosing true branch: `!sequence.termination_known()`.


<a id="cause-PqcVerifysignatureInputChanged"></a>

### `PqcVerifysignatureInputChanged`


Local detection/handling phase and implementation owner:

- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`. Enclosing true branch: `!call.unchanged(key.algorithm, parameters, &[]) || call.signature.as_slice() != signature.as_bytes()`.
- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`. Enclosing true branch: `!call.unchanged(key.algorithm, parameters, part) || call.signature.as_slice() != signature.as_bytes()`.
- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`. Enclosing true branch: `!call.unchanged(key.algorithm, parameters, last) || call.signature.as_slice() != signature.as_bytes()`.


<a id="cause-PqcContextLength"></a>

### `PqcContextLength`


Local detection/handling phase and implementation owner:

- `PqcSignatureParameters::new` — `src/crypto/pqc/parameters.rs`. Enclosing true branch: `context.len() > 255`.


<a id="cause-PqcExportAccessOwner"></a>

### `PqcExportAccessOwner`


Local detection/handling phase and implementation owner:

- `read_prepared` (module-level helper) — `src/crypto/pqc_material/export.rs`. Enclosing true branch: `!access.owns_session(session)`.


<a id="cause-PqcExportCandidateKind"></a>

### `PqcExportCandidateKind`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::attach` — `src/crypto/pqc_material/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-PqcExportCompletionPhase"></a>

### `PqcExportCompletionPhase`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::advance` — `src/crypto/pqc_material/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-PqcExportContinuationChanged"></a>

### `PqcExportContinuationChanged`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::attach` — `src/crypto/pqc_material/resident.rs`. Enclosing true branch: `self.need() != Some(need)`.


<a id="cause-PqcExportIdentityPreparationAbsent"></a>

### `PqcExportIdentityPreparationAbsent`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::advance` — `src/crypto/pqc_material/resident.rs`. Enclosing match alternative: `Phase::Private { call, before }`.


<a id="cause-PqcExportIncomplete"></a>

### `PqcExportIncomplete`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::result` — `src/crypto/pqc_material/resident.rs`.


<a id="cause-PqcExportMetadataPhase"></a>

### `PqcExportMetadataPhase`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::attach` — `src/crypto/pqc_material/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-PqcExportMetadataSize"></a>

### `PqcExportMetadataSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`.


<a id="cause-PqcExportOwnerAbsent"></a>

### `PqcExportOwnerAbsent`


Local detection/handling phase and implementation owner:

- `export` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`.
- `export` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`.


<a id="cause-PqcExportPossessionAbsent"></a>

### `PqcExportPossessionAbsent`


Local detection/handling phase and implementation owner:

- `export` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`.


<a id="cause-PqcExportRequiresPrivateKey"></a>

### `PqcExportRequiresPrivateKey`


Local detection/handling phase and implementation owner:

- `export` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`. Enclosing true branch: `key.class() != ManagedClass::PrivateKey`.


<a id="cause-PqcExportResourceNeedAbsent"></a>

### `PqcExportResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `export` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`.


<a id="cause-PqcExportStopped"></a>

### `PqcExportStopped`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::advance` — `src/crypto/pqc_material/resident.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-PqcExportStorageSize"></a>

### `PqcExportStorageSize`


Local detection/handling phase and implementation owner:

- `Storage::requested` — `src/crypto/pqc_material/export/preparation.rs`. Enclosing match alternative: `PqcPrivateEncoding::SeedAndValue`.
- `Storage::requested` — `src/crypto/pqc_material/export/preparation.rs`.
- `Storage::allocated_bytes` — `src/crypto/pqc_material/export/preparation.rs`. Enclosing match alternative: `EmptyComponents::Both { seed, value }`.
- `Storage::allocated_bytes` — `src/crypto/pqc_material/export/preparation.rs`.


<a id="cause-PqcImportPublicLength"></a>

### `PqcImportPublicLength`


Local detection/handling phase and implementation owner:

- `Session::import_pqc_private_key` — `src/crypto/pqc_material/import.rs`. Enclosing true branch: `expected_public.len() != algorithm.public_length()`.


<a id="cause-PqcImportSeedLength"></a>

### `PqcImportSeedLength`


Local detection/handling phase and implementation owner:

- `PqcPrivateInput::validate` — `src/crypto/pqc_material/import.rs`. Enclosing true branch: `value.len() != algorithm.seed_length()`.


<a id="cause-PqcImportValueLength"></a>

### `PqcImportValueLength`


Local detection/handling phase and implementation owner:

- `PqcPrivateInput::validate` — `src/crypto/pqc_material/import.rs`. Enclosing true branch: `bytes.len() != algorithm.value_length()`.


<a id="cause-PqcInputPreparationChanged"></a>

### `PqcInputPreparationChanged`


Local detection/handling phase and implementation owner:

- `PqcOwnerPlan<'_>::allocated_bytes` — `src/crypto/pqc/owned.rs`. Enclosing match alternative: `_`.
- `PqcOwnerPlan<'_>::finish_owner` — `src/crypto/pqc/owned.rs`. Enclosing true branch: `!matches!( (&input.input, &candidate.storage.input), ( PqcOwnerInput::Generation { .. }, PqcInputStorage::Generation ) | (PqcOwnerInput::Existing { .. }, PqcInputStorage::Existing(_)) )`.


<a id="cause-PqcMessageCeiling"></a>

### `PqcMessageCeiling`


Local detection/handling phase and implementation owner:

- `validate_message` (module-level helper) — `src/crypto/pqc/parameters.rs`. Enclosing true branch: `limits.maximum_parts < 1 || length > limits.maximum_total_bytes`.


<a id="cause-PqcNativeFrameAccounting"></a>

### `PqcNativeFrameAccounting`


Local detection/handling phase and implementation owner:

- `PreparedPqcCall::verification` — `src/crypto/pqc/frame/preparation.rs`.
- `PreparedPqcCall::signing` — `src/crypto/pqc/frame/preparation.rs`.


<a id="cause-PqcNativeParameterStorage"></a>

### `PqcNativeParameterStorage`


Local detection/handling phase and implementation owner:

- `NativeParameters::requested_bytes` — `src/crypto/pqc/parameters.rs`.
- `NativeParameters::allocated_bytes` — `src/crypto/pqc/parameters.rs`.


<a id="cause-PqcNativeSignatureLength"></a>

### `PqcNativeSignatureLength`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `rv == CKR_OK`.
- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`.


<a id="cause-PqcNativeSignatureWidth"></a>

### `PqcNativeSignatureWidth`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `bounds::final_length(call.length, call.buffers.signature.capacity()).map_err( |_| { sequence.invalid_output(crate::RejectionReason::PostQuantumKeys( crate::PostQuantumKeysRejection::PqcNativeSignatureLength, )) }, )? != call.buffers.signature.capacity()`.


<a id="cause-PqcNativeStorageSize"></a>

### `PqcNativeStorageSize`


Local detection/handling phase and implementation owner:

- `PreparedPqcCall::prepare` — `src/crypto/pqc/frame/preparation.rs`.
- `PreparedPqcCall::prepare` — `src/crypto/pqc/frame/preparation.rs`.
- `PreparedPqcCall::prepare` — `src/crypto/pqc/frame/preparation.rs`.


<a id="cause-PqcPairObservationBudget"></a>

### `PqcPairObservationBudget`


Local detection/handling phase and implementation owner:

- `validate_observation_budgets` (module-level helper) — `src/crypto/pqc/keys.rs`. Enclosing true branch: `public_admission.metadata.maximum_bytes < identity_bytes.max(algorithm.public_key_length()) || private_admission.metadata.maximum_bytes < identity_bytes`.


<a id="cause-PqcPairOwnerSize"></a>

### `PqcPairOwnerSize`


Local detection/handling phase and implementation owner:

- `owner_bytes` (module-level helper) — `src/crypto/pqc/owned.rs`.


<a id="cause-PqcPairSourceStorage"></a>

### `PqcPairSourceStorage`


Local detection/handling phase and implementation owner:

- `PqcOwnerPlan<'_>::source_bytes` — `src/crypto/pqc/owned.rs`. Enclosing match alternative: `PqcOwnerInput::Generation { request, .. }`.


<a id="cause-PqcPrehashLength"></a>

### `PqcPrehashLength`


Local detection/handling phase and implementation owner:

- `PqcSignatureParameters::validate_input` — `src/crypto/pqc/parameters.rs`. Enclosing true branch: `length != hash.output_length()`.


<a id="cause-PqcPrivateAttributeDescriptorOrLength"></a>

### `PqcPrivateAttributeDescriptorOrLength`


Local detection/handling phase and implementation owner:

- `validate_descriptors` (module-level helper) — `src/crypto/pqc_material.rs`. Enclosing true branch: `actual.len() != expected.len() || actual.iter().zip(expected).any(|(value, original)| { value.r#type != original.r#type || value.pValue != original.pValue || value.ulValueLen != original.ulValueLen })`.


<a id="cause-PqcPrivateDescriptorOrCapacityChanged"></a>

### `PqcPrivateDescriptorOrCapacityChanged`


Local detection/handling phase and implementation owner:

- `read_prepared` (module-level helper) — `src/crypto/pqc_material/export.rs`. Enclosing true branch: `!data.inputs_valid(rv)`.


<a id="cause-PqcPrivateIdentityChangedDuringExport"></a>

### `PqcPrivateIdentityChangedDuringExport`


Local detection/handling phase and implementation owner:

- `PqcExportOwner::advance` — `src/crypto/pqc_material/resident.rs`. Enclosing true branch: `validate_exportable(&read.required_result(session, access)?)? != output.algorithm`.


<a id="cause-PqcPrivateIdentityEncoding"></a>

### `PqcPrivateIdentityEncoding`


Local detection/handling phase and implementation owner:

- `validate_exportable` (module-level helper) — `src/crypto/pqc_material.rs`.


<a id="cause-PqcPublicSpkiDer"></a>

### `PqcPublicSpkiDer`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`.


<a id="cause-PqcPublicSpkiBound"></a>

### `PqcPublicSpkiBound`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `bytes.is_empty()`.


<a id="cause-PqcPublicAlgorithm"></a>

### `PqcPublicAlgorithm`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`.


<a id="cause-PqcPublicAllocation"></a>

### `PqcPublicAllocation`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::observation_storage` — `src/crypto/pqc/encoding.rs`.
- `PqcPublicKey::copy_validated` — `src/crypto/pqc/encoding.rs`.
- `PublicKey<'a>::from_validated` — `src/crypto/pqc/public_verifier.rs`.


<a id="cause-PqcPublicBitString"></a>

### `PqcPublicBitString`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::spki` — `src/crypto/pqc/encoding.rs`.


<a id="cause-PqcPublicContextAllocation"></a>

### `PqcPublicContextAllocation`


Local detection/handling phase and implementation owner:

- `PublicKey<'a>::prepare` — `src/crypto/pqc/public_verifier.rs`.


<a id="cause-PqcPublicContextBound"></a>

### `PqcPublicContextBound`


Local detection/handling phase and implementation owner:

- `PublicKey<'a>::prepare` — `src/crypto/pqc/public_verifier.rs`. Enclosing true branch: `bytes.len() > 255`.


<a id="cause-PqcPublicEncoding"></a>

### `PqcPublicEncoding`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::spki_fingerprint` — `src/crypto/pqc/encoding.rs`.
- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`.
- `PqcPublicKey::to_spki` — `src/crypto/pqc/encoding.rs`.


<a id="cause-PqcPublicIdentityAlreadyObserved"></a>

### `PqcPublicIdentityAlreadyObserved`


Local detection/handling phase and implementation owner:

- `PreparedPqcPair::validate` — `src/crypto/pqc/owned.rs`. Enclosing true branch: `!matches!(self.public, PublicState::AwaitingIdentity(_))`.


<a id="cause-PqcPublicKeyLength"></a>

### `PqcPublicKeyLength`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::observe_raw` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `bytes.len() != self.algorithm.public_key_length()`.
- `PqcPublicKey::from_raw` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `bytes.len() != algorithm.public_key_length()`.
- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `raw.len() != algorithm.public_key_length()`.


<a id="cause-PqcPublicNoncanonicalDer"></a>

### `PqcPublicNoncanonicalDer`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `spki.to_der().map_err(|_| { Error::Rejected(crate::RejectionReason::PostQuantumKeys( crate::PostQuantumKeysRejection::PqcPublicEncoding, )) })? != bytes`.


<a id="cause-PqcPublicObservationIncomplete"></a>

### `PqcPublicObservationIncomplete`


Local detection/handling phase and implementation owner:

- `PreparedPqcPair::public` — `src/crypto/pqc/owned.rs`. Enclosing match alternative: `_`.


<a id="cause-PqcPublicParametersMustBeAbsent"></a>

### `PqcPublicParametersMustBeAbsent`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `spki.algorithm.parameters.is_some()`.


<a id="cause-PqcPublicPrehashFramingAllocation"></a>

### `PqcPublicPrehashFramingAllocation`


Local detection/handling phase and implementation owner:

- `frame` (module-level helper) — `src/crypto/pqc/public_verifier.rs`.


<a id="cause-PqcPublicPrehashFramingBounds"></a>

### `PqcPublicPrehashFramingBounds`


Local detection/handling phase and implementation owner:

- `frame` (module-level helper) — `src/crypto/pqc/public_verifier.rs`. Enclosing true branch: `context.len() > 255 || digest.len() != hash.output_length()`.


<a id="cause-PqcPublicUnusedBits"></a>

### `PqcPublicUnusedBits`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::borrow_spki` — `src/crypto/pqc/encoding.rs`.


<a id="cause-PqcPublicVerificationBounds"></a>

### `PqcPublicVerificationBounds`


Local detection/handling phase and implementation owner:

- `PreparedVerification<'_>::verify` — `src/crypto/pqc/public_verifier.rs`. Enclosing true branch: `signature.len() != self.key.algorithm.signature_length()`.


<a id="cause-PqcSelectionIdAllocation"></a>

### `PqcSelectionIdAllocation`


Local detection/handling phase and implementation owner:

- `PqcOwnerPlan<'_>::allocate` — `src/crypto/pqc/owned.rs`. Enclosing match alternative: `PqcOwnerInput::Existing { id, .. }`.


<a id="cause-PqcSignatureAlgorithmMismatch"></a>

### `PqcSignatureAlgorithmMismatch`


Local detection/handling phase and implementation owner:

- `PqcPublicKey::verify` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `signature.algorithm() != self.algorithm`.
- `Session::verify_pqc_multipart` — `src/crypto/pqc/multipart.rs`. Enclosing true branch: `signature.algorithm() != key.algorithm`.
- `Session::verify_pqc` — `src/crypto/pqc/operations.rs`. Enclosing true branch: `signature.algorithm() != key.algorithm`.
- `Session::verify_pqc_signature_input` — `src/crypto/pqc/verify_signature.rs`. Enclosing true branch: `signature.algorithm() != key.algorithm`.


<a id="cause-PqcSignatureCompletionUnproven"></a>

### `PqcSignatureCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!sequence.termination_known()`.


<a id="cause-PqcSignatureInputChanged"></a>

### `PqcSignatureInputChanged`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.buffers.unchanged(algorithm, parameters, part)`.
- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.buffers.unchanged(algorithm, parameters, last)`.


<a id="cause-PqcSignatureLength"></a>

### `PqcSignatureLength`


Local detection/handling phase and implementation owner:

- `PqcSignature::from_native` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `bytes.as_slice().len() != algorithm.signature_length()`.
- `PqcSignature::from_bytes` — `src/crypto/pqc/encoding.rs`. Enclosing true branch: `bytes.len() != algorithm.signature_length()`.


<a id="cause-PqcSignatureParametersChanged"></a>

### `PqcSignatureParametersChanged`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.buffers.unchanged(algorithm, parameters, &[])`.


<a id="cause-PqcSignatureParametersChangedDuringContextAuthentication"></a>

### `PqcSignatureParametersChangedDuringContextAuthentication`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.buffers.unchanged(algorithm, parameters, &[])`.


<a id="cause-PqcValueRequiresPublicIdentity"></a>

### `PqcValueRequiresPublicIdentity`


Local detection/handling phase and implementation owner:

- `PreparedPqcPair::observe_public` — `src/crypto/pqc/owned.rs`.


<a id="cause-PqcVerificationCompletionUnproven"></a>

### `PqcVerificationCompletionUnproven`


Local detection/handling phase and implementation owner:

- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!sequence.termination_known()`.


<a id="cause-PqcVerificationInputChanged"></a>

### `PqcVerificationInputChanged`


Local detection/handling phase and implementation owner:

- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.unchanged(algorithm, parameters, part)`.
- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.unchanged(algorithm, parameters, last) || call.signature.as_slice() != signature`.


<a id="cause-PqcVerificationParametersChanged"></a>

### `PqcVerificationParametersChanged`


Local detection/handling phase and implementation owner:

- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!call.unchanged(algorithm, parameters, &[])`.


<a id="cause-ExistingPqcPairHasNoCreationTemplates"></a>

### `ExistingPqcPairHasNoCreationTemplates`


Local detection/handling phase and implementation owner:

- `PqcOwnerPlan<'_>::generation_templates_as` — `src/crypto/pqc/owned.rs`.
- `Source::templates_as` — `src/crypto/pqc/owned/source.rs`. Enclosing match alternative: `Self::Existing { .. }`.


<a id="cause-ExistingPqcPairHasNoGenerationRequest"></a>

### `ExistingPqcPairHasNoGenerationRequest`


Local detection/handling phase and implementation owner:

- `PqcOwnerPlan<'_>::generation_identity` — `src/crypto/pqc/owned.rs`.
- `PqcOwnerPlan<'_>::generation_mechanism` — `src/crypto/pqc/owned.rs`.
- `Source::generation_request` — `src/crypto/pqc/owned/source.rs`. Enclosing match alternative: `Self::Existing { .. }`.


<a id="cause-SinglePartPqcSignatureRequiresOneInput"></a>

### `SinglePartPqcSignatureRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!multipart && parts.len() != 1`.


<a id="cause-SinglePartPqcVerificationRequiresOneInput"></a>

### `SinglePartPqcVerificationRequiresOneInput`


Local detection/handling phase and implementation owner:

- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing true branch: `!multipart && parts.len() != 1`.

