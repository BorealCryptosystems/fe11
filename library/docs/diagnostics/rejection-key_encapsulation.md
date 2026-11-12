Cause contracts for `KeyEncapsulationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CDecapsulateKeyUnavailable"></a>

### `CDecapsulateKeyUnavailable`


Local detection/handling phase and implementation owner:

- `Session::admit_imported_kem_decapsulation_key` — `src/crypto/kem/admission.rs`. Enclosing true branch: `functions.decapsulate.is_none()`.
- `Session::kem_native` — `src/crypto/kem/operations.rs`. Enclosing match alternative: `Direction::Decapsulate(_, _) if functions.decapsulate.is_none()`.
- `Call::resolve` — `src/crypto/kem/operations/resolved_call.rs`. Enclosing match alternative: `Direction::Decapsulate(_, _)`.


<a id="cause-CEncapsulateKeyUnavailable"></a>

### `CEncapsulateKeyUnavailable`


Local detection/handling phase and implementation owner:

- `Session::kem_native` — `src/crypto/kem/operations.rs`. Enclosing match alternative: `Direction::Encapsulate(_) if functions.encapsulate.is_none()`.
- `Call::resolve` — `src/crypto/kem/operations/resolved_call.rs`. Enclosing match alternative: `Direction::Encapsulate(_)`.


<a id="cause-KemCiphertextOwnerAbsent"></a>

### `KemCiphertextOwnerAbsent`


Local detection/handling phase and implementation owner:

- `Session::kem_native` — `src/crypto/kem/operations.rs`.


<a id="cause-KemPublicPublicationPairing"></a>

### `KemPublicPublicationPairing`


Local detection/handling phase and implementation owner:

- `Session::import_kem_public_key` — `src/crypto/kem/admission.rs`.


<a id="cause-MlKemSpkiDer"></a>

### `MlKemSpkiDer`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`.


<a id="cause-MlKemSpkiAlgorithm"></a>

### `MlKemSpkiAlgorithm`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`.


<a id="cause-MlKemSpkiEncoding"></a>

### `MlKemSpkiEncoding`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`.
- `KemPublicKey::to_spki` — `src/crypto/kem/encoding.rs`.
- `KemPublicKey::spki_fingerprint` — `src/crypto/kem/encoding.rs`.


<a id="cause-MlKemSpkiLength"></a>

### `MlKemSpkiLength`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`. Enclosing true branch: `bytes.is_empty()`.


<a id="cause-MlKemSpkiParametersMustBeAbsent"></a>

### `MlKemSpkiParametersMustBeAbsent`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`. Enclosing true branch: `spki.algorithm.parameters.is_some()`.


<a id="cause-MlKemSpkiUnusedBits"></a>

### `MlKemSpkiUnusedBits`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`.


<a id="cause-MlKemCiphertextLength"></a>

### `MlKemCiphertextLength`


Local detection/handling phase and implementation owner:

- `KemCiphertext::from_bytes` — `src/crypto/kem/encoding.rs`. Enclosing true branch: `bytes.len() != parameter_set.ciphertext_length()`.


<a id="cause-MlKemCiphertextParameterMismatch"></a>

### `MlKemCiphertextParameterMismatch`


Local detection/handling phase and implementation owner:

- `Direction<'_>::validate` — `src/crypto/kem/operations.rs`. Enclosing true branch: `ciphertext.parameter_set() != key.parameter_set`.


<a id="cause-MlKemImportedKeyFamily"></a>

### `MlKemImportedKeyFamily`


Local detection/handling phase and implementation owner:

- `Session::admit_imported_kem_decapsulation_key` — `src/crypto/kem/admission.rs`.


<a id="cause-MlKemInputPreparationChanged"></a>

### `MlKemInputPreparationChanged`


Local detection/handling phase and implementation owner:

- `KemOwnerPlan<'_>::allocated_bytes` — `src/crypto/kem/owned.rs`. Enclosing match alternative: `_`.
- `KemOwnerPlan<'_>::finish_owner` — `src/crypto/kem/owned.rs`. Enclosing true branch: `!matches!( (&input.input, &candidate.storage.input), ( KemOwnerInput::Generation { .. }, KemInputStorage::Generation ) | (KemOwnerInput::Existing { .. }, KemInputStorage::Existing(_)) )`.


<a id="cause-MlKemNativeGraphOverflow"></a>

### `MlKemNativeGraphOverflow`


Local detection/handling phase and implementation owner:

- `Session::kem_native` — `src/crypto/kem/operations.rs`.
- `Session::kem_native` — `src/crypto/kem/operations.rs`.
- `Session::kem_native` — `src/crypto/kem/operations.rs`.
- `Session::kem_native` — `src/crypto/kem/operations.rs`.
- `Session::kem_native` — `src/crypto/kem/operations.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-MlKemNativeInputOrOutputCapacityViolation"></a>

### `MlKemNativeInputOrOutputCapacityViolation`

Detected after an ML-KEM native return when an input descriptor was altered
or the output exceeds its allocation. Native object creation may already have
occurred. The cleanup owner marks that objects may remain; publication of the
requested result is refused. Preserve the complete cleanup/creation error and
retained references. Do not infer rollback, enlarge a buffer and repeat KEM,
or destroy a possibly aliased object outside the explicit cleanup protocol.


Local detection/handling phase and implementation owner:

- `execute_kem` (module-level helper) — `src/crypto/kem/operations.rs`. Enclosing true branch: `completed && rv == CKR_BUFFER_TOO_SMALL && matches!(&direction, Direction::Encapsulate(_))`.
- `execute_kem` (module-level helper) — `src/crypto/kem/operations.rs`. Enclosing true branch: `!unchanged || overflow`.


<a id="cause-MlKemNoncanonicalSpki"></a>

### `MlKemNoncanonicalSpki`


Local detection/handling phase and implementation owner:

- `KemPublicKey::borrow_spki` — `src/crypto/kem/encoding.rs`. Enclosing true branch: `spki.to_der().map_err(|_| { Error::Rejected(crate::RejectionReason::KeyEncapsulation( crate::KeyEncapsulationRejection::MlKemSpkiEncoding, )) })? != bytes`.


<a id="cause-MlKemPairObservationBudget"></a>

### `MlKemPairObservationBudget`


Local detection/handling phase and implementation owner:

- `validate_observation_budgets` (module-level helper) — `src/crypto/kem.rs`. Enclosing true branch: `public.metadata.maximum_bytes < identity_bytes.max(parameter_set.public_key_length()) || private.metadata.maximum_bytes < identity_bytes`.


<a id="cause-MlKemPairOwnerSize"></a>

### `MlKemPairOwnerSize`


Local detection/handling phase and implementation owner:

- `owner_bytes` (module-level helper) — `src/crypto/kem/owned.rs`.


<a id="cause-MlKemPairSourceStorage"></a>

### `MlKemPairSourceStorage`


Local detection/handling phase and implementation owner:

- `KemOwnerPlan<'_>::source_bytes` — `src/crypto/kem/owned.rs`. Enclosing match alternative: `KemOwnerInput::Generation { request, .. }`.


<a id="cause-MlKemPublicAllocation"></a>

### `MlKemPublicAllocation`


Local detection/handling phase and implementation owner:

- `KemPublicKey::observation_storage` — `src/crypto/kem/encoding.rs`.
- `KemPublicKey::copy_validated` — `src/crypto/kem/encoding.rs`.


<a id="cause-MlKemPublicBitString"></a>

### `MlKemPublicBitString`


Local detection/handling phase and implementation owner:

- `KemPublicKey::spki` — `src/crypto/kem/encoding.rs`.


<a id="cause-MlKemPublicCoefficientEncoding"></a>

### `MlKemPublicCoefficientEncoding`


Local detection/handling phase and implementation owner:

- `KemPublicKey::validate_raw` — `src/crypto/kem/encoding.rs`. Enclosing true branch: `first >= 3329 || second >= 3329`.


<a id="cause-MlKemPublicIdentityAlreadyObserved"></a>

### `MlKemPublicIdentityAlreadyObserved`


Local detection/handling phase and implementation owner:

- `PreparedKemPair::validate` — `src/crypto/kem/owned.rs`. Enclosing true branch: `!matches!(self.public, PublicState::AwaitingIdentity(_))`.


<a id="cause-MlKemPublicKeyLength"></a>

### `MlKemPublicKeyLength`


Local detection/handling phase and implementation owner:

- `KemPublicKey::validate_raw` — `src/crypto/kem/encoding.rs`. Enclosing true branch: `bytes.len() != parameter_set.public_key_length()`.


<a id="cause-MlKemPublicObservationIncomplete"></a>

### `MlKemPublicObservationIncomplete`


Local detection/handling phase and implementation owner:

- `PreparedKemPair::complete` — `src/crypto/kem/owned.rs`. Enclosing true branch: `!matches!(self.public, PublicState::Observed(_))`.


<a id="cause-MlKemRequiresSelected32Interface"></a>

### `MlKemRequiresSelected32Interface`


Local detection/handling phase and implementation owner:

- `Session::admit_imported_kem_decapsulation_key` — `src/crypto/kem/admission.rs`.
- `Session::kem_native` — `src/crypto/kem/operations.rs`.
- `execute_kem` (module-level helper) — `src/crypto/kem/operations.rs`.


<a id="cause-MlKemReturnedBaseHandle"></a>

### `MlKemReturnedBaseHandle`


Local detection/handling phase and implementation owner:

- `execute_kem` (module-level helper) — `src/crypto/kem/operations.rs`. Enclosing true branch: `data.created == handle`.


<a id="cause-MlKemSelectionIdAllocation"></a>

### `MlKemSelectionIdAllocation`


Local detection/handling phase and implementation owner:

- `KemOwnerPlan<'_>::allocate` — `src/crypto/kem/owned.rs`. Enclosing match alternative: `KemOwnerInput::Existing { id, .. }`.


<a id="cause-MlKemValueRequiresPublicIdentity"></a>

### `MlKemValueRequiresPublicIdentity`


Local detection/handling phase and implementation owner:

- `PreparedKemPair::observe_public` — `src/crypto/kem/owned.rs`.


<a id="cause-ExistingMlKemPairHasNoCreationTemplates"></a>

### `ExistingMlKemPairHasNoCreationTemplates`


Local detection/handling phase and implementation owner:

- `KemOwnerPlan<'_>::generation_templates_as` — `src/crypto/kem/owned.rs`.
- `Source::templates_as` — `src/crypto/kem/owned/source.rs`. Enclosing match alternative: `Self::Existing { .. }`.


<a id="cause-ExistingMlKemPairHasNoGenerationRequest"></a>

### `ExistingMlKemPairHasNoGenerationRequest`


Local detection/handling phase and implementation owner:

- `KemOwnerPlan<'_>::generation_identity` — `src/crypto/kem/owned.rs`.
- `KemOwnerPlan<'_>::generation_mechanism` — `src/crypto/kem/owned.rs`.
- `Source::generation_request` — `src/crypto/kem/owned/source.rs`. Enclosing match alternative: `Self::Existing { .. }`.

