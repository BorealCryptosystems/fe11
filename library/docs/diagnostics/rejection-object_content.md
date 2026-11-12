Cause contracts for `ObjectContentRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ContentContinuationPhase"></a>

### `ContentContinuationPhase`


Local detection/handling phase and implementation owner:

- `ContentOwner::advance` — `src/content_controls/owned/resident.rs`. Enclosing match alternative: `state`.


<a id="cause-ContentNativeDescriptorOrCapacityChanged"></a>

### `ContentNativeDescriptorOrCapacityChanged`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/content_controls/owned.rs`. Enclosing true branch: `!data.descriptor_valid(rv)`.


<a id="cause-ContentObservationIncomplete"></a>

### `ContentObservationIncomplete`


Local detection/handling phase and implementation owner:

- `ContentOwner::result` — `src/content_controls/owned/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ContentObservationRequiresPreparedOwner"></a>

### `ContentObservationRequiresPreparedOwner`


Local detection/handling phase and implementation owner:

- `ContentObservation::observe_local` — `src/content_controls.rs`.


<a id="cause-ContentObservationStorageSize"></a>

### `ContentObservationStorageSize`


Local detection/handling phase and implementation owner:

- `value_with` (module-level helper) — `src/content_controls/owned/resident/runner.rs`.


<a id="cause-ContentOwnerAbsent"></a>

### `ContentOwnerAbsent`


Local detection/handling phase and implementation owner:

- `value_with` (module-level helper) — `src/content_controls/owned/resident/runner.rs`.
- `value_with` (module-level helper) — `src/content_controls/owned/resident/runner.rs`.


<a id="cause-ContentPossessionAbsent"></a>

### `ContentPossessionAbsent`


Local detection/handling phase and implementation owner:

- `value_with` (module-level helper) — `src/content_controls/owned/resident/runner.rs`.


<a id="cause-ContentPreparationChanged"></a>

### `ContentPreparationChanged`


Local detection/handling phase and implementation owner:

- `ContentOwner::attach` — `src/content_controls/owned/resident.rs`. Enclosing true branch: `self.need() != Some(length) || bytes.len() != length`.


<a id="cause-ContentReadPhase"></a>

### `ContentReadPhase`


Local detection/handling phase and implementation owner:

- `ContentOwner::advance` — `src/content_controls/owned/resident.rs`. Enclosing false branch: `let Some(content) = absence(code, call.descriptor.ulValueLen)`.


<a id="cause-ContentSourceChanged"></a>

### `ContentSourceChanged`


Local detection/handling phase and implementation owner:

- `ContentOwner::advance` — `src/content_controls/owned/resident.rs`. Enclosing true branch: `handle != self.handle`.


<a id="cause-ContentValueNeedAbsent"></a>

### `ContentValueNeedAbsent`


Local detection/handling phase and implementation owner:

- `value_with` (module-level helper) — `src/content_controls/owned/resident/runner.rs`.


<a id="cause-FingerprintAlreadyFinished"></a>

### `FingerprintAlreadyFinished`


Local detection/handling phase and implementation owner:

- `ProtectedFingerprintHash::finish` — `src/content_controls.rs`.


<a id="cause-FingerprintByteBudget"></a>

### `FingerprintByteBudget`


Local detection/handling phase and implementation owner:

- `Header::from_values` — `src/content_controls/fingerprint_observation.rs`.
- `DigestState::from_material_with_digest` — `src/content_controls/fingerprint_observation.rs`.
- `DigestState::accept_value` — `src/content_controls/fingerprint_observation.rs`.


<a id="cause-FingerprintCandidateKind"></a>

### `FingerprintCandidateKind`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-FingerprintCompletionPhase"></a>

### `FingerprintCompletionPhase`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::advance` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-FingerprintContinuationStopped"></a>

### `FingerprintContinuationStopped`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::advance` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `State::Stopped`.


<a id="cause-FingerprintDigestPreparation"></a>

### `FingerprintDigestPreparation`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `State::NeedMaterial(header)`.


<a id="cause-FingerprintHashAccounting"></a>

### `FingerprintHashAccounting`


Local detection/handling phase and implementation owner:

- `ProtectedFingerprintHash::allocated_bytes` — `src/content_controls.rs`.


<a id="cause-FingerprintHeaderCount"></a>

### `FingerprintHeaderCount`


Local detection/handling phase and implementation owner:

- `Header::from_values` — `src/content_controls/fingerprint_observation.rs`. Enclosing true branch: `values.len() != FINGERPRINT_HEADER.len()`.
- `DigestState::finish` — `src/content_controls/fingerprint_observation.rs`. Enclosing true branch: `values.len() != FINGERPRINT_HEADER.len()`.


<a id="cause-FingerprintMaterialCount"></a>

### `FingerprintMaterialCount`


Local detection/handling phase and implementation owner:

- `DigestState::from_material_with_digest` — `src/content_controls/fingerprint_observation.rs`. Enclosing true branch: `values.len() != fields.len()`.


<a id="cause-FingerprintMetadataNeed"></a>

### `FingerprintMetadataNeed`


Local detection/handling phase and implementation owner:

- `Need::recipe` — `src/content_controls/fingerprint_observation/resident.rs`.


<a id="cause-FingerprintMetadataPhase"></a>

### `FingerprintMetadataPhase`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-FingerprintOwnerAbsent"></a>

### `FingerprintOwnerAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.
- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.


<a id="cause-FingerprintOwnerStorageSize"></a>

### `FingerprintOwnerStorageSize`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.
- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.
- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.


<a id="cause-FingerprintPossessionAbsent"></a>

### `FingerprintPossessionAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.


<a id="cause-FingerprintPreparationAccounting"></a>

### `FingerprintPreparationAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/content_controls/fingerprint_observation/resident/preparation.rs`. Enclosing match alternative: `Need::Metadata { .. }`.
- `prepare` (module-level helper) — `src/content_controls/fingerprint_observation/resident/preparation.rs`. Enclosing match alternative: `Need::Metadata { .. }`.


<a id="cause-FingerprintPreparationChanged"></a>

### `FingerprintPreparationChanged`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing true branch: `self.need() != Some(need)`.


<a id="cause-FingerprintPreparationNeedAbsent"></a>

### `FingerprintPreparationNeedAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/content_controls/fingerprint_observation/resident/runner.rs`.


<a id="cause-FingerprintProtectedCallPhase"></a>

### `FingerprintProtectedCallPhase`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `(Need::ProtectedCall { maximum }, Candidate::ProtectedCall(mut credit))`.


<a id="cause-FingerprintProtectedValuePhase"></a>

### `FingerprintProtectedValuePhase`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-FingerprintPublicValuePhase"></a>

### `FingerprintPublicValuePhase`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::attach` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-FingerprintSourceChanged"></a>

### `FingerprintSourceChanged`


Local detection/handling phase and implementation owner:

- `FingerprintOwner::advance` — `src/content_controls/fingerprint_observation/resident.rs`. Enclosing true branch: `handle != self.handle`.


<a id="cause-FingerprintStateAllocation"></a>

### `FingerprintStateAllocation`


Local detection/handling phase and implementation owner:

- `ProtectedFingerprintHash::new` — `src/content_controls.rs`.
