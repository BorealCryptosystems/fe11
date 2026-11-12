Cause contracts for `ObjectObservationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CDestroyObjectUnavailable"></a>

### `CDestroyObjectUnavailable`


Local detection/handling phase and implementation owner:

- `Session::destroy` — `src/objects.rs`.
- `Session::destroy_managed` — `src/managed/destruction.rs`.
- `Session::destroy_resource_with` — `src/managed/destruction.rs`.
- `destroy_created` (module-level helper) — `src/managed/mutations.rs`.


<a id="cause-RsaCreationReservationAbsent"></a>

### `RsaCreationReservationAbsent`


Local detection/handling phase and implementation owner:

- `Initial::publish` — `src/objects/resident/preparation.rs`. Enclosing match alternative: `Start::Generate { public, private, public_template, private_template, }`.


<a id="cause-RsaDiagnosticAccounting"></a>

### `RsaDiagnosticAccounting`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `generating`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`.


<a id="cause-RsaGenerationCompletionUnknown"></a>

### `RsaGenerationCompletionUnknown`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `held.native.is_uncertain()`.


<a id="cause-RsaGenerationDiagnosticAbsent"></a>

### `RsaGenerationDiagnosticAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `need == Need::Native`.


<a id="cause-RsaGenerationDispatchPhase"></a>

### `RsaGenerationDispatchPhase`


Local detection/handling phase and implementation owner:

- `Owner::dispatch` — `src/objects/resident.rs`.


<a id="cause-RsaGenerationResultKind"></a>

### `RsaGenerationResultKind`


Local detection/handling phase and implementation owner:

- `generate` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaGenerationReturnPhase"></a>

### `RsaGenerationReturnPhase`


Local detection/handling phase and implementation owner:

- `Owner::returned` — `src/objects/resident.rs`.


<a id="cause-RsaNativeEffectIsNotAStorageRequest"></a>

### `RsaNativeEffectIsNotAStorageRequest`


Local detection/handling phase and implementation owner:

- `prepare_candidate` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObjectActivationPhase"></a>

### `RsaObjectActivationPhase`


Local detection/handling phase and implementation owner:

- `Owner::activate` — `src/objects/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObjectAggregateAccounting"></a>

### `RsaObjectAggregateAccounting`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-RsaObjectCandidateKind"></a>

### `RsaObjectCandidateKind`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObjectContinuationChanged"></a>

### `RsaObjectContinuationChanged`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-RsaObjectGraphSize"></a>

### `RsaObjectGraphSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/objects/resident/preparation.rs`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`.


<a id="cause-RsaObjectNeedAbsent"></a>

### `RsaObjectNeedAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`.


<a id="cause-RsaObjectOperationStopped"></a>

### `RsaObjectOperationStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/resident.rs`. Enclosing match alternative: `Phase::Stopped | Phase::InFlight { .. }`.


<a id="cause-RsaObjectOwnerAbsent"></a>

### `RsaObjectOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `need == Need::Activate`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing true branch: `need == Need::Native`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`.


<a id="cause-RsaObjectPossessionAbsent"></a>

### `RsaObjectPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/objects/resident/runner.rs`.


<a id="cause-RsaObjectPublicationPhase"></a>

### `RsaObjectPublicationPhase`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObjectResultIncomplete"></a>

### `RsaObjectResultIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/objects/resident.rs`.


<a id="cause-RsaObjectResultKind"></a>

### `RsaObjectResultKind`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/objects/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaObjectSearchRequest"></a>

### `RsaObjectSearchRequest`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/resident.rs`. Enclosing match alternative: `Phase::PrivateSearch { public, read }`.


<a id="cause-RsaObjectTransition"></a>

### `RsaObjectTransition`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaPairCandidateKind"></a>

### `RsaPairCandidateKind`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/objects/pair_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaPairCompletionPhase"></a>

### `RsaPairCompletionPhase`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/pair_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaPairContinuationChanged"></a>

### `RsaPairContinuationChanged`


Local detection/handling phase and implementation owner:

- `Owner::attach` — `src/objects/pair_observation.rs`. Enclosing true branch: `self.need() != Some(need)`.


<a id="cause-RsaPairObservationIncomplete"></a>

### `RsaPairObservationIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/objects/pair_observation.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaPairObservationStopped"></a>

### `RsaPairObservationStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/pair_observation.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-RsaPairObservationStorage"></a>

### `RsaPairObservationStorage`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/objects/pair_observation.rs`.


<a id="cause-RsaPairPreparationAbsent"></a>

### `RsaPairPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::begin_pair` — `src/objects/resident.rs`.


<a id="cause-RsaPrivateSnapshotPreparationAbsent"></a>

### `RsaPrivateSnapshotPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/objects/pair_observation.rs`. Enclosing match alternative: `Phase::Public(read)`.


<a id="cause-RsaPropertyPreparationAbsent"></a>

### `RsaPropertyPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::begin_properties` — `src/objects/resident.rs`.


<a id="cause-RsaPublicEncodingAbsent"></a>

### `RsaPublicEncodingAbsent`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/objects/resident.rs`. Enclosing match alternative: `( Origin::Generated { reports: [public_report, private_report], .. }, Identities::Pair { public, private }, )`.


<a id="cause-RsaPublicationPreparationAbsent"></a>

### `RsaPublicationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::returned` — `src/objects/resident.rs`.


<a id="cause-RsaSelectionPreparationAbsent"></a>

### `RsaSelectionPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Initial::publish` — `src/objects/resident/preparation.rs`. Enclosing match alternative: `Start::Find { public, private }`.
- `run` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing false branch: `generating`.


<a id="cause-RsaSelectionResultKind"></a>

### `RsaSelectionResultKind`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/objects/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignOrStaleObject"></a>

### `ForeignOrStaleObject`


Local detection/handling phase and implementation owner:

- `Session::object` — `src/objects.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &o.inner) || self.uid != o.session || o.session != o.identity.session || o.handle != o.identity.handle || o.identity.revoked.load(Ordering::Acquire)`.


<a id="cause-ObjectContextOrClass"></a>

### `ObjectContextOrClass`


Local detection/handling phase and implementation owner:

- `Session::object` — `src/objects.rs`. Enclosing true branch: `entry.slot != o.identity.slot || entry.generation != o.identity.generation || class.is_some_and(|c| c != o.identity.class)`.


<a id="cause-PublicAttributeSelectionSizeOverflow"></a>

### `PublicAttributeSelectionSizeOverflow`


Local detection/handling phase and implementation owner:

- `ObjectAdmission::public_attribute_retained_bytes` — `src/object_controls.rs`.
