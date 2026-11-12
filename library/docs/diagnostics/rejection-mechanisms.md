Cause contracts for `MechanismsRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ConflictingMechanismProperties"></a>

### `ConflictingMechanismProperties`


Local detection/handling phase and implementation owner:

- `MechanismCatalog::insert` — `src/mechanism_catalog.rs`. Enclosing match alternative: `Ok(_)`.


<a id="cause-MechanismCatalogueAllocation"></a>

### `MechanismCatalogueAllocation`


Local detection/handling phase and implementation owner:

- `MechanismCatalog::insert` — `src/mechanism_catalog.rs`. Enclosing match alternative: `Err(index)`.


<a id="cause-MechanismNotAnnounced"></a>

### `MechanismNotAnnounced`


Local detection/handling phase and implementation owner:

- `MechanismCatalog::properties` — `src/mechanism_catalog.rs`.


<a id="cause-MechanismRequestAllocation"></a>

### `MechanismRequestAllocation`


Local detection/handling phase and implementation owner:

- `MechanismAttributes<'_>::prepare` — `src/mechanism_policy.rs`. Enclosing match alternative: `MechanismRequest::Explicit { mechanisms, maximum_bytes, }`.
- `Template::mechanism_numbers` — `src/attributes/template_plan.rs`.


<a id="cause-MechanismRequestBudget"></a>

### `MechanismRequestBudget`


Local detection/handling phase and implementation owner:

- `MechanismAttributes<'_>::validate` — `src/mechanism_policy.rs`. Enclosing true branch: `bytes > maximum_bytes`.
- `MechanismAttributes<'_>::prepare` — `src/mechanism_policy.rs`. Enclosing true branch: `bytes > maximum_bytes`.


<a id="cause-MechanismRequestByteCount"></a>

### `MechanismRequestByteCount`


Local detection/handling phase and implementation owner:

- `MechanismAttributes<'_>::validate` — `src/mechanism_policy.rs`. Enclosing true branch: `let MechanismRequest::Explicit { mechanisms, maximum_bytes, } = self.request`.
- `MechanismAttributes<'_>::requested_bytes` — `src/mechanism_policy.rs`. Enclosing match alternative: `MechanismRequest::Explicit { mechanisms, .. }`.
- `MechanismAttributes<'_>::prepare` — `src/mechanism_policy.rs`. Enclosing match alternative: `MechanismRequest::Explicit { mechanisms, maximum_bytes, }`.


<a id="cause-MechanismRequestWidth"></a>

### `MechanismRequestWidth`


Local detection/handling phase and implementation owner:

- `MechanismAttributes<'_>::validate` — `src/mechanism_policy.rs`. Enclosing true branch: `let MechanismRequest::Explicit { mechanisms, maximum_bytes, } = self.request`.
- `MechanismAttributes<'_>::prepare` — `src/mechanism_policy.rs`. Enclosing match alternative: `MechanismRequest::Explicit { mechanisms, maximum_bytes, }`.
- `Template::mechanism_numbers` — `src/attributes/template_plan.rs`.
- `TemplateSize::mechanism_numbers` — `src/attributes/template_plan.rs`.


<a id="cause-PolicyMechanismRecipeAbsent"></a>

### `PolicyMechanismRecipeAbsent`


Local detection/handling phase and implementation owner:

- `PolicyOwner::mechanisms` — `src/mechanism_controls/resident.rs`. Enclosing match alternative: `Some(storage)`.


<a id="cause-PolicyObservationCompletionPhase"></a>

### `PolicyObservationCompletionPhase`


Local detection/handling phase and implementation owner:

- `PolicyOwner::advance` — `src/mechanism_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-PolicyObservationIncomplete"></a>

### `PolicyObservationIncomplete`


Local detection/handling phase and implementation owner:

- `PolicyOwner::result` — `src/mechanism_controls/resident.rs`.


<a id="cause-PolicyObservationNeedAbsent"></a>

### `PolicyObservationNeedAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/mechanism_controls/resident/runner.rs`.


<a id="cause-PolicyObservationOwnerAbsent"></a>

### `PolicyObservationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/mechanism_controls/resident/runner.rs`.
- `observe` (module-level helper) — `src/mechanism_controls/resident/runner.rs`.


<a id="cause-PolicyObservationPhase"></a>

### `PolicyObservationPhase`


Local detection/handling phase and implementation owner:

- `PolicyOwner::attach` — `src/mechanism_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-PolicyObservationPossessionAbsent"></a>

### `PolicyObservationPossessionAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/mechanism_controls/resident/runner.rs`.


<a id="cause-PolicyObservationSourceChanged"></a>

### `PolicyObservationSourceChanged`


Local detection/handling phase and implementation owner:

- `PolicyOwner::advance` — `src/mechanism_controls/resident.rs`. Enclosing true branch: `handle != self.handle`.


<a id="cause-PolicyObservationStopped"></a>

### `PolicyObservationStopped`


Local detection/handling phase and implementation owner:

- `PolicyOwner::advance` — `src/mechanism_controls/resident.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-PolicyObservationStorageSize"></a>

### `PolicyObservationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/mechanism_controls/resident.rs`.


<a id="cause-RetainedMechanismRequestSize"></a>

### `RetainedMechanismRequestSize`


Local detection/handling phase and implementation owner:

- `PreparedMechanismAttributes::retained_request_bytes` — `src/mechanism_policy.rs`. Enclosing match alternative: `PreparedMechanismRequest::Explicit(values)`.
