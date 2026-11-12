Cause contracts for `ObjectDestinationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DestinationCardinalityWidth"></a>

### `DestinationCardinalityWidth`


Local detection/handling phase and implementation owner:

- `DestinationOwner::advance` — `src/destination_controls/resident.rs`. Enclosing match alternative: `Phase::Searching { evaluation, search, source, }`.
- `CreationDestinations::finish` — `src/advanced/admission/destination.rs`.


<a id="cause-DestinationCompletionPhase"></a>

### `DestinationCompletionPhase`


Local detection/handling phase and implementation owner:

- `DestinationOwner::advance` — `src/destination_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-DestinationContinuationPhase"></a>

### `DestinationContinuationPhase`


Local detection/handling phase and implementation owner:

- `DestinationOwner::attach` — `src/destination_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-DestinationIncomplete"></a>

### `DestinationIncomplete`


Local detection/handling phase and implementation owner:

- `DestinationOwner::result` — `src/destination_controls/resident.rs`.


<a id="cause-DestinationObservationRequiresPreparedOwner"></a>

### `DestinationObservationRequiresPreparedOwner`


Local detection/handling phase and implementation owner:

- `DestinationReport::observe_local` — `src/destination_controls.rs`. Enclosing true branch: `destination.query_allocation_bytes(&selection)? != 0`.


<a id="cause-DestinationPreparationAlreadyBound"></a>

### `DestinationPreparationAlreadyBound`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/destination_controls/resident.rs`. Enclosing match alternative: `Query::BoundSearch { .. } | Query::Consumed`.


<a id="cause-DestinationPreparationAlreadyConsumed"></a>

### `DestinationPreparationAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Initial::bind_retained` — `src/destination_controls/resident.rs`. Enclosing true branch: `matches!(self.0, Query::Consumed)`.


<a id="cause-DestinationProtectionAbsent"></a>

### `DestinationProtectionAbsent`


Local detection/handling phase and implementation owner:

- `Initial::bind_retained` — `src/destination_controls/resident.rs`. Enclosing true branch: `protection.is_none()`.


<a id="cause-DestinationQueryReachedLocalReport"></a>

### `DestinationQueryReachedLocalReport`


Local detection/handling phase and implementation owner:

- `DestinationReport::observe_local` — `src/destination_controls.rs`. Enclosing match alternative: `DestinationQuery::Enumerate { .. }`.


<a id="cause-DestinationSearchPreparationAbsent"></a>

### `DestinationSearchPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/destination_controls/resident.rs`. Enclosing match alternative: `Query::Search { storage, .. }`.


<a id="cause-DestinationStorageSize"></a>

### `DestinationStorageSize`


Local detection/handling phase and implementation owner:

- `Initial::requested` — `src/destination_controls/resident.rs`.
- `Initial::allocated_bytes` — `src/destination_controls/resident.rs`.


<a id="cause-UnrequestedDestinationCount"></a>

### `UnrequestedDestinationCount`


Local detection/handling phase and implementation owner:

- `PreparedDestination::finish` — `src/destination_controls.rs`. Enclosing true branch: `matches!(&self.selection.search, DestinationSearchPlan::NotRequested) && count != Observation::NotRequested`.
