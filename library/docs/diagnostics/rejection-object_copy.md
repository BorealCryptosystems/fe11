Cause contracts for `ObjectCopyRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CCopyObjectUnavailable"></a>

### `CCopyObjectUnavailable`


Local detection/handling phase and implementation owner:

- `dispatch_owned` (module-level helper) — `src/managed/mutations/copy.rs`.
- `execute` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`.


<a id="cause-CopyAdmissionPhase"></a>

### `CopyAdmissionPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyAdmissionPreparationAbsent"></a>

### `CopyAdmissionPreparationAbsent`


Local detection/handling phase and implementation owner:

- `CopyOwner::admit` — `src/managed/mutations/copy/resident.rs`.


<a id="cause-CopyAlreadyDispatched"></a>

### `CopyAlreadyDispatched`


Local detection/handling phase and implementation owner:

- `CopyOwner::dispatch` — `src/managed/mutations/copy/resident.rs`.


<a id="cause-CopyCandidateKind"></a>

### `CopyCandidateKind`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyCompletionPhase"></a>

### `CopyCompletionPhase`


Local detection/handling phase and implementation owner:

- `CopyOwner::advance` — `src/managed/mutations/copy/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyContinuationChanged"></a>

### `CopyContinuationChanged`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-CopyDestinationClass"></a>

### `CopyDestinationClass`


Local detection/handling phase and implementation owner:

- `public` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyDestinationPhase"></a>

### `CopyDestinationPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyDestinationPreparationAbsent"></a>

### `CopyDestinationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing match alternative: `(Need::StartDestination, Candidate::StartDestination)`.


<a id="cause-CopyDiagnosticsAlreadyConsumed"></a>

### `CopyDiagnosticsAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `PreparedCopyDiagnostics::take` — `src/managed/mutations/copy.rs`.


<a id="cause-CopyIncomplete"></a>

### `CopyIncomplete`


Local detection/handling phase and implementation owner:

- `CopyOwner::result` — `src/managed/mutations/copy/resident.rs`.


<a id="cause-CopyInputChanged"></a>

### `CopyInputChanged`


Local detection/handling phase and implementation owner:

- `dispatch_owned` (module-level helper) — `src/managed/mutations/copy.rs`. Enclosing true branch: `!unchanged`.


<a id="cause-CopyMetadataPhase"></a>

### `CopyMetadataPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyNativeLifetimeAbsent"></a>

### `CopyNativeLifetimeAbsent`


Local detection/handling phase and implementation owner:

- `CopyOwner::admit` — `src/managed/mutations/copy/resident.rs`.


<a id="cause-CopyOutputAbsent"></a>

### `CopyOutputAbsent`


Local detection/handling phase and implementation owner:

- `CopyOwner::advance` — `src/managed/mutations/copy/resident.rs`. Enclosing match alternative: `Phase::Class { read, .. } | Phase::After { read, .. }`.
- `CopyOwner::created` — `src/managed/mutations/copy/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyOwnerAbsent"></a>

### `CopyOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`.
- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing true branch: `matches!(need, Need::StartDestination)`.
- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`.
- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing true branch: `published`.


<a id="cause-CopyPossessionAbsent"></a>

### `CopyPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`.


<a id="cause-CopyPublicationQuotaAbsent"></a>

### `CopyPublicationQuotaAbsent`


Local detection/handling phase and implementation owner:

- `CopyOwner::dispatch` — `src/managed/mutations/copy/resident.rs`.


<a id="cause-CopyPublicationQuotaTransferred"></a>

### `CopyPublicationQuotaTransferred`


Local detection/handling phase and implementation owner:

- `CopyOwner::admit` — `src/managed/mutations/copy/resident.rs`.


<a id="cause-CopyReferencePhase"></a>

### `CopyReferencePhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CopyResourceNeedAbsent"></a>

### `CopyResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/mutations/copy/resident/runner.rs`.


<a id="cause-CopyReturnedInvalidIdentity"></a>

### `CopyReturnedInvalidIdentity`


Local detection/handling phase and implementation owner:

- `PreparedCopyDiagnostics::prepare` — `src/managed/mutations/copy.rs`.


<a id="cause-CopyStopped"></a>

### `CopyStopped`


Local detection/handling phase and implementation owner:

- `CopyOwner::advance` — `src/managed/mutations/copy/resident.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-CopyStorageSize"></a>

### `CopyStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`.


<a id="cause-CopyTemplateRecipeKind"></a>

### `CopyTemplateRecipeKind`


Local detection/handling phase and implementation owner:

- `Input<'a>::public_recipe` — `src/managed/mutations/copy/resident/preparation.rs`.
