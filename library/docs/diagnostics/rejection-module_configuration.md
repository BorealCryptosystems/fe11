Cause contracts for `ModuleConfigurationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-InitializationArgumentsDuringAttachment"></a>

### `InitializationArgumentsDuringAttachment`


Local detection/handling phase and implementation owner:

- `ModuleBuilder::open_selected` — `src/module/configuration.rs`. Enclosing true branch: `external.is_some() && (self.reserved_initialization.is_some() || self.initialization_mutexes.is_some())`.
- `Request<'a>::prepare` — `src/native/initialization.rs`. Enclosing true branch: `reserved.is_some() || mutexes.is_some()`.


<a id="cause-LocalModuleIdentityExhausted"></a>

### `LocalModuleIdentityExhausted`


Local detection/handling phase and implementation owner:

- `ModuleProvenance::binding` — `src/module/provenance.rs`. Enclosing match alternative: `Self::Process { file: Err(_) }`.


<a id="cause-ModuleDigestMismatch"></a>

### `ModuleDigestMismatch`


Local detection/handling phase and implementation owner:

- `ModuleIntegrity::evaluate` — `src/module/integrity.rs`. Enclosing true branch: `*on_mismatch == ModuleDigestMismatch::Refuse`.


<a id="cause-ModuleFileRead"></a>

### `ModuleFileRead`


Local detection/handling phase and implementation owner:

- `digest` (module-level helper) — `src/module/provenance.rs`. Enclosing match alternative: `Err(_)`.


<a id="cause-ProcessExportObservationAbsent"></a>

### `ProcessExportObservationAbsent`


Local detection/handling phase and implementation owner:

- `observe_process_file` (module-level helper) — `src/module/provenance.rs`.


<a id="cause-ProcessExportsDoNotShareTheObservedFile"></a>

### `ProcessExportsDoNotShareTheObservedFile`


Local detection/handling phase and implementation owner:

- `observe_process_file` (module-level helper) — `src/module/provenance.rs`. Enclosing true branch: `!crate::native::mapped_image_matches(*address, identity)?`.


<a id="cause-ProcessImageFileIsNotRegular"></a>

### `ProcessImageFileIsNotRegular`


Local detection/handling phase and implementation owner:

- `observe_process_file` (module-level helper) — `src/module/provenance.rs`. Enclosing true branch: `!metadata.is_file()`.


<a id="cause-ProcessImageFileMetadata"></a>

### `ProcessImageFileMetadata`


Local detection/handling phase and implementation owner:

- `observe_process_file` (module-level helper) — `src/module/provenance.rs`.


<a id="cause-ProcessImageFileUnavailable"></a>

### `ProcessImageFileUnavailable`


Local detection/handling phase and implementation owner:

- `observe_process_file` (module-level helper) — `src/module/provenance.rs`.


<a id="cause-ProcessImageFilenameUnavailable"></a>

### `ProcessImageFilenameUnavailable`


Local detection/handling phase and implementation owner:

- `observe_process_file` (module-level helper) — `src/module/provenance.rs`. Enclosing true branch: `unsafe { dladdr(address as *const c_void, &mut info) } == 0 || info.name.is_null()`.
