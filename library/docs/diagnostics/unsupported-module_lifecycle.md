Cause contracts for `ModuleLifecycleUnsupported`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AutonomousArchiveRequiresAnObservedModuleFile"></a>

### `AutonomousArchiveRequiresAnObservedModuleFile`


Local detection/handling phase and implementation owner:

- `ModuleBinding::persistent_digest` — `src/module/access.rs`. Enclosing match alternative: `provenance::BindingIdentity::Local(_)`.


<a id="cause-FileLoadingOptionsForProcessSource"></a>

### `FileLoadingOptionsForProcessSource`


Local detection/handling phase and implementation owner:

- `Module::open_selected_symmetric` — `src/module/open.rs`. Enclosing true branch: `!matches!(windows_file_pinning, WindowsFilePinning::NotRequested) || !matches!( windows_image_consistency, WindowsImageConsistency::NotRequested ) || !matches!( windows_dependency_search, WindowsDependencySearch::ApplicationConfigured ) || !matches!( windows_loader_observations, WindowsLoaderObservations::NotRequested )`.
- `ModuleBuilder::observation_source` — `src/module/configuration/observation.rs`.

