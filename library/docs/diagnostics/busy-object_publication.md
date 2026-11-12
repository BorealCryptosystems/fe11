Cause contracts for `ObjectPublicationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-MutationCleanupAwaitsNativeCompletion"></a>

### `MutationCleanupAwaitsNativeCompletion`


Cleanup found an unfinished native loan outside the search being finalized, or
another uncertain native context not classified here as retired initialization.
An unfinished loan must establish completion before cleanup can proceed; waiting
alone does not restore a withdrawn context. An active search alone does not
trigger this refusal: its own Final checks the search phase, ownership and context.

A direct `CKR_CRYPTOKI_NOT_INITIALIZED` refusal is preserved without adding a
cleanup failure when the resident owner proves that no cleanup work is due.
That conclusion does not release any reservation or retained native frame and
does not prove that no native effect occurred. Otherwise, an unfinished loan
takes priority; a known initialization retirement is reported separately as
`NativeExecutionRejection::NativeInitializationRetired`, before native cleanup.

Local handling owners:

- `run` in `src/managed/mutations/outputs/runner.rs`: checks every output slot independently.
- `run` in `src/managed/mutations/copy/resident/runner.rs`: checks the current copy phase.
- `run_with_native` in `src/managed/mutations/create/resident/runner.rs`: checks the current creation phase.

