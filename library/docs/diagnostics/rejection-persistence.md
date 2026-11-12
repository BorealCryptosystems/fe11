Cause contracts for `PersistenceRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AsynchronousRejoinSessionMode"></a>

### `AsynchronousRejoinSessionMode`


Local detection/handling phase and implementation owner:

- `AdvancedSession::import_detached` — `src/advanced/detached_persistence.rs`. Enclosing true branch: `self.mode() != AdvancedSessionMode::Asynchronous`.
- `AdvancedSession::start_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `self.mode() != AdvancedSessionMode::Asynchronous`.


<a id="cause-CapturedModuleNoLongerOwned"></a>

### `CapturedModuleNoLongerOwned`


Local detection/handling phase and implementation owner:

- `SavedOperationState::export_state` — `src/advanced/persistence.rs`.
- `SavedOperationState::checkpoint_context` — `src/advanced/saved_state.rs`.


<a id="cause-CapturedNativeStateAbsent"></a>

### `CapturedNativeStateAbsent`


Local detection/handling phase and implementation owner:

- `SavedOperationState::export_state` — `src/advanced/persistence.rs`.


<a id="cause-DetachedRecordKind"></a>

### `DetachedRecordKind`


Local detection/handling phase and implementation owner:

- `detached_context` (module-level helper) — `src/advanced/persistence.rs`. Enclosing match alternative: `_`.
- `DetachedRecord<'a>::read_with` — `src/advanced/record/detached.rs`. Enclosing true branch: `!matches!( kind, Kind::Detached | Kind::DetachedCapture | Kind::DetachedValidation )`.


<a id="cause-ImportNativeStorageAbsent"></a>

### `ImportNativeStorageAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::import_state` — `src/advanced/persistence.rs`.


<a id="cause-NativeMessageDestinationRequired"></a>

### `NativeMessageDestinationRequired`


Local detection/handling phase and implementation owner:

- `AdvancedSession::import_state` — `src/advanced/persistence.rs`. Enclosing true branch: `let Some(initialization) = initialization`.
- `Prepared<'a>::captured` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `let OperationBody::NativeMessages(source) = body`.
- `Prepared<'a>::imported` — `src/advanced/keys/restoration.rs`. Enclosing true branch: `descriptor.family == record::Family::NativeMessages`.


<a id="cause-UnsupportedAuthenticatedRecordKind"></a>

### `UnsupportedAuthenticatedRecordKind`


Local detection/handling phase and implementation owner:

- `validate_import_with` (module-level helper) — `src/advanced/persistence.rs`. Enclosing match alternative: `record::Kind::GcmRecovery`.
