Cause contracts for `TokenAdministrationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGetTokenInfoUnavailable"></a>

### `CGetTokenInfoUnavailable`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`.
- `Module::token_info` — `src/module/observations.rs`.


<a id="cause-CInitPINUnavailable"></a>

### `CInitPINUnavailable`


Local detection/handling phase and implementation owner:

- `Session::initialize_pin_admitted` — `src/administration.rs`.


<a id="cause-CInitTokenUnavailable"></a>

### `CInitTokenUnavailable`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`.


<a id="cause-CSetPINUnavailable"></a>

### `CSetPINUnavailable`


Local detection/handling phase and implementation owner:

- `Session::change_pin_admitted` — `src/administration.rs`.


<a id="cause-AdministrativeGenerationStale"></a>

### `AdministrativeGenerationStale`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`. Enclosing true branch: `!access .token_registry()? .tokens .iter() .any(|p| Arc::ptr_eq(p, &target.snapshot))`.


<a id="cause-AdministrativeTargetIdentityOrStateChanged"></a>

### `AdministrativeTargetIdentityOrStateChanged`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`. Enclosing true branch: `info.manufacturerID != cap.identity.manufacturer || info.model != cap.identity.model || info.serialNumber != cap.identity.serial || info.label != cap.label || (info.flags & CKF_TOKEN_INITIALIZED as CK_FLAGS != 0) != destructive || (cap.flags & CKF_TOKEN_INITIALIZED as u64 != 0) != destructive`.


<a id="cause-ChangedTokenSessionsRequireClose"></a>

### `ChangedTokenSessionsRequireClose`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`.
- `crate::TokenContext::refresh` — `src/administration.rs`. Enclosing true branch: `!s.session_ledger.refreshable_slot(slot)?`.


<a id="cause-DiscoveryPublicationReportAllocation"></a>

### `DiscoveryPublicationReportAllocation`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`.


<a id="cause-ForeignAdministrativeTarget"></a>

### `ForeignAdministrativeTarget`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &target.inner)`.


<a id="cause-NativePinInputChanged"></a>

### `NativePinInputChanged`


Local detection/handling phase and implementation owner:

- `Session::initialize_pin_admitted` — `src/administration.rs`. Enclosing true branch: `certain && !witnesses.pins[0].unchanged(&body.data)`.
- `Session::change_pin_admitted` — `src/administration.rs`. Enclosing true branch: `certain && (!witnesses.pins[0].unchanged(&body.data.old) || !witnesses.pins[1].unchanged(&body.data.new))`.


<a id="cause-NativeTokenInitializationInputChanged"></a>

### `NativeTokenInitializationInputChanged`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`. Enclosing true branch: `certain && (!witnesses.pins[0].unchanged(&body.data.pin) || body.data.label != label)`.


<a id="cause-RefreshedTokenIdentityChanged"></a>

### `RefreshedTokenIdentityChanged`


Local detection/handling phase and implementation owner:

- `crate::TokenContext::refresh` — `src/administration.rs`. Enclosing true branch: `cap.identity != self.snapshot.capabilities.identity`.


<a id="cause-TargetTokenSessionsActive"></a>

### `TargetTokenSessionsActive`


Local detection/handling phase and implementation owner:

- `Module::initialize_observed` — `src/administration.rs`. Enclosing true branch: `access.session_ledger.has_slot(slot)? || access.session_ledger.has_retention(&cap.identity)?`.


<a id="cause-TokenContextReplaced"></a>

### `TokenContextReplaced`


Local detection/handling phase and implementation owner:

- `crate::TokenContext::refresh` — `src/administration.rs`. Enclosing true branch: `!s .token_registry()? .tokens .iter() .any(|t| Arc::ptr_eq(t, &self.snapshot))`.
- `crate::TokenContext::refresh` — `src/administration.rs`. Enclosing true branch: `!r.tokens.iter().any(|t| Arc::ptr_eq(t, &self.snapshot))`.
- `crate::TokenContext::refresh` — `src/administration.rs`.
- `TokenDrain::recover_sessions` — `src/module/drain.rs`. Enclosing true branch: `!s .token_registry()? .tokens .iter() .any(|t| Arc::ptr_eq(t, snapshot))`.
- `TokenContext::begin_drain` — `src/module/sessions.rs`. Enclosing true branch: `!state .token_registry()? .tokens .iter() .any(|t| Arc::ptr_eq(t, &self.snapshot))`.


<a id="cause-TokenGenerationExhausted"></a>

### `TokenGenerationExhausted`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`. Enclosing false branch: `let Some(old) = observed .iter() .find(|old| old.admission_available() && same_capabilities(&old.capabilities, cap))`.
- `crate::TokenContext::refresh` — `src/administration.rs`.
- `Module::open_selected_symmetric` — `src/module/open.rs`.


<a id="cause-TokenLabel"></a>

### `TokenLabel`


Local detection/handling phase and implementation owner:

- `Module::initialize_token` — `src/administration.rs`. Enclosing true branch: `label.len() > native_label.len()`.
- `Module::reinitialize_token` — `src/administration.rs`. Enclosing true branch: `label.len() > native_label.len()`.


<a id="cause-TokenRegistryAllocation"></a>

### `TokenRegistryAllocation`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`.
- `Module::refresh_tokens_report` — `src/administration.rs`.


<a id="cause-TokenRegistryCapacity"></a>

### `TokenRegistryCapacity`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`.


<a id="cause-TokenRegistryChangedAfterDiscovery"></a>

### `TokenRegistryChangedAfterDiscovery`


Local detection/handling phase and implementation owner:

- `Module::refresh_tokens_report` — `src/administration.rs`. Enclosing true branch: `s.token_registry()?.revision != revision`.
- `Module::refresh_tokens_report` — `src/administration.rs`. Enclosing true branch: `r.revision != revision`.
- `stale_observation` (module-level helper) — `src/administration/discovery_admission.rs`.

