Cause contracts for `AuthenticationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-PinFrameAccounting"></a>

### `PinFrameAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/pin/preparation.rs`.


<a id="cause-AuthenticationEpochChanged"></a>

### `AuthenticationEpochChanged`


Local detection/handling phase and implementation owner:

- `Authentication::check_unchanged` — `src/authentication.rs`. Enclosing true branch: `self.stamp() != stamp`.
- `Authentication::observe_unchanged` — `src/authentication.rs`. Enclosing true branch: `self.stamp() != stamp`.


<a id="cause-AuthenticationEpochExhausted"></a>

### `AuthenticationEpochExhausted`


Local detection/handling phase and implementation owner:

- `Authentication::publish` — `src/authentication.rs`.


<a id="cause-ContextAuthenticationRequiresInitializedOperation"></a>

### `ContextAuthenticationRequiresInitializedOperation`


Local detection/handling phase and implementation owner:

- `Operation::check_context_authentication` — `src/advanced/authentication.rs`. Enclosing true branch: `self.active_categories() == 0 || self.body.complete()`.
- `Operation::check_authentication_budget` — `src/advanced/operation.rs`. Enclosing match alternative: `OperationBody::Control | OperationBody::Admission(_)`.


<a id="cause-ForeignAuthenticationSession"></a>

### `ForeignAuthenticationSession`


Local detection/handling phase and implementation owner:

- `TokenContext::logout_entry` — `src/module/authentication.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &self.inner) || !Arc::ptr_eq(&session.snapshot, &self.snapshot)`.
- `TokenContext::authentication_entry` — `src/module/authentication.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &self.inner) || !Arc::ptr_eq(&session.snapshot, &self.snapshot)`.


<a id="cause-ForeignOrConsumedOperationTicket"></a>

### `ForeignOrConsumedOperationTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::next_native_function` — `src/advanced/authentication.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &self.session.inner) || ticket.uid != self.session.uid || ticket.id == 0`.
- `Session::authenticate_context_with_budget` — `src/advanced/authentication.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0`.
- `check_ticket` (module-level helper) — `src/advanced/detachment.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner)`.
- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `self.session.entry.advanced_progress.retired(ticket.id)?`.
- `AdvancedSession::drive_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `self.session.entry.advanced_progress.retired(ticket.id)?`.
- `poll_live_operation` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.
- `poll_live_operation` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `session.entry.advanced_progress.retired(ticket.id)?`.
- `poll_live_operation` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `session.entry.advanced_progress.retired(ticket.id)?`.
- `poll_owned` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.
- `poll_owned` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `session.entry.advanced_progress.retired(ticket.id)?`.
- `check_ticket` (module-level helper) — `src/advanced/saved_state.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner)`.


<a id="cause-LogoutRequiresLiveSession"></a>

### `LogoutRequiresLiveSession`


Local detection/handling phase and implementation owner:

- `TokenContext::logout_entry` — `src/module/authentication.rs`.


<a id="cause-MissingContextualAuthentication"></a>

### `MissingContextualAuthentication`


Local detection/handling phase and implementation owner:

- `Session::authenticate_context_with_budget` — `src/advanced/authentication.rs`.
