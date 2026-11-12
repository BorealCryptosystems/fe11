Cause contracts for `ExternalExecutionRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-ForeignJoinOwnerMismatch"></a>

### `ForeignJoinOwnerMismatch`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::prepare_join_admitted` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &source.inner) || !Arc::ptr_eq(&self.inner, &session.inner) || !Arc::ptr_eq(&self.participant, &source.work.participant) || !Arc::ptr_eq(&self.participant, &session.work.participant) || session.work.kind != ForeignWorkKind::Session`.


<a id="cause-ForeignJoinSourceMissing"></a>

### `ForeignJoinSourceMissing`


Local detection/handling phase and implementation owner:

- `ForeignWork::begin_admitted` — `src/module/foreign/call.rs`. Enclosing true branch: `step == ForeignStep::Join`.


<a id="cause-ForeignJoinSourceNotDetached"></a>

### `ForeignJoinSourceNotDetached`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::prepare_join_admitted` — `src/module/foreign.rs`. Enclosing true branch: `source.work.state.lock().map_err(|_| Error::Poisoned)?.phase != Phase::Detached`.


<a id="cause-ForeignAdoptedProgressMismatch"></a>

### `ForeignAdoptedProgressMismatch`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::adopt_operation` — `src/module/foreign.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignCallAlreadyDispatched"></a>

### `ForeignCallAlreadyDispatched`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::dispatched` — `src/module/foreign/call.rs`. Enclosing true branch: `self.state != CallState::Prepared`.


<a id="cause-ForeignCallReservationChanged"></a>

### `ForeignCallReservationChanged`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::dispatched` — `src/module/foreign/call.rs`. Enclosing true branch: `state.phase != Phase::Reserved(self.step)`.


<a id="cause-ForeignCallScopeAllocation"></a>

### `ForeignCallScopeAllocation`


Local detection/handling phase and implementation owner:

- `PreparedScope::new` — `src/module/foreign/call_scope.rs`.


<a id="cause-ForeignCallbackCount"></a>

### `ForeignCallbackCount`


Local detection/handling phase and implementation owner:

- `Registry::status` — `src/module/foreign/registry.rs`.
- `Registry::status` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignCallbackCountExhausted"></a>

### `ForeignCallbackCountExhausted`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`.


<a id="cause-ForeignCallbackGraphRetired"></a>

### `ForeignCallbackGraphRetired`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`. Enclosing true branch: `work_state.as_ref().is_some_and(|state| { matches!( state.phase, Phase::Prepared | Phase::PreparedJoin | Phase::Returned | Phase::Detached | Phase::JoinReserved ) })`.


<a id="cause-ForeignCallbackScopeAllocation"></a>

### `ForeignCallbackScopeAllocation`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`.


<a id="cause-ForeignCloseSessionOwner"></a>

### `ForeignCloseSessionOwner`


Local detection/handling phase and implementation owner:

- `Registry::session_close_ready` — `src/module/foreign/registry.rs`. Enclosing true branch: `session.kind != ForeignWorkKind::Session`.


<a id="cause-ForeignCloseSessionOwnerRequired"></a>

### `ForeignCloseSessionOwnerRequired`


Local detection/handling phase and implementation owner:

- `ForeignWork::begin_admitted` — `src/module/foreign/call.rs`. Enclosing true branch: `step == ForeignStep::CloseSession && self.work.kind != ForeignWorkKind::Session`.


<a id="cause-ForeignCollectionAllocation"></a>

### `ForeignCollectionAllocation`


Local detection/handling phase and implementation owner:

- `Registry::collect_completed` — `src/module/foreign/registry.rs`.
- `Registry::collect_completed` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignDrainingRuntime"></a>

### `ForeignDrainingRuntime`


Local detection/handling phase and implementation owner:

- `super::ModuleDrain::prepare_foreign_join` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &participant.inner)`.
- `super::ModuleDrain::begin_foreign` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &work.inner)`.


<a id="cause-ForeignDrainingSlot"></a>

### `ForeignDrainingSlot`


Local detection/handling phase and implementation owner:

- `super::TokenDrain::prepare_foreign_join` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.context.inner, &participant.inner) || !session .work .domain .as_ref() .is_some_and(|domain| Arc::ptr_eq(domain, &self.context.snapshot.domain))`.
- `super::TokenDrain::begin_foreign` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.context.inner, &work.inner) || !work .work .domain .as_ref() .is_some_and(|domain| Arc::ptr_eq(domain, &self.context.snapshot.domain))`.


<a id="cause-ForeignEventAlreadyIssued"></a>

### `ForeignEventAlreadyIssued`


Local detection/handling phase and implementation owner:

- `ForeignEvent<'_>::dispatched` — `src/module/foreign/event.rs`. Enclosing true branch: `self.phase != Phase::Prepared`.


<a id="cause-ForeignEventCodeConversion"></a>

### `ForeignEventCodeConversion`


Local detection/handling phase and implementation owner:

- `ForeignEvent<'_>::returned` — `src/module/foreign/event.rs`.


<a id="cause-ForeignEventCompletionUnproven"></a>

### `ForeignEventCompletionUnproven`


Local detection/handling phase and implementation owner:

- `ForeignEvent<'_>::returned` — `src/module/foreign/event.rs`. Enclosing true branch: `rv == fe11_sys::CKR_PENDING`.


<a id="cause-ForeignEventNotDispatched"></a>

### `ForeignEventNotDispatched`


Local detection/handling phase and implementation owner:

- `ForeignEvent<'_>::returned` — `src/module/foreign/event.rs`. Enclosing true branch: `self.phase != Phase::Issued`.


<a id="cause-ForeignEventRuntimeMismatch"></a>

### `ForeignEventRuntimeMismatch`


Local detection/handling phase and implementation owner:

- `RuntimeOwner::use_foreign_events` — `src/module/foreign/event.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.module().inner, &participant.inner)`.


<a id="cause-ForeignEventSlotConversion"></a>

### `ForeignEventSlotConversion`


Local detection/handling phase and implementation owner:

- `ForeignEvent<'_>::returned` — `src/module/foreign/event.rs`. Enclosing true branch: `rv == fe11_sys::CKR_OK`.


<a id="cause-ForeignGraphRetired"></a>

### `ForeignGraphRetired`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`.


<a id="cause-ForeignInitializationFinalized"></a>

### `ForeignInitializationFinalized`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`. Enclosing true branch: `participant.finalized.load(Ordering::Acquire)`.


<a id="cause-ForeignNativeContextRetired"></a>

### `ForeignNativeContextRetired`


Local detection/handling phase and implementation owner:

- `ForeignWork::begin_admitted` — `src/module/foreign/call.rs`. Enclosing true branch: `registry::native_context_retired(&self.work)`.
- `Registry::check_session` — `src/module/foreign/registry.rs`. Enclosing true branch: `native_context_retired(selected)`.


<a id="cause-ForeignNativeReturnWithoutMatchingDispatch"></a>

### `ForeignNativeReturnWithoutMatchingDispatch`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::record_return` — `src/module/foreign/call.rs`. Enclosing true branch: `self.state != CallState::Dispatched || state.phase != Phase::Issued(self.step)`.


<a id="cause-ForeignNativeSessionHandleReused"></a>

### `ForeignNativeSessionHandleReused`


Local detection/handling phase and implementation owner:

- `Registry::check_opened_handle` — `src/module/foreign/registry.rs`. Enclosing true branch: `!retired || old.callbacks.load(Ordering::Acquire) != 0`.


<a id="cause-ForeignOpenSessionOwnerRequired"></a>

### `ForeignOpenSessionOwnerRequired`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::opened` — `src/module/foreign/call.rs`. Enclosing true branch: `self.work.work.kind != ForeignWorkKind::Session || self.step != ForeignStep::Start`.


<a id="cause-ForeignOpenSessionReceiptRequired"></a>

### `ForeignOpenSessionReceiptRequired`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::record_return` — `src/module/foreign/call.rs`. Enclosing true branch: `self.work.work.kind == ForeignWorkKind::Session && self.step == ForeignStep::Start && rv == fe11_sys::CKR_OK`.


<a id="cause-ForeignOpenWithoutDispatch"></a>

### `ForeignOpenWithoutDispatch`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::opened` — `src/module/foreign/call.rs`. Enclosing true branch: `self.state != CallState::Dispatched || state.phase != Phase::Issued(ForeignStep::Start)`.


<a id="cause-ForeignOperationSessionMismatch"></a>

### `ForeignOperationSessionMismatch`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::adopt_operation` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.inner) || !Arc::ptr_eq(&self.participant, &session.work.participant) || session.work.kind != ForeignWorkKind::Session || kind == ForeignWorkKind::Session`.
- `ForeignParticipant::prepare_operation` — `src/module/foreign.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.inner) || !Arc::ptr_eq(&self.participant, &session.work.participant) || session.work.kind != ForeignWorkKind::Session || kind == ForeignWorkKind::Session`.


<a id="cause-ForeignParticipantAllocation"></a>

### `ForeignParticipantAllocation`


Local detection/handling phase and implementation owner:

- `Registry::register` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignParticipantRetired"></a>

### `ForeignParticipantRetired`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`.


<a id="cause-ForeignRetirementAllocation"></a>

### `ForeignRetirementAllocation`


Local detection/handling phase and implementation owner:

- `Registry::prepare_retirement` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignRetirementCapacityChanged"></a>

### `ForeignRetirementCapacityChanged`


Local detection/handling phase and implementation owner:

- `Registry::retire` — `src/module/foreign/registry.rs`. Enclosing true branch: `retired.graphs.len() == retired.graphs.capacity() && state.graph.is_some()`.
- `Registry::retire_session` — `src/module/foreign/registry.rs`. Enclosing true branch: `state.graph.is_some() && retired.graphs.len() == retired.graphs.capacity()`.


<a id="cause-ForeignReturnCodeConversion"></a>

### `ForeignReturnCodeConversion`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::adopt_operation` — `src/module/foreign.rs`.
- `ForeignCall<'_>::record_return` — `src/module/foreign/call.rs`.


<a id="cause-ForeignReturnDoesNotProveDeclaredCompletion"></a>

### `ForeignReturnDoesNotProveDeclaredCompletion`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::record_return` — `src/module/foreign/call.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignRuntimeRetired"></a>

### `ForeignRuntimeRetired`


Local detection/handling phase and implementation owner:

- `ForeignCallbackHandle::enter` — `src/module/foreign/call.rs`.


<a id="cause-ForeignSessionAlreadyRegistered"></a>

### `ForeignSessionAlreadyRegistered`


Local detection/handling phase and implementation owner:

- `Registry::publish` — `src/module/foreign/registry.rs`. Enclosing true branch: `!matches!(phase, Phase::Returned)`.


<a id="cause-ForeignSessionHandleConversion"></a>

### `ForeignSessionHandleConversion`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::register_work` — `src/module/foreign.rs`. Enclosing true branch: `let ForeignScope::Session { handle, .. } = scope`.
- `ForeignCall<'_>::opened` — `src/module/foreign/call.rs`.


<a id="cause-ForeignSessionHandleInvalid"></a>

### `ForeignSessionHandleInvalid`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::register_work` — `src/module/foreign.rs`. Enclosing true branch: `handle == fe11_sys::CK_INVALID_HANDLE`.
- `ForeignCall<'_>::opened` — `src/module/foreign/call.rs`. Enclosing true branch: `native == fe11_sys::CK_INVALID_HANDLE`.


<a id="cause-ForeignSessionOwnerRequired"></a>

### `ForeignSessionOwnerRequired`


Local detection/handling phase and implementation owner:

- `ForeignParticipant::prepare_call` — `src/module/foreign.rs`. Enclosing true branch: `matches!(scope, ForeignScope::Session { .. })`.


<a id="cause-ForeignSessionRetired"></a>

### `ForeignSessionRetired`


Local detection/handling phase and implementation owner:

- `Registry::check_session` — `src/module/foreign/registry.rs`. Enclosing true branch: `session.state.lock().map_err(|_| Error::Poisoned)?.phase != Phase::SessionOpen`.


<a id="cause-ForeignSessionsActive"></a>

### `ForeignSessionsActive`


Local detection/handling phase and implementation owner:

- `Registry::finalization_ready` — `src/module/foreign/registry.rs`. Enclosing match alternative: `Phase::SessionOpen`.


<a id="cause-ForeignSlotConversion"></a>

### `ForeignSlotConversion`


Local detection/handling phase and implementation owner:

- `ForeignCall<'_>::finish_receipt` — `src/module/foreign/call.rs`. Enclosing true branch: `let Some(slot) = self.work.work.scope.slot()`.
- `Registry::domain` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignSlotRegistryAllocation"></a>

### `ForeignSlotRegistryAllocation`


Local detection/handling phase and implementation owner:

- `Registry::domain` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignWorkRegistryAllocation"></a>

### `ForeignWorkRegistryAllocation`


Local detection/handling phase and implementation owner:

- `Registry::publish` — `src/module/foreign/registry.rs`.


<a id="cause-ForeignWorkStepNotAdmitted"></a>

### `ForeignWorkStepNotAdmitted`


Local detection/handling phase and implementation owner:

- `ForeignWork::begin_admitted` — `src/module/foreign/call.rs`. Enclosing true branch: `!applicable`.
