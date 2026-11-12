Cause contracts for `OperationOwnershipBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AdvancedFinalizationActivity"></a>

### `AdvancedFinalizationActivity`

Finalization could not borrow an operation owner because its mutex is in use. The ledger keeps the owner and buffers. End the current observation/transition before retrying local finalization admission; no native finalization is authorized by this diagnostic.


Local detection/handling phase and implementation owner:

- `Ledger::finalization_ready` — `src/advanced/ledger.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.


<a id="cause-AdvancedNativeCompletionUnproven"></a>

### `AdvancedNativeCompletionUnproven`

Finalization or slot retirement found an operation whose native execution is incomplete. The ledger retains that operation, token binding and buffers. Do not discard its ticket, replay the native call or release its operands. Only the existing operation/recovery protocol can provide completion evidence.


Local detection/handling phase and implementation owner:

- `Ledger::finalization_ready` — `src/advanced/ledger.rs`. Enclosing true branch: `operation.execution_incomplete()`.
- `Ledger::retire_slot_admission` — `src/advanced/ledger.rs`. Enclosing true branch: `operation.execution_incomplete()`.


<a id="cause-AdvancedOperation"></a>

### `AdvancedOperation`


Local detection/handling phase and implementation owner:

- `reserve_new_while_in` (module-level helper) — `src/advanced/preparation.rs`. Enclosing true branch: `matches!(admission, crate::ResourceAdmission::WaitUntil { .. })`.
- `AdvancedSession::set_validation_capture` — `src/advanced/validation.rs`. Enclosing true branch: `self .session .entry .advanced_operation .load(Ordering::Acquire) != 0`.
- `Session::entry` — `src/session/access.rs`. Enclosing true branch: `self.entry.advanced_operation.load(Ordering::Acquire) != 0`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `self.entry.advanced_operation.load(Ordering::Acquire) != 0`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `matches!(mode, ReferenceMode::Advanced) && self.entry.advanced_operation.load(Ordering::Acquire) != 0`.
- `Session::reference_admission_with_epoch` — `src/session/references.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::OperationOwnership( crate::OperationOwnershipBusy::AdvancedOperation, ))) if progress.can_maintain() && self.entry.advanced_progress.cleanup_hint()`.
- `ReferenceAdmission<'_>::reserve` — `src/session/references.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::OperationOwnership( crate::OperationOwnershipBusy::AdvancedOperation, ))) if self.progress.can_maintain() && self.session.entry.advanced_progress.cleanup_hint()`.
- `ReferenceAdmission<'_>::references_with_storage` — `src/session/references.rs`. Enclosing match alternative: `Err(Error::Busy(crate::BusyReason::OperationOwnership( crate::OperationOwnershipBusy::AdvancedOperation, ))) if self.progress.can_maintain() && self.session.entry.advanced_progress.cleanup_hint()`.
- `init_reader_borrow` (module-level helper) — `src/advanced/ledger.rs`. Enclosing true branch: `operation.active_categories() & category == 0`.
- `Ledger::install_with_retained` — `src/advanced/ledger.rs`. Enclosing true branch: `slots.contains_key(&uid)`.
- `AdvancedSession::set_pacing` — `src/advanced.rs`. Enclosing true branch: `self .session .entry .advanced_operation .load(Ordering::Acquire) != 0`.


<a id="cause-AdvancedRetirementActivity"></a>

### `AdvancedRetirementActivity`

Slot retirement could not borrow an operation owner because its mutex is in use. The ledger retains the operation. Complete the current local access before another retirement attempt; retirement does not itself establish native completion.


Local detection/handling phase and implementation owner:

- `Ledger::retire_slot_admission` — `src/advanced/ledger.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.


<a id="cause-AsynchronousJoinControl"></a>

### `AsynchronousJoinControl`


Local detection/handling phase and implementation owner:

- `Operation::attach_join` — `src/advanced/operation.rs`. Enclosing true branch: `self.joined.is_some()`.


<a id="cause-LiveAdvancedTokenBinding"></a>

### `LiveAdvancedTokenBinding`

Slot retirement found an operation whose token binding is still live. The ledger retains it. A retirement request requires actual withdrawal of that same binding; do not manufacture withdrawal or use another generation to bypass the check.


Local detection/handling phase and implementation owner:

- `Ledger::retire_slot_admission` — `src/advanced/ledger.rs`. Enclosing true branch: `!owner.identity.retired_binding()`.


<a id="cause-NativeOperationCallPending"></a>

### `NativeOperationCallPending`

A new Init reader or Logout observation found an existing operation with incomplete native execution. The ledger retains that operation. Resolve the existing execution through its owner; issuing another Init or Logout cannot substitute for its return.


Local detection/handling phase and implementation owner:

- `init_reader_borrow` (module-level helper) — `src/advanced/ledger.rs`. Enclosing true branch: `operation.execution_incomplete()`.
- `Ledger::logout_ready` — `src/advanced/ledger.rs`. Enclosing true branch: `operation.execution_incomplete()`.


<a id="cause-OperationObservationInProgress"></a>

### `OperationObservationInProgress`

The requested local inspection or transfer could not acquire an operation mutex immediately. This occurs when Logout inspects the active operation, or when take_aead_message_ticket tries to transfer the stored AEAD ticket. The current owner keeps the operation or ticket. Retry after the competing local access finishes; this refusal establishes no native result, removes no owner and dispatches no native call.


Local detection/handling phase and implementation owner:

- `Session::take_aead_message_ticket` — `src/advanced/gcm/ticket.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.
- `Ledger::logout_ready` — `src/advanced/ledger.rs`. Enclosing match alternative: `std::sync::TryLockError::WouldBlock`.


<a id="cause-OperationStateControl"></a>

### `OperationStateControl`


Local detection/handling phase and implementation owner:

- `drive` (module-level helper) — `src/advanced/operation.rs`. Enclosing true branch: `op.state_io().is_some()`.
- `Operation::begin_state` — `src/advanced/ownership.rs`.

