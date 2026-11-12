Cause contracts for `NativeMessagesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CapturedGenericMessageRequiresDestinationBinding"></a>

### `CapturedGenericMessageRequiresDestinationBinding`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing true branch: `matches!(self.execution, Execution::Captured)`.


<a id="cause-ChangedGenericMessageSnapshotInput"></a>

### `ChangedGenericMessageSnapshotInput`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::snapshot_shape` — `src/advanced/native_messages/snapshot.rs`. Enclosing true branch: `!self.unchanged()`.


<a id="cause-ForeignMessagePreparationBudget"></a>

### `ForeignMessagePreparationBudget`


Local detection/handling phase and implementation owner:

- `submit_with_budget` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `!budget.same_account(&session.inner.symmetric_budget)`.


<a id="cause-ForeignOrConsumedGenericMessageTicket"></a>

### `ForeignOrConsumedGenericMessageTicket`


Local detection/handling phase and implementation owner:

- `park_ticket` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner)`.
- `ticket_owner` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.


<a id="cause-GenericMessageContinuationTicketUnavailable"></a>

### `GenericMessageContinuationTicketUnavailable`


Local detection/handling phase and implementation owner:

- `take_ticket` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing true branch: `body.observer != Observer::Session`.


<a id="cause-GenericMessageDestinationBinding"></a>

### `GenericMessageDestinationBinding`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/native_messages/restoration.rs`.


<a id="cause-GenericMessageDiagnosticNotUsed"></a>

### `GenericMessageDiagnosticNotUsed`


Local detection/handling phase and implementation owner:

- `prepared_diagnostic` (module-level helper) — `src/advanced/native_messages.rs`.


<a id="cause-GenericMessageFacadeIncomplete"></a>

### `GenericMessageFacadeIncomplete`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-GenericMessageInitializationBinding"></a>

### `GenericMessageInitializationBinding`


Local detection/handling phase and implementation owner:

- `PreparedOwner::check_binding` — `src/advanced/native_messages/preparation.rs`. Enclosing true branch: `self.initialization.kind() != binding.primary.contract.native_mechanism() || binding.primary.contract.operation() != operation || binding.primary.contract.mutates_key() && !binding.writer`.


<a id="cause-GenericMessageInputBoundaryNotEstablished"></a>

### `GenericMessageInputBoundaryNotEstablished`


Local detection/handling phase and implementation owner:

- `ready` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-GenericMessageInputBoundaryUnavailable"></a>

### `GenericMessageInputBoundaryUnavailable`


Local detection/handling phase and implementation owner:

- `plan` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `!matches!(body.execution, Execution::Running) || !body.input.is_open() || !body.input.incremental || body.pending() || body.input.retained_submission || body.released.call.is_some() || body.released.output.is_some()`.


<a id="cause-GenericMessageInputMutation"></a>

### `GenericMessageInputMutation`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing true branch: `!self.unchanged()`.


<a id="cause-GenericMessageIsNotWaitingForOutput"></a>

### `GenericMessageIsNotWaitingForOutput`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::output_preparation` — `src/advanced/native_messages/output.rs`.


<a id="cause-GenericMessageNotAtACapturableBoundary"></a>

### `GenericMessageNotAtACapturableBoundary`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::snapshot_shape` — `src/advanced/native_messages/snapshot.rs`. Enclosing true branch: `!matches!(self.execution, Execution::Running) || self.observer != Observer::Ticket || self.pending() || self.native_inactive() || self.initialization.is_none() || self.released.call.is_some() || self.released.output.is_some() || matches!(self.phase, Phase::Init | Phase::Complete)`.


<a id="cause-GenericMessageOutputRowAbsent"></a>

### `GenericMessageOutputRowAbsent`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::attach_output` — `src/advanced/native_messages/output.rs`.


<a id="cause-GenericMessageOwnerAccounting"></a>

### `GenericMessageOwnerAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/advanced/native_messages/preparation.rs`.


<a id="cause-GenericMessageOwnerShape"></a>

### `GenericMessageOwnerShape`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/native_messages.rs`.


<a id="cause-GenericMessageParameterDeclarationMismatch"></a>

### `GenericMessageParameterDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `plan` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `request.contract.native_mechanism() != body.initialization().kind() || request.contract.mutates_key() && !body.binding.writer`.


<a id="cause-GenericMessagePreparedOutputWidth"></a>

### `GenericMessagePreparedOutputWidth`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::attach_output` — `src/advanced/native_messages/output.rs`. Enclosing true branch: `output.capacity() != self.output_storage_bytes(capacity)?`.


<a id="cause-GenericMessageReconstruction"></a>

### `GenericMessageReconstruction`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/native_messages/checkpoint.rs`.


<a id="cause-GenericMessageRequiresExplicitCleanup"></a>

### `GenericMessageRequiresExplicitCleanup`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing true branch: `self.pending() || matches!(self.execution, Execution::Failed)`.


<a id="cause-GenericMessageResultAbsent"></a>

### `GenericMessageResultAbsent`


Local detection/handling phase and implementation owner:

- `verification_refusal` (module-level helper) — `src/advanced/native_messages/batch.rs`.


<a id="cause-GenericMessageResultNotAvailable"></a>

### `GenericMessageResultNotAvailable`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::result` — `src/advanced/native_messages/result.rs`. Enclosing true branch: `!self.complete() || !self.native_inactive() || self.initialization.is_none()`.


<a id="cause-GenericMessageResultShape"></a>

### `GenericMessageResultShape`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::result` — `src/advanced/native_messages/result.rs`. Enclosing match alternative: `_`.


<a id="cause-GenericMessageRetainedInputMutation"></a>

### `GenericMessageRetainedInputMutation`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing true branch: `!self.unchanged()`.


<a id="cause-GenericMessageSigningOutputAbsent"></a>

### `GenericMessageSigningOutputAbsent`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::attach_output` — `src/advanced/native_messages/output.rs`.


<a id="cause-GenericMessageSnapshotShape"></a>

### `GenericMessageSnapshotShape`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/advanced/native_messages/snapshot.rs`.


<a id="cause-GenericMessageStartAccounting"></a>

### `GenericMessageStartAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/advanced/native_messages/start.rs`.


<a id="cause-GenericMessageStreamIsNotAwaitingInput"></a>

### `GenericMessageStreamIsNotAwaitingInput`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `!matches!(body.execution, Execution::Running) || !body.input.incremental || !body.input.is_open() || body.input.retained_submission || body.released.call.is_some() || body.released.output.is_some() || !matches!(body.phase, Phase::Ready | Phase::Receive(_))`.


<a id="cause-GenericMessageSubmissionAccounting"></a>

### `GenericMessageSubmissionAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/advanced/native_messages/input.rs`.


<a id="cause-GenericMessageSubmissionRoute"></a>

### `GenericMessageSubmissionRoute`


Local detection/handling phase and implementation owner:

- `plan` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `!shape_matches`.


<a id="cause-GenericMessageTerminalOperands"></a>

### `GenericMessageTerminalOperands`


Local detection/handling phase and implementation owner:

- `plan` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `kind.terminal() != action.is_some() || action.is_some_and(|action| matches!(action, Action::Verify(_)) != body.verify)`.


<a id="cause-GenericMessageTicketAlreadyTransferred"></a>

### `GenericMessageTicketAlreadyTransferred`


Local detection/handling phase and implementation owner:

- `park_ticket` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing true branch: `body.observer != Observer::Ticket`.


<a id="cause-GenericMessageTicketRequired"></a>

### `GenericMessageTicketRequired`


Local detection/handling phase and implementation owner:

- `verification_refusal` (module-level helper) — `src/advanced/native_messages/batch.rs`.
- `park_ticket` (module-level helper) — `src/advanced/native_messages/batch.rs`.
- `take_ticket` (module-level helper) — `src/advanced/native_messages/batch.rs`.
- `check_owner` (module-level helper) — `src/advanced/native_messages/input.rs`.
- `poll` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `operation.id != ticket.id || !matches!(operation.body, OperationBody::NativeMessages(_))`.


<a id="cause-GenericResultAccounting"></a>

### `GenericResultAccounting`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::result` — `src/advanced/native_messages/result.rs`.


<a id="cause-MessageAsynchronousModeUnavailable"></a>

### `MessageAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/native_messages/start.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.


<a id="cause-MessageOutputAlreadySubmitted"></a>

### `MessageOutputAlreadySubmitted`


Local detection/handling phase and implementation owner:

- `plan` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `matches!(message.output, MessageOutput::Sign(Some(_)))`.


<a id="cause-MessageParameterMechanismMismatch"></a>

### `MessageParameterMechanismMismatch`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing true branch: `parameters.contract.native_mechanism() != request.contract.native_mechanism()`.


<a id="cause-MessagePartCountOverflow"></a>

### `MessagePartCountOverflow`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/advanced/native_messages/batch.rs`.


<a id="cause-MessagePrimaryBindingAbsent"></a>

### `MessagePrimaryBindingAbsent`


Local detection/handling phase and implementation owner:

- `Binding::from_start` — `src/advanced/native_messages/binding.rs`.


<a id="cause-MessageSignatureNotCompleted"></a>

### `MessageSignatureNotCompleted`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::result` — `src/advanced/native_messages/result.rs`. Enclosing match alternative: `MessageOutput::Sign(Some(output)) if !self.verify`.


<a id="cause-MessageSignatureOutputOffset"></a>

### `MessageSignatureOutputOffset`


Local detection/handling phase and implementation owner:

- `SignatureOutput::capacity` — `src/advanced/native_messages.rs`.


<a id="cause-MessageSignatureResultExtent"></a>

### `MessageSignatureResultExtent`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::result` — `src/advanced/native_messages/result.rs`. Enclosing true branch: `produced > output.capacity()?`.


<a id="cause-MessageWriteRequiresItsDeclaredWriter"></a>

### `MessageWriteRequiresItsDeclaredWriter`


Local detection/handling phase and implementation owner:

- `NativeMessageOperation::drive_inner` — `src/advanced/native_messages/driver.rs`. Enclosing true branch: `mutates && !self.binding.writer`.


<a id="cause-RevokedMessageAuxiliaryKey"></a>

### `RevokedMessageAuxiliaryKey`


Local detection/handling phase and implementation owner:

- `Binding::check` — `src/advanced/native_messages/binding.rs`. Enclosing true branch: `key.revoked.load(Ordering::Acquire) && !own_revocation`.


<a id="cause-StaleGenericMessageTicket"></a>

### `StaleGenericMessageTicket`


Local detection/handling phase and implementation owner:

- `verification_refusal` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing true branch: `operation.id != id`.
- `park_ticket` (module-level helper) — `src/advanced/native_messages/batch.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `check_owner` (module-level helper) — `src/advanced/native_messages/input.rs`. Enclosing true branch: `operation.id != id`.

