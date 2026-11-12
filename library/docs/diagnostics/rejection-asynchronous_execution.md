Cause contracts for `AsynchronousExecutionRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CAsyncGetIDUnavailable"></a>

### `CAsyncGetIDUnavailable`


Local detection/handling phase and implementation owner:

- `GetId::dispatch` — `src/advanced/asynchronous.rs`.
- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `s.native.asynchronous.and_then(|f| f.get_id).is_none()`.
- `AdvancedSession::start_restore_detachment` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `s.native.asynchronous.and_then(|f| f.get_id).is_none()`.


<a id="cause-CAsyncJoinUnavailable"></a>

### `CAsyncJoinUnavailable`


Local detection/handling phase and implementation owner:

- `JoinedCall::attach` — `src/advanced/asynchronous.rs`.


<a id="cause-GcmMessageEncryptionDetachmentDeferred"></a>

### `GcmMessageEncryptionDetachmentDeferred`


Local detection/handling phase and implementation owner:

- `GetId::checked_function` — `src/advanced/asynchronous.rs`. Enclosing true branch: `operation.state_io().is_none() && !operation.validation_pending() && matches!(&operation.body,OperationBody::AeadMessages(body) if body.encrypting())`.
- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family == Family::MessageEncrypt`.


<a id="cause-AsynchronousIdentifierAlreadyRequested"></a>

### `AsynchronousIdentifierAlreadyRequested`


Local detection/handling phase and implementation owner:

- `GetId::dispatch` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.phase != GetIdPhase::Prepared`.


<a id="cause-AsynchronousInterfaceUnavailable"></a>

### `AsynchronousInterfaceUnavailable`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_rejoin` — `src/advanced/rejoin.rs`.


<a id="cause-AsynchronousJoinAlreadyAttempted"></a>

### `AsynchronousJoinAlreadyAttempted`


Local detection/handling phase and implementation owner:

- `JoinedCall::attach` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.phase != JoinPhase::Prepared`.
- `AdvancedSession::poll_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `control.call.is_none()`.


<a id="cause-AsynchronousJoinNotAttached"></a>

### `AsynchronousJoinNotAttached`


Local detection/handling phase and implementation owner:

- `JoinedCall::poll` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.phase != JoinPhase::Attached`.


<a id="cause-AsynchronousObjectHandles"></a>

### `AsynchronousObjectHandles`


Local detection/handling phase and implementation owner:

- `completed_objects` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing true branch: `result.ulVersion != 0 || result.hObject == CK_INVALID_HANDLE || pair && (result.hAdditionalObject == CK_INVALID_HANDLE || result.hObject == result.hAdditionalObject)`.


<a id="cause-AsynchronousRejoinFunctionsUnavailable"></a>

### `AsynchronousRejoinFunctionsUnavailable`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `functions.join.is_none() || functions.complete.is_none()`.


<a id="cause-CaptureNativeStorageAbsent"></a>

### `CaptureNativeStorageAbsent`


Local detection/handling phase and implementation owner:

- `PreparedRejoin::prepare` — `src/advanced/rejoin.rs`. Enclosing true branch: `record.capture`.


<a id="cause-ControlNotDetachable"></a>

### `ControlNotDetachable`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing match alternative: `OperationBody::Control`.


<a id="cause-DetachedCaptureCapacityAbsent"></a>

### `DetachedCaptureCapacityAbsent`


Local detection/handling phase and implementation owner:

- `PreparedRejoin::prepare` — `src/advanced/rejoin.rs`. Enclosing true branch: `record.capture`.


<a id="cause-FailedJoinedFixedOutput"></a>

### `FailedJoinedFixedOutput`


Local detection/handling phase and implementation owner:

- `JoinedResult::project_fixed` — `src/advanced/asynchronous/fixed.rs`. Enclosing true branch: `self.fixed.is_some()`.


<a id="cause-FailedJoinedOutput"></a>

### `FailedJoinedOutput`


Local detection/handling phase and implementation owner:

- `JoinedResult::project` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.output.is_some()`.


<a id="cause-ForeignOrConsumedRejoinTicket"></a>

### `ForeignOrConsumedRejoinTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != self.session.uid || !Arc::ptr_eq(&ticket.owner, &self.session.inner)`.


<a id="cause-GenericMessageAsynchronousModeUnavailable"></a>

### `GenericMessageAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing match alternative: `OperationBody::NativeMessages(_)`.
- `PreparedDestination::prepare_at_epoch` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `r.saved.descriptor.family == record::Family::NativeMessages`.
- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `self.family == Family::NativeMessages`.
- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family == Family::NativeMessages`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `detached`.


<a id="cause-JoinedAsynchronousOutputIdentity"></a>

### `JoinedAsynchronousOutputIdentity`


Local detection/handling phase and implementation owner:

- `JoinedCall::poll` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.result.ulVersion != 0 || self.capacity().is_some() && self.result.pValue != self.output_pointer()`.
- `JoinedCall::poll` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.result.ulVersion != 0 || self.capacity().is_some() && self.result.pValue != self.output_pointer()`.


<a id="cause-JoinedFixedOutputAbsent"></a>

### `JoinedFixedOutputAbsent`


Local detection/handling phase and implementation owner:

- `JoinedResult::project_fixed` — `src/advanced/asynchronous/fixed.rs`.


<a id="cause-JoinedFixedOutputCapacity"></a>

### `JoinedFixedOutputCapacity`

Detected when checking the destination allocation for a joined fixed-size
result (session information or validation flags). Its capacity must equal the
ABI structure's exact size, not merely be larger. This preparation check makes
no native join call. Reject the incompatible prepared owner through the existing
transfer protocol; the original pending operation remains separately owned.
Do not change the declared function/ABI or treat this as a variable-size query.


Local detection/handling phase and implementation owner:

- `FixedOutput::allocation_bytes` — `src/advanced/asynchronous/fixed.rs`. Enclosing true branch: `capacity != Some(size)`.


<a id="cause-JoinedFixedOutputLength"></a>

### `JoinedFixedOutputLength`

Detected after the joined operation reports CKR_OK but the returned fixed-size
result length differs from its ABI size. JoinPhase becomes ReturnedUncertain
and the runtime is marked uncertain. The joined control, output allocation and
original operation remain retained; the result is not transferable through take.
This owner has no buffer-resize retry. Do not rejoin, replay the original call,
or discard its retained storage. Only its completion-aware recovery/cleanup
protocol can establish release; an available cleanup is not promised.


Local detection/handling phase and implementation owner:

- `JoinedCall::poll` — `src/advanced/asynchronous.rs`. Enclosing true branch: `fixed_length.is_some_and(|length| self.result.ulValue != length)`.
- `JoinedCall::poll` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.result.ulValue != fixed_length`.


<a id="cause-JoinedFixedResultShape"></a>

### `JoinedFixedResultShape`


Local detection/handling phase and implementation owner:

- `JoinedResult::project_fixed` — `src/advanced/asynchronous/fixed.rs`. Enclosing true branch: `self.function != function || self.return_value == CKR_PENDING || self.output.is_some()`.


<a id="cause-JoinedFixedResultSizeOrType"></a>

### `JoinedFixedResultSizeOrType`


Local detection/handling phase and implementation owner:

- `JoinedResult::project_fixed` — `src/advanced/asynchronous/fixed.rs`. Enclosing true branch: `!fixed.matches(function) || self.value != bounds::ck_length(fixed.capacity())?`.


<a id="cause-JoinedObjectResultShape"></a>

### `JoinedObjectResultShape`


Local detection/handling phase and implementation owner:

- `JoinedResult::project_objects` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.function != function || self.return_value == CKR_PENDING || self.output.is_some() || self.fixed.is_some()`.


<a id="cause-JoinedPreparedOwnerLayout"></a>

### `JoinedPreparedOwnerLayout`


Local detection/handling phase and implementation owner:

- `JoinedCall::check_prepared` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.phase != JoinPhase::Prepared || self.function != function || self.capacity() != capacity`.


<a id="cause-JoinedResultFunctionOrPhase"></a>

### `JoinedResultFunctionOrPhase`


Local detection/handling phase and implementation owner:

- `JoinedResult::project` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.function != function || self.return_value == CKR_PENDING || self.fixed.is_some()`.


<a id="cause-JoinedResultOutputKind"></a>

### `JoinedResultOutputKind`


Local detection/handling phase and implementation owner:

- `JoinedResult::project` — `src/advanced/asynchronous.rs`. Enclosing match alternative: `_`.


<a id="cause-JoinedResultOutputShape"></a>

### `JoinedResultOutputShape`


Local detection/handling phase and implementation owner:

- `JoinedResult::project` — `src/advanced/asynchronous.rs`. Enclosing true branch: `output.capacity() != target.len() || output.as_slice().len() != length`.


<a id="cause-JoinedResultUnavailable"></a>

### `JoinedResultUnavailable`


Local detection/handling phase and implementation owner:

- `JoinedCall::take` — `src/advanced/asynchronous.rs`. Enclosing true branch: `self.phase != JoinPhase::Complete || !crate::native_return::call_memory_returned(self.return_value)`.
- `JoinedCall::take` — `src/advanced/asynchronous.rs`.


<a id="cause-JoinedStateSizeResultShape"></a>

### `JoinedStateSizeResultShape`


Local detection/handling phase and implementation owner:

- `JoinedResult::project_state_size` — `src/advanced/asynchronous/fixed.rs`. Enclosing true branch: `self.function != "C_GetOperationState" || self.return_value == CKR_PENDING || self.output.is_some() || self.fixed.is_some()`.


<a id="cause-JoinedStorageAccounting"></a>

### `JoinedStorageAccounting`


Local detection/handling phase and implementation owner:

- `JoinPlan::new` — `src/advanced/asynchronous.rs`.
- `JoinPlan::allocation_bytes` — `src/advanced/asynchronous.rs`.
- `JoinStorage::allocated_bytes` — `src/advanced/asynchronous.rs`.


<a id="cause-NativeAesAsynchronousModeUnavailable"></a>

### `NativeAesAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing match alternative: `OperationBody::Cipher(_)`.


<a id="cause-OperationNotDetachable"></a>

### `OperationNotDetachable`


Local detection/handling phase and implementation owner:

- `GetId::checked_function` — `src/advanced/asynchronous.rs`. Enclosing true branch: `operation.cancellation.is_withdrawn() || operation.continuation_status.is_frozen() && operation.restore_owner().is_none() || operation.cancel.is_submitted() || operation .joined .as_ref() .is_some_and(|c| c.phase != JoinPhase::Attached)`.


<a id="cause-OperationNotPending"></a>

### `OperationNotPending`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing true branch: `!operation.body.pending()`.


<a id="cause-RejoinAbsent"></a>

### `RejoinAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_rejoin` — `src/advanced/rejoin.rs`.


<a id="cause-RejoinInspectionAbsent"></a>

### `RejoinInspectionAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_rejoin` — `src/advanced/rejoin.rs`.


<a id="cause-RejoinOutputStorageAbsent"></a>

### `RejoinOutputStorageAbsent`


Local detection/handling phase and implementation owner:

- `PreparedRejoin::prepare` — `src/advanced/rejoin.rs`.


<a id="cause-RejoinOwnerAdapterAbsent"></a>

### `RejoinOwnerAdapterAbsent`


Local detection/handling phase and implementation owner:

- `check_keys` (module-level helper) — `src/advanced/rejoin.rs`. Enclosing match alternative: `_`.


<a id="cause-RejoinPreparationAbsent"></a>

### `RejoinPreparationAbsent`


Local detection/handling phase and implementation owner:

- `PreparedRejoin::bind_retained` — `src/advanced/rejoin.rs`.


<a id="cause-SignatureAsynchronousModeUnavailable"></a>

### `SignatureAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing match alternative: `OperationBody::Signature(_)`.
- `SignatureOperation::drive` — `src/advanced/signature.rs`. Enclosing true branch: `self.pending()`.
- `Descriptor::validate_terminal` — `src/advanced/record/terminal.rs`. Enclosing true branch: `self.family == Family::Signature`.
- `RecordPlan<'a>::new` — `src/advanced/signature/checkpoint.rs`. Enclosing true branch: `pending`.
- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `detached`.


<a id="cause-SignatureRecoveryAsynchronousModeUnavailable"></a>

### `SignatureRecoveryAsynchronousModeUnavailable`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing match alternative: `OperationBody::Recover(_)`.
- `RecoverOperation::output_preparation` — `src/advanced/recover.rs`. Enclosing true branch: `self.pending()`.
- `RecoverOperation::drive` — `src/advanced/recover.rs`. Enclosing true branch: `self.pending()`.
- `synchronous` (module-level helper) — `src/advanced/recover/api.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.
- `RecordPlan<'a>::new` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `pending`.
- `Descriptor::validate_detached` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `self.family.is_recover()`.
- `Descriptor::validate_mode` — `src/advanced/record/checkpoint/validation.rs`. Enclosing true branch: `detached`.


<a id="cause-StaleRejoinTicket"></a>

### `StaleRejoinTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::poll_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `op.id != ticket.id`.


<a id="cause-StateControlNotPending"></a>

### `StateControlNotPending`


Local detection/handling phase and implementation owner:

- `pending_function` (module-level helper) — `src/advanced/asynchronous.rs`. Enclosing true branch: `!control.pending()`.
- `StateIo::joined_capacity` — `src/advanced/state_io.rs`. Enclosing true branch: `!self.pending`.

