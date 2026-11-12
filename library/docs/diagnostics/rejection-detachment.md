Cause contracts for `DetachmentRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AsynchronousDetachmentSessionMode"></a>

### `AsynchronousDetachmentSessionMode`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `self.mode() != AdvancedSessionMode::Asynchronous`.
- `AdvancedSession::start_restore_detachment` — `src/advanced/restoration_transfer.rs`. Enclosing true branch: `self.mode() != AdvancedSessionMode::Asynchronous`.


<a id="cause-ConflictingDetachmentOwners"></a>

### `ConflictingDetachmentOwners`


Local detection/handling phase and implementation owner:

- `DetachKind::select` — `src/advanced/detachment.rs`. Enclosing match alternative: `_`.


<a id="cause-DetachmentAbsent"></a>

### `DetachmentAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::drive_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `op.detachment().is_none()`.
- `AdvancedSession::drive_detachment` — `src/advanced/detachment.rs`. Enclosing match alternative: `Ok(DetachmentProgress::Ready)`.
- `AdvancedSession::write_detachment_record` — `src/advanced/detachment.rs`.
- `AdvancedSession::finish_detachment` — `src/advanced/detachment.rs`.
- `AdvancedSession::advance_detachment` — `src/advanced/detachment.rs`.


<a id="cause-DetachmentCaptureOwnerAbsent"></a>

### `DetachmentCaptureOwnerAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `let Some(io) = op.state_io()`.


<a id="cause-DetachmentContextAbsent"></a>

### `DetachmentContextAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::drive_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `let Some((bytes, _, waiter, publication)) = prepared.as_mut()`.
- `AdvancedSession::write_detachment_record` — `src/advanced/detachment.rs`.


<a id="cause-DetachmentNativeStateUncertain"></a>

### `DetachmentNativeStateUncertain`


Local detection/handling phase and implementation owner:

- `AdvancedSession::advance_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `control.get_id.retains_native_memory()`.


<a id="cause-DetachmentOwnerAdapterNotIntegrated"></a>

### `DetachmentOwnerAdapterNotIntegrated`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `!matches!( op.body, OperationBody::Digest(_) | OperationBody::Messages(_) | OperationBody::AeadMessages(_) | OperationBody::Dual(_) ) && !(matches!(op.body, OperationBody::Control) && op.capture_owner().is_some())`.


<a id="cause-DetachmentPublicationCreditAbsent"></a>

### `DetachmentPublicationCreditAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::finish_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `control.publication_credit.is_none()`.


<a id="cause-DetachmentRecordCeiling"></a>

### `DetachmentRecordCeiling`


Local detection/handling phase and implementation owner:

- `limits` (module-level helper) — `src/advanced/detachment.rs`. Enclosing true branch: `maximum < 17 || maximum > isize::MAX as usize`.


<a id="cause-DetachmentRecordPhaseChanged"></a>

### `DetachmentRecordPhaseChanged`


Local detection/handling phase and implementation owner:

- `AdvancedSession::drive_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `*publication != control.id.is_some()`.
- `AdvancedSession::write_detachment_record` — `src/advanced/detachment.rs`. Enclosing true branch: `publication != control.id.is_some()`.


<a id="cause-DetachmentStorageAccounting"></a>

### `DetachmentStorageAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/detachment/preparation.rs`.
- `prepare` (module-level helper) — `src/advanced/detachment/preparation.rs`.
- `prepare` (module-level helper) — `src/advanced/detachment/preparation.rs`.


<a id="cause-NonterminalValidationAdapterNotIntegrated"></a>

### `NonterminalValidationAdapterNotIntegrated`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `terminal && !op.body.complete()`.
