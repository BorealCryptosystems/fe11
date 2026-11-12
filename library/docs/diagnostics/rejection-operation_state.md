Cause contracts for `OperationStateRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGetOperationStateUnavailable"></a>

### `CGetOperationStateUnavailable`


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/state_io/resolved_call.rs`.


<a id="cause-CGetSessionInfoUnavailable"></a>

### `CGetSessionInfoUnavailable`


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/state_io/resolved_call.rs`. Enclosing match alternative: `Phase::Info`.


<a id="cause-CancelledStateCapture"></a>

### `CancelledStateCapture`


Local detection/handling phase and implementation owner:

- `AdvancedSession::capture_control` — `src/advanced/saved_state.rs`. Enclosing match alternative: `CaptureAdvance::NeedBuffer(_)`.
- `AdvancedSession::advance_state_capture` — `src/advanced/saved_state.rs`. Enclosing true branch: `withdrawn`.


<a id="cause-CaptureSessionState"></a>

### `CaptureSessionState`


Local detection/handling phase and implementation owner:

- `StateIo::capture_metadata` — `src/advanced/state_io.rs`. Enclosing true branch: `!session_state(self.info.state)`.
- `StateIo::joined_capture_prepaid` — `src/advanced/state_io.rs`. Enclosing true branch: `!session_state(state)`.


<a id="cause-DuplicateStateCompletion"></a>

### `DuplicateStateCompletion`


Local detection/handling phase and implementation owner:

- `StateIo::advance` — `src/advanced/state_io/progression.rs`. Enclosing match alternative: `_`.


<a id="cause-FinalStateCaptureRequired"></a>

### `FinalStateCaptureRequired`


Local detection/handling phase and implementation owner:

- `StateIo::capture_metadata` — `src/advanced/state_io.rs`. Enclosing true branch: `!matches!(self.flow.direction(), Direction::Capture { .. }) || self.flow.phase() != Phase::Bytes || self.captured()`.


<a id="cause-OperationStateCeiling"></a>

### `OperationStateCeiling`


Local detection/handling phase and implementation owner:

- `StateIo::validate_capture_maximum` — `src/advanced/state_io.rs`. Enclosing true branch: `maximum == 0 || maximum > isize::MAX as usize`.


<a id="cause-OperationStateSession"></a>

### `OperationStateSession`


Local detection/handling phase and implementation owner:

- `StateIo::prepare_restore_prepaid` — `src/advanced/state_io.rs`. Enclosing true branch: `!session_state(expected)`.


<a id="cause-OperationStateSessionIdentity"></a>

### `OperationStateSessionIdentity`


Local detection/handling phase and implementation owner:

- `validate_info` (module-level helper) — `src/advanced/state_io.rs`. Enclosing true branch: `info.slotID != slot || !session_state(info.state) || (info.flags & CKF_RW_SESSION != 0) != read_write`.


<a id="cause-OperationStateSessionMismatch"></a>

### `OperationStateSessionMismatch`


Local detection/handling phase and implementation owner:

- `StateIo::advance` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.info.state != expected`.


<a id="cause-PreparatoryStateCaptureDetachmentDeferred"></a>

### `PreparatoryStateCaptureDetachmentDeferred`


Local detection/handling phase and implementation owner:

- `StateIo::check_detachment` — `src/advanced/state_io.rs`. Enclosing true branch: `matches!(self.flow.direction(), Direction::Capture { .. }) && matches!( self.flow.phase(), Phase::Info | Phase::Size | Phase::Sized { .. } )`.


<a id="cause-RestorationInputAbsent"></a>

### `RestorationInputAbsent`


Local detection/handling phase and implementation owner:

- `StateIo::restore_input` — `src/advanced/state_io.rs`.


<a id="cause-RestorationInputLength"></a>

### `RestorationInputLength`


Local detection/handling phase and implementation owner:

- `StateIo::restore_input_length` — `src/advanced/state_io.rs`.
- `StateIo::restore_input` — `src/advanced/state_io.rs`. Enclosing true branch: `bytes.len() != length`.


<a id="cause-RestorationInputStillNativeOwned"></a>

### `RestorationInputStillNativeOwned`


Local detection/handling phase and implementation owner:

- `StateIo::restore_input` — `src/advanced/state_io.rs`. Enclosing true branch: `self.pending`.


<a id="cause-RestorationStateAbsent"></a>

### `RestorationStateAbsent`


Local detection/handling phase and implementation owner:

- `StateIo::take_refused_restore` — `src/advanced/state_io.rs`.


<a id="cause-RestorationStateNotRecoverable"></a>

### `RestorationStateNotRecoverable`


Local detection/handling phase and implementation owner:

- `StateIo::take_refused_restore` — `src/advanced/state_io.rs`. Enclosing true branch: `self.pending || self.complete() || !matches!(self.flow.direction(), Direction::Restore { .. })`.


<a id="cause-RestorationTransferFunction"></a>

### `RestorationTransferFunction`


Local detection/handling phase and implementation owner:

- `StateIo::mark_joined_restore` — `src/advanced/state_io.rs`. Enclosing match alternative: `_`.


<a id="cause-RestorationTransferPhase"></a>

### `RestorationTransferPhase`


Local detection/handling phase and implementation owner:

- `StateIo::restore_input_length` — `src/advanced/state_io.rs`. Enclosing true branch: `!matches!(self.flow.direction(), Direction::Restore { .. }) || !matches!(self.flow.phase(), Phase::Info | Phase::Restore)`.


<a id="cause-SessionInspectionIncomplete"></a>

### `SessionInspectionIncomplete`


Local detection/handling phase and implementation owner:

- `StateIo::inspected_state` — `src/advanced/state_io.rs`. Enclosing true branch: `!self.complete() || !matches!(self.flow.direction(), Direction::Inspect)`.


<a id="cause-StateIoAbsent"></a>

### `StateIoAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::advance_state_capture` — `src/advanced/saved_state.rs`.
- `AdvancedSession::advance_state_capture` — `src/advanced/saved_state.rs`.


<a id="cause-StateIoFailed"></a>

### `StateIoFailed`


Local detection/handling phase and implementation owner:

- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.flow.phase() == Phase::Failed`.


<a id="cause-StateIoNotActive"></a>

### `StateIoNotActive`


Local detection/handling phase and implementation owner:

- `Flow::transition` — `src/advanced/state_io.rs`. Enclosing match alternative: `_`.
- `Flow::transition` — `src/advanced/state_io.rs`. Enclosing match alternative: `_`.
- `Flow::transition` — `src/advanced/state_io.rs`. Enclosing match alternative: `Phase::Info | Phase::Size | Phase::Sized { .. } if owns_buffer`.
- `Flow::transition` — `src/advanced/state_io.rs`. Enclosing match alternative: `Phase::Restore`.
- `StateIo::new_prepaid` — `src/advanced/state_io.rs`. Enclosing match alternative: `(Direction::Inspect, Some(_))`.
- `StateIo::bind_restore_keys` — `src/advanced/state_io.rs`.
- `StateIo::function` — `src/advanced/state_io.rs`. Enclosing match alternative: `_`.
- `StateIo::joined_capacity` — `src/advanced/state_io.rs`. Enclosing match alternative: `_`.
- `StateIo::accept_joined` — `src/advanced/state_io.rs`. Enclosing match alternative: `_`.
- `Call::resolve` — `src/advanced/state_io/resolved_call.rs`. Enclosing match alternative: `Phase::Restore`.
- `Call::resolve` — `src/advanced/state_io/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-StateAlreadyConsumed"></a>

### `StateAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `StateIo::take_capture` — `src/advanced/state_io.rs`.


<a id="cause-StateAsynchronousOutputIdentity"></a>

### `StateAsynchronousOutputIdentity`


Local detection/handling phase and implementation owner:

- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.completion.pValue != pointer`.
- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.completion.pValue != pointer`.


<a id="cause-StateAsynchronousVersion"></a>

### `StateAsynchronousVersion`


Local detection/handling phase and implementation owner:

- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.completion.ulVersion != 0`.
- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.completion.ulVersion != 0`.


<a id="cause-StateCaptureAbsent"></a>

### `StateCaptureAbsent`


Local detection/handling phase and implementation owner:

- `AdvancedSession::capture_control` — `src/advanced/saved_state.rs`. Enclosing true branch: `operation.capture_owner().is_none() || operation.state_io().is_none()`.


<a id="cause-StateCaptureIncomplete"></a>

### `StateCaptureIncomplete`


Local detection/handling phase and implementation owner:

- `StateIo::take_capture` — `src/advanced/state_io.rs`. Enclosing true branch: `!self.complete() || !matches!(self.flow.direction(), Direction::Capture { .. })`.


<a id="cause-StateCapturePreparationChanged"></a>

### `StateCapturePreparationChanged`


Local detection/handling phase and implementation owner:

- `StateIo::attach_capture_buffer` — `src/advanced/state_io.rs`.
- `StateIo::attach_capture_buffer` — `src/advanced/state_io.rs`. Enclosing true branch: `self.pending || bytes.capacity() != length || self.flow.bytes().is_some()`.


<a id="cause-StateOutputAbsent"></a>

### `StateOutputAbsent`


Local detection/handling phase and implementation owner:

- `Flow::transition` — `src/advanced/state_io.rs`. Enclosing match alternative: `Phase::Bytes | Phase::Done if !owns_buffer`.
- `StateIo::capture_metadata` — `src/advanced/state_io.rs`.
- `StateIo::joined_capacity` — `src/advanced/state_io.rs`. Enclosing match alternative: `Phase::Bytes`.
- `StateIo::accept_joined` — `src/advanced/state_io.rs`. Enclosing match alternative: `Phase::Bytes`.


<a id="cause-StateSizeDirection"></a>

### `StateSizeDirection`


Local detection/handling phase and implementation owner:

- `StateIo::accept_joined` — `src/advanced/state_io.rs`. Enclosing match alternative: `Phase::Size`.

