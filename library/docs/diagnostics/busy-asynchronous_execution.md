Cause contracts for `AsynchronousExecutionBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-OperationTransferActive"></a>

### `OperationTransferActive`


Local detection/handling phase and implementation owner:

- `OwnerSlot<TransferOwner>::begin_detachment` — `src/advanced/ownership.rs`.
- `OwnerSlot<TransferOwner>::begin_rejoin` — `src/advanced/ownership.rs`.
- `OwnerSlot<TransferOwner>::begin_restore_transfer` — `src/advanced/ownership.rs`.
- `AdvancedSession::start_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `next.transfer.as_ref().is_some()`.


<a id="cause-RejoinDestinationActive"></a>

### `RejoinDestinationActive`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_rejoin` — `src/advanced/rejoin.rs`. Enclosing true branch: `self .session .entry .advanced_operation .load(Ordering::Acquire) != 0`.
