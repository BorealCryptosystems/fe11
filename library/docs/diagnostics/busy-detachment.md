Cause contracts for `DetachmentBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-RestorationRequiresItsTransferTicket"></a>

### `RestorationRequiresItsTransferTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `op.restore_owner().is_some()`.
- `Operation::begin_detachment` — `src/advanced/ownership.rs`. Enclosing true branch: `self.restore_owner().is_some()`.
