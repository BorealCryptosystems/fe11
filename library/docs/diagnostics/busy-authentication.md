Cause contracts for `AuthenticationBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-OperationControlInProgress"></a>

### `OperationControlInProgress`

Detected before a control/authentication or continuation access is admitted.
It can include incomplete native execution and retained observation memory,
not just an active state-control object. No Login or continuation is dispatched
by this check.

This is a local admission barrier while the existing operation and all of
its input/output, key and control owners remain in the session ledger. It is
not necessarily a temporary mutex conflict. The alternatives have different
consequences:

* A state capture/restore, detachment or rejoin control must be driven through
  its existing control API (`poll_state_capture`, `poll_state_restore`,
  `poll_detachment`, `poll_rejoin`, or `poll_restore_detachment` as applicable).
  Keep that control's ticket/return owner. Completing it can transfer or freeze
  the original continuation; removal of the control alone does not make the
  original request admissible.
* A submitted cancellation is observed through `poll_cancellation`, not by
  sending another cancellation or replaying the cryptographic request. Once
  cancellation has withdrawn the continuation, it cannot be resumed, even
  after the cancellation control itself disappears.
* A frozen continuation was captured/transferred under its own protocol.
  Waiting does not thaw it. Use the resulting saved/detached owner through its
  restore/rejoin contract; do not resume the original ticket.
* An attached asynchronous result must be resolved through the existing
  operation's polling protocol. A failed projection can deliberately retain
  the joined control. Do not discard it or repeat the original native call.
* Where the listed predicate includes pending validation or retained native
  observations, completion/cleanup belongs to that existing observation owner.
  A returned anomaly can retain memory without permitting another native poll.

Only after the corresponding protocol has completed, the same continuation
is still runnable/uncancelled, and all controls covered by the local predicate
are absent may this local admission be attempted again. Its ordinary identity,
key, authentication and input-boundary checks still apply. There is no automatic
wait-for-control loop: `WaitUntil` is local resource admission, not proof that
any of these state transitions occurred. When the owner reports an irreversible
withdrawal, freeze or uncertain completion, no retry of this request is established.



Local detection/handling phase and implementation owner:

- `Operation::check_control_state` — `src/advanced/authentication.rs`. Enclosing true branch: `self.body.pending() || self.uncancellable_retained() || self.cancel.is_submitted() || self.joined.is_some() || self.state.as_ref().is_some() || self.transfer.as_ref().is_some() || self.continuation_status.is_frozen() || self.cancellation.is_withdrawn()`.
