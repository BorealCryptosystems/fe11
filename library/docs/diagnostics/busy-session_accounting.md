Cause contracts for `SessionAccountingBusy`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-SessionCapacity"></a>

### `SessionCapacity`


Local detection/handling phase and implementation owner:

- `SessionLedger::reserve_waiting` — `src/session_budget/reservation.rs`. Enclosing match alternative: `Err(Error::Rejected(crate::RejectionReason::SessionAccounting( crate::SessionAccountingRejection::SessionLimit, )))`.


<a id="cause-SessionReservationOrRecoveryActive"></a>

### `SessionReservationOrRecoveryActive`


Local detection/handling phase and implementation owner:

- `SessionLedger::finalization_candidates` — `src/session_budget/close.rs`. Enclosing true branch: `matches!(record.phase(), Some(Phase::Reserved | Phase::Opening)) || record.recovery_active()`.


<a id="cause-UnpublishedNativeSession"></a>

### `UnpublishedNativeSession`


Local detection/handling phase and implementation owner:

- `SessionLedger::finalization_candidates` — `src/session_budget/close.rs`.
- `SessionLedger::seal_recovery` — `src/session_budget/recovery.rs`.

