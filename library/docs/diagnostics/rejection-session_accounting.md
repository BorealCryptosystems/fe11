Cause contracts for `SessionAccountingRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AmbiguousSessionOwner"></a>

### `AmbiguousSessionOwner`


Local detection/handling phase and implementation owner:

- `SessionLedger::publish` — `src/session_budget/reservation.rs`. Enclosing true branch: `owners.next().is_some()`.
- `SessionLedger::for_handle` — `src/session_budget/status.rs`. Enclosing true branch: `found.next().is_some()`.


<a id="cause-AuthenticationRequiresSession"></a>

### `AuthenticationRequiresSession`


Local detection/handling phase and implementation owner:

- `SessionLedger::usable_for` — `src/session_budget/access.rs`.


<a id="cause-DuplicateSessionPolicyToken"></a>

### `DuplicateSessionPolicyToken`


Local detection/handling phase and implementation owner:

- `SessionPolicy::validate` — `src/session_budget/policy.rs`. Enclosing true branch: `self.tokens[..i] .iter() .any(|other| other.identity == entry.identity)`.


<a id="cause-FinalizationOwnersNotSealed"></a>

### `FinalizationOwnersNotSealed`


Local detection/handling phase and implementation owner:

- `SessionLedger::take_finalized` — `src/session_budget/close.rs`. Enclosing true branch: `!matches!(state.admission, ReservationAdmission::Sealed) || state .records .values() .any(|r| matches!(r, Record::Live { .. }))`.


<a id="cause-FinalizationOwnershipChanged"></a>

### `FinalizationOwnershipChanged`


Local detection/handling phase and implementation owner:

- `SessionLedger::seal_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `!entries .iter() .any(|e| e.credit.uid() == uid && Arc::ptr_eq(e, entry)) || matches!(record.phase(), Some(Phase::Reserved | Phase::Opening)) || record.recovery_active()`.


<a id="cause-FinalizationPopulationChanged"></a>

### `FinalizationPopulationChanged`


Local detection/handling phase and implementation owner:

- `SessionLedger::seal_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `entries.len() != state.records.len()`.


<a id="cause-FinalizationSnapshotAllocation"></a>

### `FinalizationSnapshotAllocation`


Local detection/handling phase and implementation owner:

- `SessionLedger::finalization_candidates` — `src/session_budget/close.rs`.


<a id="cause-LiveProviderSessionCollision"></a>

### `LiveProviderSessionCollision`


Local detection/handling phase and implementation owner:

- `SessionLedger::publish` — `src/session_budget/reservation.rs`. Enclosing true branch: `!(retired && quiet.is_some()) && (!owner.close_attempted.load(Ordering::Acquire) || !(owned || quiet.is_some()))`.


<a id="cause-ModuleSessionAdmissionClosed"></a>

### `ModuleSessionAdmissionClosed`


Local detection/handling phase and implementation owner:

- `SessionLedger::reserve` — `src/session_budget/reservation.rs`. Enclosing true branch: `matches!(state.admission, ReservationAdmission::Sealed)`.
- `SessionLedger::dispatch_open` — `src/session_budget/reservation.rs`. Enclosing true branch: `matches!(state.admission, ReservationAdmission::Sealed)`.


<a id="cause-PendingCloseHandleCollision"></a>

### `PendingCloseHandleCollision`


Local detection/handling phase and implementation owner:

- `SessionLedger::publish` — `src/session_budget/reservation.rs`. Enclosing true branch: `owner.close_pending.load(Ordering::Acquire)`.


<a id="cause-PredecessorSessionAdmissionNotSealed"></a>

### `PredecessorSessionAdmissionNotSealed`


Local detection/handling phase and implementation owner:

- `SessionLedger::successor` — `src/session_budget/status.rs`. Enclosing true branch: `!matches!( previous .state .lock() .map_err(|_| Error::Poisoned)? .admission, ReservationAdmission::Sealed )`.


<a id="cause-PredecessorSessionAdmissionReopened"></a>

### `PredecessorSessionAdmissionReopened`


Local detection/handling phase and implementation owner:

- `SessionLedger::inherited_counts` — `src/session_budget/status.rs`. Enclosing true branch: `!matches!(state.admission, ReservationAdmission::Sealed)`.


<a id="cause-RecoveryAlreadyStarted"></a>

### `RecoveryAlreadyStarted`


Local detection/handling phase and implementation owner:

- `SessionLedger::start_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `batch.started`.


<a id="cause-RecoveryOwnerAbsent"></a>

### `RecoveryOwnerAbsent`


Local detection/handling phase and implementation owner:

- `SessionLedger::start_recovery` — `src/session_budget/recovery.rs`.
- `SessionLedger::finish_recovery` — `src/session_budget/recovery.rs`.


<a id="cause-RecoveryStateMismatch"></a>

### `RecoveryStateMismatch`


Local detection/handling phase and implementation owner:

- `SessionLedger::start_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `record.recovering(record.identity().proof.ticket.load(Ordering::Acquire))`.
- `SessionLedger::record_recovery_completion` — `src/session_budget/recovery.rs`. Enclosing true branch: `!valid`.
- `SessionLedger::finish_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, &item.proof) || !record.recovering(batch.ticket)`.


<a id="cause-RecoveryTicketExhausted"></a>

### `RecoveryTicketExhausted`


Local detection/handling phase and implementation owner:

- `SessionLedger::begin_close` — `src/session_budget/close.rs`.
- `SessionLedger::prepare_recovery_selected` — `src/session_budget/recovery.rs`.


<a id="cause-RecoveryTicketMismatch"></a>

### `RecoveryTicketMismatch`


Local detection/handling phase and implementation owner:

- `SessionCredit::collective_completion` — `src/session_budget/collective.rs`. Enclosing match alternative: `CloseAttempt::Collective { .. }`.
- `SessionLedger::finish_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `item.proof.ticket.load(Ordering::Acquire) != batch.ticket`.


<a id="cause-SessionCloseState"></a>

### `SessionCloseState`


Local detection/handling phase and implementation owner:

- `SessionLedger::begin_close` — `src/session_budget/close.rs`. Enclosing true branch: `!Arc::ptr_eq(&r.identity().proof, proof) || !(r.live_native() || matches!( r, Record::RetainedReturned { recovery: RetentionRecovery::AwaitingProof, .. } )) || matches!(r.phase(), Some(Phase::Closing | Phase::Recovering))`.


<a id="cause-SessionClosingOwnership"></a>

### `SessionClosingOwnership`


Local detection/handling phase and implementation owner:

- `SessionLedger::complete_close` — `src/session_budget/close.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, proof) || !record.closing(ticket)`.


<a id="cause-SessionCountInvariant"></a>

### `SessionCountInvariant`


Local detection/handling phase and implementation owner:

- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `!reused`.
- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `!reused`.
- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `total.total != state.total.total || total.read_write != state.total.read_write`.
- `Counts::release` — `src/session_budget/record.rs`.
- `Counts::release` — `src/session_budget/record.rs`.
- `SessionLedger::settle_quota` — `src/session_budget/status.rs`.


<a id="cause-SessionCountOverflow"></a>

### `SessionCountOverflow`


Local detection/handling phase and implementation owner:

- `Counts::combine` — `src/session_budget/record.rs`.
- `Counts::combine` — `src/session_budget/record.rs`.
- `Counts::acquire` — `src/session_budget/record.rs`.
- `Counts::acquire` — `src/session_budget/record.rs`.


<a id="cause-SessionDispatchReservation"></a>

### `SessionDispatchReservation`


Local detection/handling phase and implementation owner:

- `SessionLedger::dispatch_open` — `src/session_budget/reservation.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, proof) || proof.terminal.load(Ordering::Acquire) != 0 || record.phase() != Some(Phase::Reserved)`.


<a id="cause-SessionGenerationExhausted"></a>

### `SessionGenerationExhausted`


Local detection/handling phase and implementation owner:

- `SessionLedger::reserve` — `src/session_budget/reservation.rs`.


<a id="cause-SessionLedgerEntryInvariant"></a>

### `SessionLedgerEntryInvariant`


Local detection/handling phase and implementation owner:

- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `entry.credit.uid() != uid || !Arc::ptr_eq(&entry.credit.proof, &identity.proof) || entry.snapshot.generation != identity.generation || entry.snapshot.capabilities.identity != identity.token`.


<a id="cause-SessionLedgerIdentityInvariant"></a>

### `SessionLedgerIdentityInvariant`


Local detection/handling phase and implementation owner:

- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `uid == 0 || uid > state.next_uid || identity.proof.terminal.load(Ordering::Acquire) != if reused { 2 } else { 0 }`.


<a id="cause-SessionLimit"></a>

### `SessionLimit`


Local detection/handling phase and implementation owner:

- `Counts::within` — `src/session_budget/record.rs`. Enclosing true branch: `self.total > limit.total || self.read_write > limit.read_write`.
- `Counts::acquire` — `src/session_budget/record.rs`. Enclosing true branch: `total > limit.total || read_write > limit.read_write`.
- `SessionLedger::reserve_waiting` — `src/session_budget/reservation.rs`. Enclosing true branch: `self.module.total == 0 || limit.total == 0 || (rw && (self.module.read_write == 0 || limit.read_write == 0))`.
- `SessionLedger::reserve_waiting` — `src/session_budget/reservation.rs`. Enclosing match alternative: `Err(Error::Rejected(crate::RejectionReason::SessionAccounting( crate::SessionAccountingRejection::SessionLimit, )))`.


<a id="cause-SessionLossOwnerMismatch"></a>

### `SessionLossOwnerMismatch`


Local detection/handling phase and implementation owner:

- `SessionCredit::record_handle_loss` — `src/session_budget/reservation.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, &self.proof)`.


<a id="cause-SessionOwnerAbsent"></a>

### `SessionOwnerAbsent`


Local detection/handling phase and implementation owner:

- `SessionCredit::record_handle_loss` — `src/session_budget/reservation.rs`.
- `SessionLedger::for_handle` — `src/session_budget/status.rs`.


<a id="cause-SessionOwnerMismatch"></a>

### `SessionOwnerMismatch`


Local detection/handling phase and implementation owner:

- `SessionLedger::retain_without_handle` — `src/session_budget/access.rs`. Enclosing true branch: `!matches!( record, Record::Live { entry: Some(_), .. } | Record::RetainedReturned { .. } ) || record.identity().proof.terminal.load(Ordering::Acquire) != 0`.
- `SessionCredit::collective_completion` — `src/session_budget/collective.rs`. Enclosing true branch: `!Arc::ptr_eq(&identity.proof, &self.proof)`.
- `SessionLedger::remove` — `src/session_budget/status.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, proof)`.
- `SessionLedger::remove` — `src/session_budget/status.rs`. Enclosing true branch: `proof.terminal.load(Ordering::Acquire) != QUOTA_UNSETTLED`.
- `SessionLedger::remove` — `src/session_budget/status.rs`. Enclosing true branch: `terminal != RECORD_REMOVED || proof.terminal.load(Ordering::Acquire) != QUOTA_SETTLED_RETAINED`.
- `SessionLedger::settle_quota` — `src/session_budget/status.rs`.
- `SessionLedger::phase` — `src/session_budget/status.rs`. Enclosing true branch: `!Arc::ptr_eq(&record.identity().proof, proof)`.


<a id="cause-SessionOwnerReleased"></a>

### `SessionOwnerReleased`


Local detection/handling phase and implementation owner:

- `SessionCredit::owner` — `src/session_budget/reservation.rs`.


<a id="cause-SessionPublicationState"></a>

### `SessionPublicationState`


Local detection/handling phase and implementation owner:

- `SessionLedger::publish` — `src/session_budget/reservation.rs`. Enclosing true branch: `r.phase() != Some(Phase::Opening) || r.entry().is_some() || !Arc::ptr_eq(&r.identity().proof, &entry.credit.proof)`.


<a id="cause-SessionRegistryAllocation"></a>

### `SessionRegistryAllocation`


Local detection/handling phase and implementation owner:

- `SessionLedger::reserve` — `src/session_budget/reservation.rs`.
- `SessionLedger::reserve` — `src/session_budget/reservation.rs`. Enclosing true branch: `!state.tokens.contains_key(token)`.


<a id="cause-SessionReservationAbsent"></a>

### `SessionReservationAbsent`


Local detection/handling phase and implementation owner:

- `SessionLedger::retain_without_handle` — `src/session_budget/access.rs`.
- `SessionLedger::begin_close` — `src/session_budget/close.rs`.
- `SessionLedger::complete_close` — `src/session_budget/close.rs`.
- `SessionCredit::collective_completion` — `src/session_budget/collective.rs`.
- `SessionCredit::collective_completion` — `src/session_budget/collective.rs`.
- `SessionLedger::publish` — `src/session_budget/reservation.rs`.
- `SessionLedger::dispatch_open` — `src/session_budget/reservation.rs`.
- `SessionLedger::remove` — `src/session_budget/status.rs`.
- `SessionLedger::settle_quota` — `src/session_budget/status.rs`.
- `SessionLedger::phase` — `src/session_budget/status.rs`.


<a id="cause-SessionReservationAlreadyReleased"></a>

### `SessionReservationAlreadyReleased`


Local detection/handling phase and implementation owner:

- `SessionLedger::release` — `src/session_budget/access.rs`. Enclosing true branch: `proof.terminal.load(Ordering::Acquire) != 0`.


<a id="cause-SessionSnapshotAllocation"></a>

### `SessionSnapshotAllocation`


Local detection/handling phase and implementation owner:

- `SessionLedger::entries_for_close` — `src/session_budget/close.rs`.
- `SessionLedger::local_candidates` — `src/session_budget/status.rs`.
- `SessionLedger::local_candidates` — `src/session_budget/status.rs`.
- `SessionLedger::deferred_for` — `src/session_budget/status.rs`.
- `SessionLedger::status` — `src/session_budget/status.rs`.
- `SessionLedger::local_status` — `src/session_budget/status.rs`.
- `SessionLedger::local_status` — `src/session_budget/status.rs`. Enclosing false branch: `let Some(i) = indices.get(&key)`.
- `SessionLedger::local_status` — `src/session_budget/status.rs`. Enclosing false branch: `let Some(i) = indices.get(&key)`.


<a id="cause-SessionStatusOverflow"></a>

### `SessionStatusOverflow`


Local detection/handling phase and implementation owner:

- `SessionUsage::combine` — `src/session_budget/status.rs`.


<a id="cause-SessionTokenCountInvariant"></a>

### `SessionTokenCountInvariant`


Local detection/handling phase and implementation owner:

- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `!state.tokens.contains_key(&identity.token)`.
- `SessionLedger::validate_metadata` — `src/session_budget/access.rs`. Enclosing true branch: `actual.total != count.total || actual.read_write != count.read_write || count.total == 0`.


<a id="cause-SessionsActive"></a>

### `SessionsActive`


Local detection/handling phase and implementation owner:

- `SessionLedger::seal_empty` — `src/session_budget/status.rs`. Enclosing true branch: `!state.records.is_empty()`.


<a id="cause-StaleClosingTicket"></a>

### `StaleClosingTicket`


Local detection/handling phase and implementation owner:

- `SessionLedger::complete_close` — `src/session_budget/close.rs`. Enclosing true branch: `ticket == 0 || proof.ticket.load(Ordering::Acquire) != ticket`.


<a id="cause-StaleRecoveryCompletion"></a>

### `StaleRecoveryCompletion`


Local detection/handling phase and implementation owner:

- `SessionLedger::record_recovery_completion` — `src/session_budget/recovery.rs`. Enclosing true branch: `!batch.active`.
- `SessionLedger::finish_recovery` — `src/session_budget/recovery.rs`. Enclosing true branch: `!batch.active`.

