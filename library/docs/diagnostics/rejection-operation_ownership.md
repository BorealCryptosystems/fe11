Cause contracts for `OperationOwnershipRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AeadMessageTicketRequired"></a>

### `AeadMessageTicketRequired`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `(_, Family::Aead)`.
- `Session::poll_aead` — `src/advanced/gcm/stream_api.rs`. Enclosing true branch: `operation.id != ticket.id || !matches!( &operation.body, crate::advanced::OperationBody::AeadMessages(_) )`.
- `OperationTicket::aead_message_progress` — `src/advanced/gcm/stream_api.rs`.
- `check_owner` (module-level helper) — `src/advanced/gcm/submission.rs`.
- `park_locked` (module-level helper) — `src/advanced/gcm/ticket.rs`.
- `Session::take_aead_message_ticket` — `src/advanced/gcm/ticket.rs`.


<a id="cause-AdmissionResultOwner"></a>

### `AdmissionResultOwner`


Local detection/handling phase and implementation owner:

- `publish_completed_result` (module-level helper) — `src/advanced/poll.rs`. Enclosing match alternative: `OperationBody::Admission(_)`.


<a id="cause-AsynchronousJoinSessionMode"></a>

### `AsynchronousJoinSessionMode`


Local detection/handling phase and implementation owner:

- `Operation::attach_join` — `src/advanced/operation.rs`. Enclosing true branch: `entry.mode != AdvancedSessionMode::Asynchronous`.


<a id="cause-AsynchronousLegacyConversion"></a>

### `AsynchronousLegacyConversion`


Local detection/handling phase and implementation owner:

- `Session::into_advanced` — `src/advanced.rs`. Enclosing true branch: `self.entry.mode != AdvancedSessionMode::Synchronous`.


<a id="cause-CancelledOperationCannotContinue"></a>

### `CancelledOperationCannotContinue`


Local detection/handling phase and implementation owner:

- `drive` (module-level helper) — `src/advanced/operation.rs`. Enclosing true branch: `op.cancellation.is_withdrawn()`.
- `poll_owned` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `operation.cancellation.is_withdrawn() && !operation.cancel.is_submitted() && operation.uncancellable_pending()`.


<a id="cause-CapturedKeyCandidateAlreadyOccupied"></a>

### `CapturedKeyCandidateAlreadyOccupied`


Local detection/handling phase and implementation owner:

- `Continuation::restore_keys` — `src/advanced/continuation.rs`. Enclosing true branch: `candidate.is_some()`.


<a id="cause-CheckpointFamilyNotSerializable"></a>

### `CheckpointFamilyNotSerializable`


Local detection/handling phase and implementation owner:

- `Continuation::header` — `src/advanced/continuation.rs`. Enclosing match alternative: `_`.
- `Continuation::write_body` — `src/advanced/continuation.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherTicketRequired"></a>

### `CipherTicketRequired`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `(_, Family::Cipher)`.
- `Session::take_cipher_ticket` — `src/advanced/cipher/api.rs`.
- `Session::poll_cipher` — `src/advanced/cipher/api.rs`. Enclosing true branch: `operation.id != ticket.id || !matches!(&operation.body, OperationBody::Cipher(_))`.
- `check_owner` (module-level helper) — `src/advanced/cipher/input.rs`.
- `OperationTicket::cipher_progress` — `src/advanced/cipher/input.rs`.


<a id="cause-ConsumedOperationTicket"></a>

### `ConsumedOperationTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::digest_progress` — `src/advanced.rs`. Enclosing true branch: `self.id == 0`.
- `OperationTicket::created_objects` — `src/advanced.rs`. Enclosing true branch: `self.id == 0`.


<a id="cause-ContinuationBufferCapacity"></a>

### `ContinuationBufferCapacity`


Local detection/handling phase and implementation owner:

- `copy` (module-level helper) — `src/advanced/continuation.rs`. Enclosing true branch: `destination.capacity() != source.capacity()`.
- `Shadow::copy_from` — `src/advanced/cipher/shadow.rs`. Enclosing true branch: `self.capacity() != source.capacity()`.


<a id="cause-ControlHasNoCryptographicResult"></a>

### `ControlHasNoCryptographicResult`


Local detection/handling phase and implementation owner:

- `drive_body` (module-level helper) — `src/advanced/operation.rs`. Enclosing match alternative: `OperationBody::Control`.
- `publish_completed_result` (module-level helper) — `src/advanced/poll.rs`. Enclosing match alternative: `OperationBody::Control`.


<a id="cause-DigestCheckpointResultLength"></a>

### `DigestCheckpointResultLength`


Local detection/handling phase and implementation owner:

- `DigestOperation::write_checkpoint_messages` — `src/advanced/continuation.rs`. Enclosing true branch: `self.step == Step::Complete && (*self.frame.length as u128 != result.len() as u128 || !self.frame.selection.accepts_length(result.len()))`.


<a id="cause-DigestCheckpointUnavailable"></a>

### `DigestCheckpointUnavailable`


Local detection/handling phase and implementation owner:

- `DigestOperation::write_checkpoint_messages` — `src/advanced/continuation.rs`. Enclosing true branch: `self.activity.pending() || self.step == Step::Failed`.
- `DigestOperation::write_checkpoint_messages` — `src/advanced/continuation.rs`. Enclosing match alternative: `Step::Failed`.


<a id="cause-DigestTicketRequired"></a>

### `DigestTicketRequired`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `(_, Family::Digest)`.
- `OperationTicket::digest_output_requirement` — `src/advanced/digest/control.rs`.
- `Session::take_digest_ticket` — `src/advanced/digest/control.rs`.
- `validate_injection` (module-level helper) — `src/advanced/digest/control/injection.rs`.
- `OperationTicket::digest_progress` — `src/advanced.rs`. Enclosing match alternative: `_`.


<a id="cause-EmptyMessageBufferShape"></a>

### `EmptyMessageBufferShape`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `!inputs.is_empty() && (inputs.len() != 1 || !inputs[0].as_slice().is_empty())`.


<a id="cause-EmptyValidationReport"></a>

### `EmptyValidationReport`


Local detection/handling phase and implementation owner:

- `ReportStorage::allocation_bytes` — `src/advanced/validation/report_storage.rs`. Enclosing true branch: `maximum == 0`.


<a id="cause-FinalizationOperationIdentity"></a>

### `FinalizationOperationIdentity`


Local detection/handling phase and implementation owner:

- `Ledger::finalization_ready` — `src/advanced/ledger.rs`. Enclosing true branch: `owner.identity.uid() != uid || !entries .iter() .any(|e| e.credit.uid() == uid && owner.identity.matches(e))`.
- `Ledger::take_finalized` — `src/advanced/ledger.rs`. Enclosing true branch: `owner.identity.uid() != uid || !entries .iter() .any(|e| e.credit.uid() == uid && owner.identity.matches(e))`.


<a id="cause-FinalizationOperationPopulation"></a>

### `FinalizationOperationPopulation`


Local detection/handling phase and implementation owner:

- `Ledger::finalization_ready` — `src/advanced/ledger.rs`. Enclosing true branch: `occupied != slots.contains_key(&entry.credit.uid())`.


<a id="cause-FinalizationOperationSnapshot"></a>

### `FinalizationOperationSnapshot`


Local detection/handling phase and implementation owner:

- `Ledger::finalization_ready` — `src/advanced/ledger.rs`.


<a id="cause-FinalizationOperationTicket"></a>

### `FinalizationOperationTicket`


Local detection/handling phase and implementation owner:

- `Ledger::finalization_ready` — `src/advanced/ledger.rs`. Enclosing true branch: `operation.id == 0 || operation.id != entry.advanced_operation.load(Ordering::Acquire)`.


<a id="cause-ForeignDiagnosticPreparationBudget"></a>

### `ForeignDiagnosticPreparationBudget`


Local detection/handling phase and implementation owner:

- `FailureDiagnostics::prepare_in` — `src/advanced/progress.rs`. Enclosing true branch: `!budget.same_account(&session.inner.symmetric_budget)`.
- `FailureDiagnostics::prepare_for_poll` — `src/advanced/progress.rs`. Enclosing true branch: `!owner.same_account(budget)`.


<a id="cause-ForeignOperationDriverAccess"></a>

### `ForeignOperationDriverAccess`


Local detection/handling phase and implementation owner:

- `poll_owned` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `!s.owns_session(session)`.


<a id="cause-ForeignOperationLeaseIdentity"></a>

### `ForeignOperationLeaseIdentity`


Local detection/handling phase and implementation owner:

- `Ledger::install_with_retained` — `src/advanced/ledger.rs`. Enclosing true branch: `!candidate._token.identity().matches(entry)`.


<a id="cause-ForeignOrConsumedAeadMessageTicket"></a>

### `ForeignOrConsumedAeadMessageTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Aead`.


<a id="cause-ForeignOrConsumedCipherTicket"></a>

### `ForeignOrConsumedCipherTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Cipher`.
- `Session::poll_cipher` — `src/advanced/cipher/api.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0`.
- `ticket_owner` (module-level helper) — `src/advanced/cipher/input.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0`.
- `park` (module-level helper) — `src/advanced/cipher/synchronous.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.


<a id="cause-ForeignOrConsumedDigestTicket"></a>

### `ForeignOrConsumedDigestTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Digest`.
- `finish` (module-level helper) — `src/advanced/digest/control.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.
- `finish` (module-level helper) — `src/advanced/digest/control.rs`. Enclosing true branch: `session.entry.advanced_progress.retired(ticket.id)?`.
- `inject` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.
- `inject` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing true branch: `session.entry.advanced_progress.retired(ticket.id)?`.


<a id="cause-ForeignOrConsumedRecoveryTicket"></a>

### `ForeignOrConsumedRecoveryTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Recovery`.
- `AdvancedSession::capture_aead_recovery` — `src/advanced/recovery.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != self.session.uid || !Arc::ptr_eq(&ticket.owner, &self.session.inner)`.
- `AdvancedSession::capture_dual_gcm_recovery` — `src/advanced/dual/recovery.rs`. Enclosing true branch: `ticket.id == 0 || ticket.uid != self.session.uid || !Arc::ptr_eq(&ticket.owner, &self.session.inner)`.
- `Session::poll_recovery` — `src/advanced/recover/api.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0`.
- `Session::poll_recovery` — `src/advanced/recover/api.rs`. Enclosing true branch: `self.entry.advanced_progress.retired(ticket.id)?`.


<a id="cause-ForeignOrConsumedSignatureTicket"></a>

### `ForeignOrConsumedSignatureTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Signature`.
- `park_synchronous` (module-level helper) — `src/advanced/signature/api.rs`. Enclosing true branch: `!Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0`.
- `change_with_budget` (module-level helper) — `src/advanced/signature/api/preparation.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0`.


<a id="cause-ForeignPreparationBudget"></a>

### `ForeignPreparationBudget`


Local detection/handling phase and implementation owner:

- `reserve_new_while_in` (module-level helper) — `src/advanced/preparation.rs`. Enclosing true branch: `!budget.same_account(&session.inner.symmetric_budget)`.


<a id="cause-FragmentBoundaryOverflow"></a>

### `FragmentBoundaryOverflow`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `route == MessageRoute::Single`.
- `FragmentIter<'a>::next` — `src/advanced/record/messages.rs`. Enclosing match alternative: `Self::Packed { bytes, lengths, offset, }`.


<a id="cause-FragmentBoundaryRange"></a>

### `FragmentBoundaryRange`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `route == MessageRoute::Single`.
- `FragmentIter<'a>::next` — `src/advanced/record/messages.rs`. Enclosing match alternative: `Self::Packed { bytes, lengths, offset, }`.


<a id="cause-FragmentMetadataOverflow"></a>

### `FragmentMetadataOverflow`


Local detection/handling phase and implementation owner:

- `InputLayout::allocation_bytes` — `src/advanced/continuation.rs`.


<a id="cause-FragmentRetirementAccounting"></a>

### `FragmentRetirementAccounting`


Local detection/handling phase and implementation owner:

- `Storage::required_bytes` — `src/advanced/fragment_retirement.rs`.
- `Storage::allocated_bytes` — `src/advanced/fragment_retirement.rs`.


<a id="cause-FragmentRetirementAllocation"></a>

### `FragmentRetirementAllocation`


Local detection/handling phase and implementation owner:

- `Storage::allocate` — `src/advanced/fragment_retirement.rs`.


<a id="cause-FragmentRetirementCursor"></a>

### `FragmentRetirementCursor`


Local detection/handling phase and implementation owner:

- `Pool::check` — `src/advanced/fragment_retirement.rs`.


<a id="cause-FragmentRetirementMetadataOverflow"></a>

### `FragmentRetirementMetadataOverflow`


Local detection/handling phase and implementation owner:

- `vector_bytes` (module-level helper) — `src/advanced/fragment_retirement.rs`.


<a id="cause-FragmentRetirementSlotAbsent"></a>

### `FragmentRetirementSlotAbsent`


Local detection/handling phase and implementation owner:

- `Pool::check` — `src/advanced/fragment_retirement.rs`. Enclosing true branch: `self .inputs .get(self.next_input..end) .map_or(true, |slots| slots.iter().any(Option::is_none)) || shadow_bytes != 0 && self.shadow.is_none()`.


<a id="cause-FragmentTotalMismatch"></a>

### `FragmentTotalMismatch`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `offset != bytes.len()`.


<a id="cause-GenerationDescriptiveResultKind"></a>

### `GenerationDescriptiveResultKind`


Local detection/handling phase and implementation owner:

- `GeneratedObjects::from_progress` — `src/advanced.rs`. Enclosing match alternative: `_`.


<a id="cause-IntermediateValidationDetachmentDeferred"></a>

### `IntermediateValidationDetachmentDeferred`


Local detection/handling phase and implementation owner:

- `Capture::check_detachment` — `src/advanced/validation.rs`. Enclosing true branch: `index < message_count - 1`.


<a id="cause-JoinedCryptographicOwnerUnavailable"></a>

### `JoinedCryptographicOwnerUnavailable`


Local detection/handling phase and implementation owner:

- `Operation::joined_capacity` — `src/advanced/operation.rs`. Enclosing true branch: `self.cancellation.is_withdrawn() || self.continuation_status.is_frozen() || self.cancel.is_submitted()`.


<a id="cause-JoinedResultRequiresItsSpecificOwner"></a>

### `JoinedResultRequiresItsSpecificOwner`


Local detection/handling phase and implementation owner:

- `Operation::joined_capacity` — `src/advanced/operation.rs`. Enclosing match alternative: `_`.
- `Operation::accept_joined` — `src/advanced/operation.rs`. Enclosing match alternative: `_`.


<a id="cause-MultipartBoundaryMismatch"></a>

### `MultipartBoundaryMismatch`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `input.as_slice().len() != *length`.


<a id="cause-MultipartBufferCount"></a>

### `MultipartBufferCount`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `inputs.len() != self.lengths().len()`.


<a id="cause-NativeAsynchronousExecutionUnavailable"></a>

### `NativeAsynchronousExecutionUnavailable`


Local detection/handling phase and implementation owner:

- `TokenContext::open_advanced_session` — `src/advanced.rs`. Enclosing true branch: `mode == AdvancedSessionMode::Asynchronous`.
- `TokenContext::open_advanced_session_with_notify` — `src/advanced.rs`. Enclosing true branch: `mode == AdvancedSessionMode::Asynchronous`.


<a id="cause-OpenCompleteInputStream"></a>

### `OpenCompleteInputStream`


Local detection/handling phase and implementation owner:

- `InputState::read` — `src/advanced/input.rs`. Enclosing true branch: `status == StreamInputStatus::Open && !incremental`.


<a id="cause-OperationAbsent"></a>

### `OperationAbsent`


Local detection/handling phase and implementation owner:

- `Ledger::get` — `src/advanced/ledger.rs`.


<a id="cause-OperationCandidateAbsent"></a>

### `OperationCandidateAbsent`


Local detection/handling phase and implementation owner:

- `Ledger::install_with_retained` — `src/advanced/ledger.rs`.


<a id="cause-OperationContinuationTransferred"></a>

### `OperationContinuationTransferred`


Local detection/handling phase and implementation owner:

- `drive` (module-level helper) — `src/advanced/operation.rs`. Enclosing true branch: `op.continuation_status.is_frozen()`.


<a id="cause-OperationHasNoSavedContinuation"></a>

### `OperationHasNoSavedContinuation`


Local detection/handling phase and implementation owner:

- `Continuation::retain_credits` — `src/advanced/continuation.rs`. Enclosing match alternative: `OperationBody::Control | OperationBody::Admission(_)`.


<a id="cause-OperationIdentityAbsent"></a>

### `OperationIdentityAbsent`


Local detection/handling phase and implementation owner:

- `TokenLease::new_retained` — `src/advanced/lease.rs`.


<a id="cause-OperationNotCapturable"></a>

### `OperationNotCapturable`


Local detection/handling phase and implementation owner:

- `Continuation::check_capture` — `src/advanced/continuation.rs`. Enclosing true branch: `op.rejoin().is_some() || op.detachment().is_some() || op.cancellation.is_withdrawn() || op.continuation_status.is_frozen() || op.cancel.is_submitted() || op.state_io().is_some() || op.joined.is_some() || op.body.pending() || op.body.complete() || op.validation.as_ref().is_some_and(|v| v.waiting())`.


<a id="cause-OperationProgressIdentity"></a>

### `OperationProgressIdentity`


Local detection/handling phase and implementation owner:

- `Progress::install` — `src/advanced/progress.rs`. Enclosing true branch: `ticket == 0 || state.lifecycle == Lifecycle::Live`.
- `Progress::replace` — `src/advanced/progress.rs`. Enclosing true branch: `ticket == 0 || state.lifecycle != Lifecycle::Live || ticket == state.ticket`.


<a id="cause-OperationProgressRevisionExhausted"></a>

### `OperationProgressRevisionExhausted`


Local detection/handling phase and implementation owner:

- `Progress::claim` — `src/advanced/progress.rs`.


<a id="cause-OperationPublicationStorageSize"></a>

### `OperationPublicationStorageSize`


Local detection/handling phase and implementation owner:

- `PreparedOperation::allocation_bytes` — `src/advanced/ledger/storage.rs`.


<a id="cause-OperationRegistryAllocation"></a>

### `OperationRegistryAllocation`


Local detection/handling phase and implementation owner:

- `Ledger::install_with_retained` — `src/advanced/ledger.rs`.


<a id="cause-OperationShellAbsent"></a>

### `OperationShellAbsent`


Local detection/handling phase and implementation owner:

- `Shell::bind_retained` — `src/advanced/preparation.rs`.


<a id="cause-OperationStorageAlreadyInitialized"></a>

### `OperationStorageAlreadyInitialized`


Local detection/handling phase and implementation owner:

- `PreparedOperation::check` — `src/advanced/ledger/storage.rs`. Enclosing true branch: `cell.operation.get().is_some()`.


<a id="cause-OperationTicketExhausted"></a>

### `OperationTicketExhausted`


Local detection/handling phase and implementation owner:

- `Ledger::install_with_retained` — `src/advanced/ledger.rs`.
- `Ledger::reserve_ticket` — `src/advanced/ledger.rs`.


<a id="cause-OperationWaiterCount"></a>

### `OperationWaiterCount`


Local detection/handling phase and implementation owner:

- `Progress::register` — `src/advanced/progress.rs`.
- `Progress::unregister` — `src/advanced/progress.rs`.


<a id="cause-PollDiagnosticByteCount"></a>

### `PollDiagnosticByteCount`


Local detection/handling phase and implementation owner:

- `FailureDiagnostics::prepare_for_poll` — `src/advanced/progress.rs`.


<a id="cause-PreparedOperationStorageAbsent"></a>

### `PreparedOperationStorageAbsent`


Local detection/handling phase and implementation owner:

- `Ledger::install_retained` — `src/advanced/ledger.rs`. Enclosing true branch: `prepared.is_none()`.


<a id="cause-RecoveryTicketRequired"></a>

### `RecoveryTicketRequired`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `(_, Family::Recovery)`.
- `Session::poll_recovery` — `src/advanced/recover/api.rs`. Enclosing true branch: `operation.id != ticket.id || !matches!(&operation.body, OperationBody::Recover(_))`.


<a id="cause-RestorationIoAbsent"></a>

### `RestorationIoAbsent`


Local detection/handling phase and implementation owner:

- `Operation::drive_restoration` — `src/advanced/ownership.rs`.
- `AdvancedSession::poll_state_restore` — `src/advanced/restoration.rs`.
- `AdvancedSession::start_restore_detachment` — `src/advanced/restoration_transfer.rs`.
- `AdvancedSession::finish_restore_detachment` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestorationAbsent"></a>

### `RestorationAbsent`


Local detection/handling phase and implementation owner:

- `Operation::begin_restore_transfer` — `src/advanced/ownership.rs`. Enclosing true branch: `self.restore_owner().is_none()`.
- `AdvancedSession::poll_state_restore` — `src/advanced/restoration.rs`.
- `AdvancedSession::finish_restore_detachment` — `src/advanced/restoration_transfer.rs`.


<a id="cause-RestorationKeyRoles"></a>

### `RestorationKeyRoles`


Local detection/handling phase and implementation owner:

- `Continuation::restore_keys` — `src/advanced/continuation.rs`. Enclosing match alternative: `_`.


<a id="cause-RestorationOwnerAbsent"></a>

### `RestorationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `Operation::drive_restoration` — `src/advanced/ownership.rs`.


<a id="cause-RetiredOperationCount"></a>

### `RetiredOperationCount`


Local detection/handling phase and implementation owner:

- `TokenLease::retire_admission` — `src/advanced/lease.rs`.


<a id="cause-RetiredOperationLeaseIdentity"></a>

### `RetiredOperationLeaseIdentity`


Local detection/handling phase and implementation owner:

- `TokenLease::retire_admission` — `src/advanced/lease.rs`. Enclosing true branch: `class != LeaseClass::Unclassified as u8 && class != LeaseClass::Stranded as u8`.


<a id="cause-RetiredStrandedCount"></a>

### `RetiredStrandedCount`


Local detection/handling phase and implementation owner:

- `TokenLease::retire_admission` — `src/advanced/lease.rs`. Enclosing true branch: `class == LeaseClass::Stranded as u8`.


<a id="cause-RetirementOwnerSnapshot"></a>

### `RetirementOwnerSnapshot`


Local detection/handling phase and implementation owner:

- `Ledger::retire_slot_admission` — `src/advanced/ledger.rs`.


<a id="cause-SharedUnboundOperationIdentity"></a>

### `SharedUnboundOperationIdentity`


Local detection/handling phase and implementation owner:

- `TokenLease::new_retained` — `src/advanced/lease.rs`.


<a id="cause-SharedUnboundOperationStorage"></a>

### `SharedUnboundOperationStorage`


Local detection/handling phase and implementation owner:

- `PreparedOperation::check` — `src/advanced/ledger/storage.rs`.


<a id="cause-SignatureTicketRequired"></a>

### `SignatureTicketRequired`


Local detection/handling phase and implementation owner:

- `need` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `(_, Family::Signature)`.
- `park_synchronous` (module-level helper) — `src/advanced/signature/api.rs`.
- `Session::take_signature_ticket` — `src/advanced/signature/api.rs`.
- `OperationTicket::signature_progress` — `src/advanced/signature/api.rs`.
- `check_owner` (module-level helper) — `src/advanced/signature/api/preparation.rs`.


<a id="cause-SingleMessageBufferCount"></a>

### `SingleMessageBufferCount`


Local detection/handling phase and implementation owner:

- `InputLayout::fragments` — `src/advanced/continuation.rs`. Enclosing true branch: `inputs.len() != 1`.


<a id="cause-StaleAeadMessageTicket"></a>

### `StaleAeadMessageTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Aead`.
- `OperationTicket::aead_message_progress` — `src/advanced/gcm/stream_api.rs`. Enclosing true branch: `operation.id != self.id`.


<a id="cause-StaleCipherTicket"></a>

### `StaleCipherTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Cipher`.
- `check_owner` (module-level helper) — `src/advanced/cipher/input.rs`. Enclosing true branch: `operation.id != id`.
- `OperationTicket::cipher_progress` — `src/advanced/cipher/input.rs`. Enclosing true branch: `operation.id != self.id`.


<a id="cause-StaleDigestTicket"></a>

### `StaleDigestTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Digest`.
- `finish` (module-level helper) — `src/advanced/digest/control.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `OperationTicket::digest_output_requirement` — `src/advanced/digest/control.rs`. Enclosing true branch: `operation.id != self.id`.
- `inject` (module-level helper) — `src/advanced/digest/control/injection.rs`. Enclosing true branch: `operation.id != ticket.id`.


<a id="cause-StaleOperationTicket"></a>

### `StaleOperationTicket`


Local detection/handling phase and implementation owner:

- `AdvancedSession::next_native_function` — `src/advanced/authentication.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `Session::authenticate_context_with_budget` — `src/advanced/authentication.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `AdvancedSession::start_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `op.id != ticket.id`.
- `AdvancedSession::drive_detachment` — `src/advanced/detachment.rs`. Enclosing true branch: `op.id != ticket.id`.
- `poll_live_operation` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `poll_live_operation` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `poll_live_operation` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `poll_owned` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `Progress::claim` — `src/advanced/progress.rs`. Enclosing true branch: `state.lifecycle != Lifecycle::Live || state.ticket != ticket`.
- `Progress::observe_revision` — `src/advanced/progress.rs`. Enclosing true branch: `state.lifecycle != Lifecycle::Live || state.ticket != ticket`.
- `Progress::register` — `src/advanced/progress.rs`. Enclosing true branch: `state.lifecycle != Lifecycle::Live || state.ticket != ticket`.
- `FailureDiagnostics::prepare_in` — `src/advanced/progress.rs`. Enclosing true branch: `session.entry.advanced_operation.load(Ordering::Acquire) != ticket`.
- `FailureDiagnostics::prepare_for_poll` — `src/advanced/progress.rs`. Enclosing true branch: `session.entry.advanced_operation.load(Ordering::Acquire) != ticket`.
- `AdvancedSession::capture_control` — `src/advanced/saved_state.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/recover.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `ContextLoginPlan<'_>::prepare_retained` — `src/session/context_authentication/preparation.rs`. Enclosing true branch: `session.entry.advanced_operation.load(Ordering::Acquire) != ticket`.
- `Ledger::maintain` — `src/advanced/ledger.rs`. Enclosing true branch: `operation.id != ticket`.
- `Ledger::logout_ready` — `src/advanced/ledger.rs`. Enclosing true branch: `operation.id != id`.
- `OperationTicket::digest_progress` — `src/advanced.rs`. Enclosing true branch: `operation.id != self.id`.
- `OperationTicket::created_objects` — `src/advanced.rs`. Enclosing true branch: `operation.id != self.id`.


<a id="cause-StaleRecoveryTicket"></a>

### `StaleRecoveryTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Recovery`.
- `copy_registered` (module-level helper) — `src/advanced/record_preparation.rs`. Enclosing true branch: `operation.id != ticket.id`.


<a id="cause-StaleSignatureTicket"></a>

### `StaleSignatureTicket`


Local detection/handling phase and implementation owner:

- `replace` (module-level helper) — `src/advanced/output_preparation.rs`. Enclosing match alternative: `Family::Signature`.
- `park_synchronous` (module-level helper) — `src/advanced/signature/api.rs`. Enclosing true branch: `operation.id != ticket.id`.
- `OperationTicket::signature_progress` — `src/advanced/signature/api.rs`. Enclosing true branch: `operation.id != self.id`.
- `check_owner` (module-level helper) — `src/advanced/signature/api/preparation.rs`. Enclosing true branch: `operation.id != ticket.id`.


<a id="cause-StreamIncrementalRoute"></a>

### `StreamIncrementalRoute`


Local detection/handling phase and implementation owner:

- `InputState::read` — `src/advanced/input.rs`.


<a id="cause-StreamInputClosureEncoding"></a>

### `StreamInputClosureEncoding`


Local detection/handling phase and implementation owner:

- `InputState::read` — `src/advanced/input.rs`. Enclosing match alternative: `_`.


<a id="cause-StreamInputCounterExhausted"></a>

### `StreamInputCounterExhausted`


Local detection/handling phase and implementation owner:

- `InputState::submission` — `src/advanced/input.rs`.
- `InputState::accepted` — `src/advanced/input.rs`.


<a id="cause-StreamKeyCounterExhausted"></a>

### `StreamKeyCounterExhausted`


Local detection/handling phase and implementation owner:

- `InputState::submission` — `src/advanced/input.rs`. Enclosing true branch: `key`.
- `InputState::accepted` — `src/advanced/input.rs`. Enclosing true branch: `key`.


<a id="cause-StreamOutputCounterExhausted"></a>

### `StreamOutputCounterExhausted`


Local detection/handling phase and implementation owner:

- `InputState::produced` — `src/advanced/input.rs`.


<a id="cause-StreamOutputDeliveryPosition"></a>

### `StreamOutputDeliveryPosition`


Local detection/handling phase and implementation owner:

- `InputState::delivered` — `src/advanced/input.rs`.


<a id="cause-StreamProgressEncoding"></a>

### `StreamProgressEncoding`


Local detection/handling phase and implementation owner:

- `InputState::read` — `src/advanced/input.rs`. Enclosing true branch: `key_inputs > submissions || counts[2] > counts[1] || retained_submission && submissions == 0`.


<a id="cause-StreamRetainedInput"></a>

### `StreamRetainedInput`


Local detection/handling phase and implementation owner:

- `InputState::read` — `src/advanced/input.rs`.


<a id="cause-StreamSubmissionCounterExhausted"></a>

### `StreamSubmissionCounterExhausted`


Local detection/handling phase and implementation owner:

- `InputState::submission` — `src/advanced/input.rs`. Enclosing true branch: `!issued.retained_submission`.


<a id="cause-TerminalCryptoNotComplete"></a>

### `TerminalCryptoNotComplete`


Local detection/handling phase and implementation owner:

- `write` (module-level helper) — `src/advanced/terminal.rs`. Enclosing true branch: `!body.complete() || body.pending()`.


<a id="cause-TerminalValidationAssociation"></a>

### `TerminalValidationAssociation`


Local detection/handling phase and implementation owner:

- `Capture::terminal_prefix` — `src/advanced/validation.rs`. Enclosing true branch: `self.observation.failed() || !self .observation .point() .is_some_and(|p| p.function == function && p.message_index.is_none())`.


<a id="cause-TokenOperationCount"></a>

### `TokenOperationCount`


Local detection/handling phase and implementation owner:

- `TokenLease::new_retained` — `src/advanced/lease.rs`.


<a id="cause-UnchangingPreparationWasInvalidated"></a>

### `UnchangingPreparationWasInvalidated`


Local detection/handling phase and implementation owner:

- `reserve_new_with_progress` (module-level helper) — `src/advanced/preparation.rs`.
- `reserve_new_at_epoch` (module-level helper) — `src/advanced/preparation.rs`.


<a id="cause-ValidationAlreadyPublished"></a>

### `ValidationAlreadyPublished`


Local detection/handling phase and implementation owner:

- `Capture::snapshot_capacity` — `src/advanced/validation.rs`.
- `Capture::copy_snapshot_from` — `src/advanced/validation.rs`.
- `Capture::write_checkpoint` — `src/advanced/validation.rs`.
- `Capture::restore_record` — `src/advanced/validation.rs`.
- `Capture::terminal_prefix` — `src/advanced/validation.rs`.
- `Capture::take` — `src/advanced/validation.rs`.
- `Capture::complete` — `src/advanced/validation.rs`.


<a id="cause-ValidationAsynchronousVersion"></a>

### `ValidationAsynchronousVersion`


Local detection/handling phase and implementation owner:

- `Capture::drive` — `src/advanced/validation.rs`. Enclosing true branch: `completing && self.observation.frame.completion.ulVersion != 0`.


<a id="cause-ValidationCollectorAbsent"></a>

### `ValidationCollectorAbsent`


Local detection/handling phase and implementation owner:

- `publish_completed_result` (module-level helper) — `src/advanced/poll.rs`. Enclosing true branch: `matches!(&operation.body, OperationBody::Digest(d) if d.validation_requested)`.


<a id="cause-ValidationControlNotPending"></a>

### `ValidationControlNotPending`


Local detection/handling phase and implementation owner:

- `Capture::joined_capacity` — `src/advanced/validation.rs`. Enclosing true branch: `!self.observation.pending() || self.observation.failed() || self.observation.point().is_none()`.


<a id="cause-ValidationFailed"></a>

### `ValidationFailed`


Local detection/handling phase and implementation owner:

- `Capture::drive` — `src/advanced/validation.rs`. Enclosing true branch: `self.observation.failed()`.


<a id="cause-ValidationIncomplete"></a>

### `ValidationIncomplete`


Local detection/handling phase and implementation owner:

- `Capture::snapshot_capacity` — `src/advanced/validation.rs`. Enclosing true branch: `self.waiting() || self.observation.failed()`.
- `Capture::write_checkpoint` — `src/advanced/validation.rs`. Enclosing true branch: `capture.waiting() || capture.observation.pending() || capture.observation.failed()`.
- `Capture::take` — `src/advanced/validation.rs`. Enclosing true branch: `self.waiting() || self.observation.failed()`.


<a id="cause-ValidationMessageIndex"></a>

### `ValidationMessageIndex`


Local detection/handling phase and implementation owner:

- `Capture::check_detachment` — `src/advanced/validation.rs`. Enclosing true branch: `index >= message_count`.


<a id="cause-ValidationObservationAbsent"></a>

### `ValidationObservationAbsent`


Local detection/handling phase and implementation owner:

- `Capture::first` — `src/advanced/validation.rs`.


<a id="cause-ValidationObservationSequence"></a>

### `ValidationObservationSequence`


Local detection/handling phase and implementation owner:

- `Capture::queue` — `src/advanced/validation.rs`. Enclosing true branch: `self.observation.point().is_some() || self.observation.failed() || self .report .as_ref() .map_or(true, |r| r.observations.len() >= self.maximum)`.


<a id="cause-ValidationPointAbsent"></a>

### `ValidationPointAbsent`


Local detection/handling phase and implementation owner:

- `Capture::complete` — `src/advanced/validation.rs`.


<a id="cause-ValidationReconstructionShape"></a>

### `ValidationReconstructionShape`


Local detection/handling phase and implementation owner:

- `Capture::restore_record` — `src/advanced/validation.rs`. Enclosing true branch: `self.maximum != record.maximum() || !report.observations.is_empty() || self.observation.point().is_some()`.


<a id="cause-ValidationReportAllocation"></a>

### `ValidationReportAllocation`


Local detection/handling phase and implementation owner:

- `ReportStorage::allocate` — `src/advanced/validation/report_storage.rs`.


<a id="cause-ValidationReportCapacityAccounting"></a>

### `ValidationReportCapacityAccounting`


Local detection/handling phase and implementation owner:

- `CaptureStorage::allocated_bytes` — `src/advanced/validation.rs`.
- `ReportStorage::allocated_bytes` — `src/advanced/validation/report_storage.rs`.


<a id="cause-ValidationReportCapacityDecreased"></a>

### `ValidationReportCapacityDecreased`


Local detection/handling phase and implementation owner:

- `Capture::report_growth_bytes` — `src/advanced/validation/report_storage.rs`. Enclosing true branch: `maximum < previous`.


<a id="cause-ValidationReportGrowthAbsent"></a>

### `ValidationReportGrowthAbsent`


Local detection/handling phase and implementation owner:

- `Capture::check_report_growth` — `src/advanced/validation/report_storage.rs`. Enclosing true branch: `required != 0`.


<a id="cause-ValidationReportGrowthShapeChanged"></a>

### `ValidationReportGrowthShapeChanged`


Local detection/handling phase and implementation owner:

- `Capture::check_report_growth` — `src/advanced/validation/report_storage.rs`. Enclosing true branch: `prepared.maximum != maximum || !prepared.report.observations.is_empty() || prepared.report.observations.capacity() < maximum`.


<a id="cause-ValidationReportLimit"></a>

### `ValidationReportLimit`


Local detection/handling phase and implementation owner:

- `Capture::complete` — `src/advanced/validation.rs`. Enclosing true branch: `report.observations.len() >= self.maximum`.


<a id="cause-ValidationSnapshotCapacityChanged"></a>

### `ValidationSnapshotCapacityChanged`


Local detection/handling phase and implementation owner:

- `Capture::copy_snapshot_from` — `src/advanced/validation.rs`. Enclosing true branch: `source.observations.len() > target.observations.capacity()`.


<a id="cause-ValidationSnapshotShapeChanged"></a>

### `ValidationSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `Capture::copy_snapshot_from` — `src/advanced/validation.rs`. Enclosing true branch: `self.maximum != source.snapshot_capacity()? || self.waiting()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing match alternative: `_`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing match alternative: `_`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `_`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing match alternative: `_`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing match alternative: `_`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/recover.rs`. Enclosing match alternative: `_`.

