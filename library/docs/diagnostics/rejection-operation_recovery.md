Cause contracts for `OperationRecoveryRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CSignRecoverUnavailable"></a>

### `CSignRecoverUnavailable`

Detected while checking required signature-recovery entries or resolving the
selected function before its dispatch. The named call has not been made by this
resolution. An output-stage refusal does not undo an earlier Init. No substitute
hash, signature API or software implementation is selected. Use a module/interface
that supplies the explicitly requested functions for a new operation; if an owner
already exists, retain its ticket and use its documented cleanup rather than
starting another operation over it.


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/recover/resolved_call.rs`. Enclosing match alternative: `(Kind::Sign, Stage::Output(plan))`.


<a id="cause-CSignRecoverInitUnavailable"></a>

### `CSignRecoverInitUnavailable`

Detected while checking required signature-recovery entries or resolving the
selected function before its dispatch. The named call has not been made by this
resolution. An output-stage refusal does not undo an earlier Init. No substitute
hash, signature API or software implementation is selected. Use a module/interface
that supplies the explicitly requested functions for a new operation; if an owner
already exists, retain its ticket and use its documented cleanup rather than
starting another operation over it.


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/recover/resolved_call.rs`. Enclosing match alternative: `(Kind::Sign, Stage::Init(_))`.


<a id="cause-CVerifyRecoverUnavailable"></a>

### `CVerifyRecoverUnavailable`

Detected while checking required signature-recovery entries or resolving the
selected function before its dispatch. The named call has not been made by this
resolution. An output-stage refusal does not undo an earlier Init. No substitute
hash, signature API or software implementation is selected. Use a module/interface
that supplies the explicitly requested functions for a new operation; if an owner
already exists, retain its ticket and use its documented cleanup rather than
starting another operation over it.


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/recover/resolved_call.rs`. Enclosing match alternative: `(Kind::Verify, Stage::Output(plan))`.


<a id="cause-CVerifyRecoverInitUnavailable"></a>

### `CVerifyRecoverInitUnavailable`

Detected while checking required signature-recovery entries or resolving the
selected function before its dispatch. The named call has not been made by this
resolution. An output-stage refusal does not undo an earlier Init. No substitute
hash, signature API or software implementation is selected. Use a module/interface
that supplies the explicitly requested functions for a new operation; if an owner
already exists, retain its ticket and use its documented cleanup rather than
starting another operation over it.


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/recover/resolved_call.rs`. Enclosing match alternative: `(Kind::Verify, Stage::Init(_))`.


<a id="cause-RecoveryAuthenticationKeyRequired"></a>

### `RecoveryAuthenticationKeyRequired`

Detected during local key rebinding for signature-recovery restoration.
The request must provide an authentication-role recovery reference and no cipher
key. The source continuation and caller's references are not replaced by this
refusal; no SetOperationState is issued by this check. Supply the correct explicit
roles through the public restoration contract, respecting the owner returned by
any failed restore attempt. Do not swap roles, infer another key, or assume a
consumed imported record was returned.


Local detection/handling phase and implementation owner:

- `RecoverOperation::restore_keys` — `src/advanced/recover/checkpoint.rs`.


<a id="cause-RecoveryCipherKeyAbsent"></a>

### `RecoveryCipherKeyAbsent`

Detected before installing fresh AEAD recovery from an imported recovery
record: it has no cipher key binding or no message. The consuming start method
returns no new ticket and makes no native call before polling. It consumes the
record on refusal as documented. A separate start requires a valid authenticated
record and explicit key continuity/old-worker exclusion; do not invent missing
bindings/messages or repeat the old executor.


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_aead_recovery` — `src/advanced/recovery.rs`.


<a id="cause-RecoveryEmptyBatch"></a>

### `RecoveryEmptyBatch`

Detected before installing fresh AEAD recovery from an imported recovery
record: it has no cipher key binding or no message. The consuming start method
returns no new ticket and makes no native call before polling. It consumes the
record on refusal as documented. A separate start requires a valid authenticated
record and explicit key continuity/old-worker exclusion; do not invent missing
bindings/messages or repeat the old executor.


Local detection/handling phase and implementation owner:

- `AdvancedSession::start_aead_recovery` — `src/advanced/recovery.rs`.
- `RecoveryManifest<'a>::read_with` — `src/advanced/record/recovery_manifest.rs`. Enclosing true branch: `let Some(v) = &validation`.


<a id="cause-RecoveryFrameAccountingOverflow"></a>

### `RecoveryFrameAccountingOverflow`

Detected in local request/snapshot preparation: a mechanism identifier does
not fit CK_MECHANISM_TYPE, or checked storage accounting overflows. This helper
makes no native call and returns no prepared candidate. It may run while an
existing source operation already owns native state. Correct the representable
request dimensions before a new local preparation; releasing credits or waiting
does not fix numeric overflow. Do not replay any earlier source operation.


Local detection/handling phase and implementation owner:

- `PreparedRecover::allocation_bytes_for_length` — `src/advanced/recover.rs`.
- `SnapshotStorage::allocated_bytes` — `src/advanced/recover/checkpoint.rs`.


<a id="cause-RecoveryFunctionsUnavailable"></a>

### `RecoveryFunctionsUnavailable`

Detected while checking required signature-recovery entries or resolving the
selected function before its dispatch. The named call has not been made by this
resolution. An output-stage refusal does not undo an earlier Init. No substitute
hash, signature API or software implementation is selected. Use a module/interface
that supplies the explicitly requested functions for a new operation; if an owner
already exists, retain its ticket and use its documented cleanup rather than
starting another operation over it.


Local detection/handling phase and implementation owner:

- `start` (module-level helper) — `src/advanced/recover/api.rs`. Enclosing true branch: `!available`.


<a id="cause-RecoveryIsNotWaitingForStorage"></a>

### `RecoveryIsNotWaitingForStorage`

Detected before replacing output storage. The existing owner is in Init,
Output, Done or Failed rather than Waiting; it is not changed by this check.
Only a genuine `RecoveryBufferRequest` from that same operation establishes the
waiting-for-storage transition. With such a request, `resize_recovery_output`
prepares storage locally, then `poll_recovery` advances the same ticket. A failed
owner or already published result cannot be turned into that state by resizing.


Local detection/handling phase and implementation owner:

- `RecoverOperation::output_preparation` — `src/advanced/recover.rs`.


<a id="cause-RecoveryMechanismDoesNotMatchRequestedApi"></a>

### `RecoveryMechanismDoesNotMatchRequestedApi`

Detected either during capture when the live AEAD family differs from the
chosen capture method, or during fresh-start validation when the imported
record's mechanism differs from the requested API. Capture leaves the original
operation owned and returns no record; fresh-start consumes the supplied record
on refusal and returns no ticket. Select the matching family explicitly. A
different fresh operation still requires authenticated persistence, key continuity
and exclusion of the old executor; this mismatch grants no fallback authority.


Local detection/handling phase and implementation owner:

- `AdvancedSession::capture_aead_recovery` — `src/advanced/recovery.rs`. Enclosing true branch: `body.cipher_kind() != kind`.
- `AdvancedSession::start_aead_recovery` — `src/advanced/recovery.rs`. Enclosing true branch: `r.section.mechanism != kind.mechanism() as u64`.


<a id="cause-RecoveryMechanismWidth"></a>

### `RecoveryMechanismWidth`

Detected in local request/snapshot preparation: a mechanism identifier does
not fit CK_MECHANISM_TYPE, or checked storage accounting overflows. This helper
makes no native call and returns no prepared candidate. It may run while an
existing source operation already owns native state. Correct the representable
request dimensions before a new local preparation; releasing credits or waiting
does not fix numeric overflow. Do not replay any earlier source operation.


Local detection/handling phase and implementation owner:

- `RecoverMechanism::native` — `src/advanced/recover.rs`.


<a id="cause-RecoveryNativeInputIdentity"></a>

### `RecoveryNativeInputIdentity`

Detected after a native return when the mechanism identifier, NULL/zero
parameter representation, or owned input differs from its saved identity.
The operation becomes Failed, activity stays Active and the runtime is marked
uncertain. Owned inputs, output and key lease remain retained. This can follow
CKR_OK; a nonzero return remains observable through the enclosing error. Do not
repair the mutated descriptors and replay, publish output or resize the owner.
Only its completion-aware cleanup path can establish release; no successful
cleanup is inferred from this cause.


Local detection/handling phase and implementation owner:

- `RecoverOperation::drive` — `src/advanced/recover.rs`. Enclosing true branch: `self.mechanism.mechanism != self.selected || !self.mechanism.pParameter.is_null() || self.mechanism.ulParameterLen != 0 || self.input.as_slice() != self.expected.as_slice()`.


<a id="cause-RecoveryNotCapturable"></a>

### `RecoveryNotCapturable`

Detected when preparing an in-memory snapshot of signature recovery. Only
Output and Waiting are capturable by this path; completed results and Init/Failed
are not a resumable snapshot. The source operation and buffers remain owned.
At a healthy running stage, its public polling protocol can reach an eligible
boundary; completion may instead yield the result. A failed/consumed owner has
no snapshot retry established. Do not repeat Init to manufacture the boundary.


Local detection/handling phase and implementation owner:

- `RecoverOperation::snapshot_shape` — `src/advanced/recover/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-RecoveryOperationStorageSize"></a>

### `RecoveryOperationStorageSize`

Detected in local request/snapshot preparation: a mechanism identifier does
not fit CK_MECHANISM_TYPE, or checked storage accounting overflows. This helper
makes no native call and returns no prepared candidate. It may run while an
existing source operation already owns native state. Correct the representable
request dimensions before a new local preparation; releasing credits or waiting
does not fix numeric overflow. Do not replay any earlier source operation.


Local detection/handling phase and implementation owner:

- `start` (module-level helper) — `src/advanced/recover/api.rs`.
- `start` (module-level helper) — `src/advanced/recover/api.rs`.


<a id="cause-RecoveryOutcomeUncertain"></a>

### `RecoveryOutcomeUncertain`

Detected while classifying a native Init/output return whose termination is
uncertain. The operation becomes Failed and the session is poisoned; resources
stay with the ledger while activity is not known inactive. A nonzero native code
can remain the outer error instead of this local reason. Preserve it. There is
no authorized output retry, resize or new Init from this failed owner; cleanup
must establish completion and can itself remain unavailable.


Local detection/handling phase and implementation owner:

- `RecoverOperation::drive` — `src/advanced/recover.rs`. Enclosing true branch: `completion == Completion::Uncertain`.


<a id="cause-RecoveryOutputCapacity"></a>

### `RecoveryOutputCapacity`

Detected after `C_SignRecover` or `C_VerifyRecover` returned `CKR_OK` for a
supplied output buffer, when its returned length does not fit that buffer.
No signature/recovered message is published. The operation enters `Failed`,
keeps native activity active and marks the runtime uncertain. The session ledger
retains the key lease, mechanism, input/expected copies, output and length slot.

This is **not** `RecoveryBufferRequest`. `resize_recovery_output` requires the
`Waiting` state; this owner is failed, so increasing capacity cannot resume it.
Do not poll it as a new output attempt, issue another Init, consume the invalid
buffer, or treat the reported length as a safe allocation request. Preserve the
full error and existing owner. Only an explicit cancellation/close/recovery path
that actually establishes its required native completion can retire it; that
path may itself refuse and retention can remain necessary. The successful native
effect is not undone by the local length failure.


Local detection/handling phase and implementation owner:

- `RecoverOperation::drive` — `src/advanced/recover.rs`. Enclosing true branch: `rv == CKR_OK`.
- `RecoverOperation::drive` — `src/advanced/recover.rs`. Enclosing true branch: `bounds::final_length(*self.length, capacity).is_err()`.


<a id="cause-RecoveryOutputCeiling"></a>

### `RecoveryOutputCeiling`

Detected during request preparation, output replacement, or verification of
the prepared replacement buffer. A requested capacity exceeds maximum_output,
or the replacement's initialized extent does not equal its declared capacity.
For an initial request, no owner has been installed by this check. For a waiting
operation, its existing request and buffers remain owned until a valid replacement
is attached. Select a representable capacity within the caller's ceiling and use
`resize_recovery_output` only while that same owner reports Waiting. Waiting for
credits cannot repair a capacity above the ceiling. A replacement-shape mismatch
is an internal preparation inconsistency, not permission to poll or replay C.


Local detection/handling phase and implementation owner:

- `PreparedRecover::allocation_bytes_for_length` — `src/advanced/recover.rs`. Enclosing true branch: `capacity > maximum_output`.
- `RecoverOperation::output_preparation` — `src/advanced/recover.rs`. Enclosing true branch: `capacity > self.maximum_output`.
- `RecoverOperation::attach_output` — `src/advanced/recover.rs`. Enclosing true branch: `output.as_slice().len() != capacity`.


<a id="cause-RecoveryPrefixWidth"></a>

### `RecoveryPrefixWidth`

Detected while writing the completed-message prefix count into an AEAD
recovery record when it does not fit the record's u32 field. No record is
returned; the original operation and completed prefix remain owned. A larger
memory budget or waiting cannot change this format width. Do not truncate the
count, omit authenticated results or replay messages to manufacture a record.


Local detection/handling phase and implementation owner:

- `AdvancedSession::capture_aead_recovery` — `src/advanced/recovery.rs`.


<a id="cause-RecoveryRecordDescriptor"></a>

### `RecoveryRecordDescriptor`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `keys.cipher.is_some() || keys.authentication.is_none() || d.size > limits.bytes || d.active_flags != 0 || d.validation_requested || d.carried_messages != 0 || d.phase.name() != kind.output() || messages.len() != 1`.


<a id="cause-RecoveryRecordFamily"></a>

### `RecoveryRecordFamily`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `Kind::from_family` — `src/advanced/recover/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-RecoveryRecordInputAbsent"></a>

### `RecoveryRecordInputAbsent`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`.
- `RecordPlan<'a>::new` — `src/advanced/recover/checkpoint.rs`.
- `RecordPlan<'a>::new` — `src/advanced/recover/checkpoint.rs`.


<a id="cause-RecoveryRecordInputCount"></a>

### `RecoveryRecordInputCount`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::new` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `message.fragments.len() != 1`.


<a id="cause-RecoveryRecordMechanismWidth"></a>

### `RecoveryRecordMechanismWidth`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`.


<a id="cause-RecoveryRecordOutputProfile"></a>

### `RecoveryRecordOutputProfile`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `Profile::read` — `src/advanced/recover/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-RecoveryRecordParameterContract"></a>

### `RecoveryRecordParameterContract`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`.


<a id="cause-RecoveryRecordPending"></a>

### `RecoveryRecordPending`

Detected when projecting a signature-recovery owner into a record while its
native call is pending. Its operands remain with the source owner and no such
record is returned. This family does not offer asynchronous signature-recovery
continuation: do not assume another poll, a timeout or serialization completes
the call. Preserve the owner and use only a completion-aware cleanup protocol
that can establish the required evidence.


Local detection/handling phase and implementation owner:

- `RecoverOperation::projection` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `self.pending()`.


<a id="cause-RecoveryRecordPhase"></a>

### `RecoveryRecordPhase`

Detected when projecting a signature-recovery owner whose phase is neither
Output, Waiting nor Done. No record is published and the source is retained.
Init can reach Output only through its existing successful native transition;
Failed is not repaired by serialization. A completed owner is projected only
while its output is still available. No native replay is authorized.


Local detection/handling phase and implementation owner:

- `RecoverOperation::projection` — `src/advanced/recover/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-RecoveryRecordPrematureObservation"></a>

### `RecoveryRecordPrematureObservation`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `report.maximum() != 1 || report.iter().next().is_some()`.


<a id="cause-RecoveryRecordProgression"></a>

### `RecoveryRecordProgression`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `m.state != MessageState::Engaged || m.next_fragment != 0 || m.produced != 0 || !m.result.is_empty() || !profile.waiting() && m.expected != d.size || matches!(profile, Profile::Query | Profile::SizeReported) && d.size != 0`.


<a id="cause-RecoveryReferenceRequired"></a>

### `RecoveryReferenceRequired`

Detected during local key rebinding for signature-recovery restoration.
The request must provide an authentication-role recovery reference and no cipher
key. The source continuation and caller's references are not replaced by this
refusal; no SetOperationState is issued by this check. Supply the correct explicit
roles through the public restoration contract, respecting the owner returned by
any failed restore attempt. Do not swap roles, infer another key, or assume a
consumed imported record was returned.


Local detection/handling phase and implementation owner:

- `RecoverOperation::restore_keys` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `!matches!(key.reference, StateKeyReference::Recovery(_))`.


<a id="cause-RecoveryReportedLengthWidth"></a>

### `RecoveryReportedLengthWidth`

Detected after a successful length-only query or `CKR_BUFFER_TOO_SMALL`, when
the native required length cannot be represented by usize. The owner enters
Failed before a RecoveryBufferRequest is installed. Its activity remains as
classified from the native return and the ledger retains its resources. Do not
truncate the length, allocate from it, resize as if Waiting, or repeat the query.
Use the existing owner's explicit cleanup protocol; its completion requirements
remain applicable.


Local detection/handling phase and implementation owner:

- `RecoverOperation::drive` — `src/advanced/recover.rs`. Enclosing match alternative: `Err(_)`.


<a id="cause-RecoveryResultAlreadyPublished"></a>

### `RecoveryResultAlreadyPublished`

Detected after the completed output has already been taken: result extraction
or record projection cannot publish it a second time. Use the RecoveryOutput
already returned to its caller. Re-polling, recapturing or replaying the native
signature/verification is not a way to recover the consumed Rust value.


Local detection/handling phase and implementation owner:

- `RecoverOperation::result` — `src/advanced/recover.rs`.


<a id="cause-RecoveryResultConsumed"></a>

### `RecoveryResultConsumed`

Detected after the completed output has already been taken: result extraction
or record projection cannot publish it a second time. Use the RecoveryOutput
already returned to its caller. Re-polling, recapturing or replaying the native
signature/verification is not a way to recover the consumed Rust value.


Local detection/handling phase and implementation owner:

- `RecoverOperation::projection` — `src/advanced/recover/checkpoint.rs`. Enclosing match alternative: `Stage::Done`.
- `RecoverOperation::write_checkpoint_messages` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `terminal`.


<a id="cause-RecoveryResultIncomplete"></a>

### `RecoveryResultIncomplete`

Detected by result extraction before Done, or defensively by native-function
selection outside Init/Output. No result is removed from the owner. For a healthy
operation, follow `poll_recovery` and any explicit RecoveryBufferRequest. For
Failed or uncertain execution, polling is not a restart; retain the owner for
its supported cleanup. This cause alone does not identify which phase applies.


Local detection/handling phase and implementation owner:

- `RecoverOperation::result` — `src/advanced/recover.rs`. Enclosing true branch: `!self.complete()`.
- `Call::resolve` — `src/advanced/recover/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-RecoverySnapshotShapeChanged"></a>

### `RecoverySnapshotShapeChanged`

Detected when filling a prepared request or copying a live continuation after
allocation: the input length or snapshot shape no longer matches its preparation.
No candidate is published. The existing source operation remains separately
owned; prepared Rust storage is rejected. Re-enter the public preparation/capture
protocol only at a valid current source boundary so it can size and revalidate
again. Do not reuse the stale allocation shape or clone native pointers.


Local detection/handling phase and implementation owner:

- `PreparedSnapshot::fill_request` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `input.len() != self.shape.input_length`.
- `PreparedSnapshot::copy_from` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `self.shape != source.snapshot_shape(entry)?`.


<a id="cause-RecoveryTerminalBufferAbsent"></a>

### `RecoveryTerminalBufferAbsent`

Detected during local reconstruction of a record carrying a completed result:
the prepared destination has no output buffer or the stored result exceeds its
capacity. No native call is made by this copy and no result is published. Reject
the inconsistent prepared/archive combination through the import/restore owner;
do not interpret it as a native buffer request, truncate the result or replay
the completed signature/verification.


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `m.state == MessageState::Finished`.


<a id="cause-RecoveryTerminalCapacity"></a>

### `RecoveryTerminalCapacity`

Detected during local reconstruction of a record carrying a completed result:
the prepared destination has no output buffer or the stored result exceeds its
capacity. No native call is made by this copy and no result is published. Reject
the inconsistent prepared/archive combination through the import/restore owner;
do not interpret it as a native buffer request, truncate the result or replay
the completed signature/verification.


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::finish` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `m.result.len() > output.capacity()`.


<a id="cause-RecoveryTerminalObservationAbsent"></a>

### `RecoveryTerminalObservationAbsent`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `terminal`.


<a id="cause-RecoveryTerminalOutput"></a>

### `RecoveryTerminalOutput`

Detected while validating or reconstructing a serialized signature-recovery
record. Its family, single input, mechanism width, output-negotiation profile,
parameter representation, progression or historical observation is inconsistent.
This record validation does not execute Init/Recover/SetOperationState and cannot
authenticate or repair the archive. No validated continuation is produced by the
failing check. Keep any owner explicitly returned by the import/restore API;
consuming APIs need not return the input archive on refusal. Obtain a coherent,
authenticated record under the persistence contract before a separate authorized
restoration. Never edit progression, remove an observation or clamp lengths merely
to make the record pass. Existing source effects are not rolled back.


Local detection/handling phase and implementation owner:

- `validate` (module-level helper) — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `profile != Profile::Buffer || m.state != MessageState::Finished || m.next_fragment != 1 || m.expected != d.size || m.produced > d.size`.


<a id="cause-UnexpectedRecoveryCipherKey"></a>

### `UnexpectedRecoveryCipherKey`

Detected during local key rebinding for signature-recovery restoration.
The request must provide an authentication-role recovery reference and no cipher
key. The source continuation and caller's references are not replaced by this
refusal; no SetOperationState is issued by this check. Supply the correct explicit
roles through the public restoration contract, respecting the owner returned by
any failed restore attempt. Do not swap roles, infer another key, or assume a
consumed imported record was returned.


Local detection/handling phase and implementation owner:

- `RecoverOperation::restore_keys` — `src/advanced/recover/checkpoint.rs`. Enclosing true branch: `keys.encryption.is_some()`.

