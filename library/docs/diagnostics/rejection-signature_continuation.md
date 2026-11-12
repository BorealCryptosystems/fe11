Cause contracts for `SignatureContinuationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-SignatureNotActive"></a>

### `SignatureNotActive`


Local detection/handling phase and implementation owner:

- `Call::resolve` — `src/advanced/signature/resolved_call.rs`. Enclosing match alternative: `_`.


<a id="cause-ChangedSignatureSnapshotInput"></a>

### `ChangedSignatureSnapshotInput`


Local detection/handling phase and implementation owner:

- `SignatureOperation::snapshot_shape` — `src/advanced/signature/snapshot.rs`. Enclosing true branch: `!graph.unchanged() || self .fragment .as_ref() .is_some_and(|input| !input.unchanged()) || self .signature .as_ref() .is_some_and(|input| !input.unchanged())`.


<a id="cause-CipherAuthenticationRoleAbsent"></a>

### `CipherAuthenticationRoleAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'a>::cipher_key` — `src/advanced/signature/binding.rs`. Enclosing true branch: `keys.authentication.is_some()`.


<a id="cause-CipherWriterDeclarationAbsent"></a>

### `CipherWriterDeclarationAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'a>::cipher_captured` — `src/advanced/signature/binding.rs`.
- `Destination<'a>::cipher_imported` — `src/advanced/signature/binding.rs`.


<a id="cause-ClassicSignatureFacadeRoute"></a>

### `ClassicSignatureFacadeRoute`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/advanced/signature/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-CompetingInitOwnerAbsent"></a>

### `CompetingInitOwnerAbsent`


Local detection/handling phase and implementation owner:

- `attempt` (module-level helper) — `src/advanced/signature/competing_init.rs`. Enclosing true branch: `crate::advanced::init_reader_borrow(session, &access, body.kind.category())?.is_none()`.


<a id="cause-CompetingSignatureInitOutcomeUncertain"></a>

### `CompetingSignatureInitOutcomeUncertain`

A second Init returned, but its continuation could not replace the resident
owner. An intact native success is reported as `OperationCompleted` naming the
Init, not the complete signature. Native refusal and parameter-boundary failures
retain their distinct diagnostics; no retry or cancellation is implied.


Local detection/handling phase and implementation owner:

- `attempt` (module-level helper) — `src/advanced/signature/competing_init.rs`.


<a id="cause-ConflictingInitReturnedNoError"></a>

### `ConflictingInitReturnedNoError`


Local detection/handling phase and implementation owner:

- `attempt` (module-level helper) — `src/advanced/signature/competing_init.rs`. Enclosing true branch: `initialization_refused`.


<a id="cause-ConsumedSignatureTicket"></a>

### `ConsumedSignatureTicket`


Local detection/handling phase and implementation owner:

- `OperationTicket::signature_progress` — `src/advanced/signature/api.rs`. Enclosing true branch: `self.id == 0`.


<a id="cause-ExplicitSignatureDeclarationMismatch"></a>

### `ExplicitSignatureDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `Destination<'a>::imported` — `src/advanced/signature/binding.rs`. Enclosing true branch: `extension.mechanism_number() != descriptor.mechanism || extension.constants_edition() != parameters.edition || extension.mutates_key() != parameters.mutates_key`.


<a id="cause-ForeignCipherDestination"></a>

### `ForeignCipherDestination`


Local detection/handling phase and implementation owner:

- `Destination<'a>::cipher_captured` — `src/advanced/signature/binding.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &key.inner) || key.identity.session != session.uid || key.identity.slot != session.entry.slot || key.identity.generation != session.snapshot.generation`.


<a id="cause-ForeignSignatureDestination"></a>

### `ForeignSignatureDestination`


Local detection/handling phase and implementation owner:

- `Destination<'a>::captured` — `src/advanced/signature/binding.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &key.inner) || key.identity.session != session.uid || key.identity.slot != session.entry.slot || key.identity.generation != session.snapshot.generation`.


<a id="cause-NativeCipherWriterDestinationRequired"></a>

### `NativeCipherWriterDestinationRequired`


Local detection/handling phase and implementation owner:

- `Destination<'a>::cipher_key` — `src/advanced/signature/binding.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeDestinationPermissionsAbsent"></a>

### `NativeDestinationPermissionsAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'a>::try_access` — `src/advanced/signature/binding.rs`. Enclosing true branch: `let Some(roles) = &self.roles`.


<a id="cause-NativeDestinationStorageNotPrepared"></a>

### `NativeDestinationStorageNotPrepared`


Local detection/handling phase and implementation owner:

- `Destination<'a>::try_access` — `src/advanced/signature/binding.rs`. Enclosing true branch: `needs_revocation != self.storage.revocation.is_some() || self.transfer.is_some() != self.storage.transfers[0].is_some() || self.storage.transfers[1..].iter().any(Option::is_some) || self.roles.is_some() != self.storage.permissions.is_some()`.


<a id="cause-NativeSignatureDestinationRequired"></a>

### `NativeSignatureDestinationRequired`


Local detection/handling phase and implementation owner:

- `Destination<'a>::selection` — `src/advanced/signature/binding.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeTransferStorageAbsent"></a>

### `NativeTransferStorageAbsent`


Local detection/handling phase and implementation owner:

- `Destination<'a>::try_access` — `src/advanced/signature/binding.rs`. Enclosing match alternative: `Some(transfer)`.


<a id="cause-RevokedSignatureDestination"></a>

### `RevokedSignatureDestination`


Local detection/handling phase and implementation owner:

- `Binding::check` — `src/advanced/signature/binding.rs`. Enclosing true branch: `self.key.revoked.load(Ordering::Acquire) && !self.own_revocation`.


<a id="cause-RevokedSignatureKey"></a>

### `RevokedSignatureKey`


Local detection/handling phase and implementation owner:

- `SignatureOperation::check_key` — `src/advanced/signature.rs`. Enclosing true branch: `!self.own_revocation && self.key.revoked.load(Ordering::Acquire)`.


<a id="cause-SignatureUpdateDidNotEstablishInputBoundary"></a>

### `SignatureUpdateDidNotEstablishInputBoundary`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/advanced/signature/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-SignatureContinuationRoute"></a>

### `SignatureContinuationRoute`


Local detection/handling phase and implementation owner:

- `Change<'a>::check` — `src/advanced/signature/api/preparation.rs`. Enclosing true branch: `single != (body.route == MessageRoute::Single)`.


<a id="cause-SignatureContinuationTicketUnavailable"></a>

### `SignatureContinuationTicketUnavailable`


Local detection/handling phase and implementation owner:

- `park_synchronous` (module-level helper) — `src/advanced/signature/api.rs`. Enclosing true branch: `body.observer != super::Observer::Ticket`.
- `Session::take_signature_ticket` — `src/advanced/signature/api.rs`. Enclosing true branch: `body.observer != super::Observer::Session`.


<a id="cause-SignatureDestinationBindingAbsent"></a>

### `SignatureDestinationBindingAbsent`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::check_binding` — `src/advanced/signature/checkpoint.rs`.


<a id="cause-SignatureDestinationDeclarationChanged"></a>

### `SignatureDestinationDeclarationChanged`


Local detection/handling phase and implementation owner:

- `Destination<'a>::captured` — `src/advanced/signature/binding.rs`. Enclosing true branch: `extension.mechanism_number() != source.contract.mechanism_number() || extension.constants_edition() != source.contract.constants_edition() || extension.mutates_key() != source.contract.mutates_key()`.


<a id="cause-SignatureDestinationRepresentationChanged"></a>

### `SignatureDestinationRepresentationChanged`


Local detection/handling phase and implementation owner:

- `PreparedCheckpoint::check_binding` — `src/advanced/signature/checkpoint.rs`. Enclosing true branch: `binding.contract.native_mechanism() != self.mechanism.mechanism || binding.contract.operation() != self.kind.operation(self.route)`.


<a id="cause-SignatureFacadeIncomplete"></a>

### `SignatureFacadeIncomplete`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/advanced/signature/batch.rs`. Enclosing match alternative: `_`.


<a id="cause-SignatureFinishOperands"></a>

### `SignatureFinishOperands`


Local detection/handling phase and implementation owner:

- `Change<'a>::check` — `src/advanced/signature/api/preparation.rs`. Enclosing true branch: `required != signature.is_some()`.


<a id="cause-SignatureHasNoCipherKeyRole"></a>

### `SignatureHasNoCipherKeyRole`


Local detection/handling phase and implementation owner:

- `Destination<'a>::selection` — `src/advanced/signature/binding.rs`. Enclosing true branch: `keys.encryption.is_some()`.


<a id="cause-SignatureImportDeclarationMismatch"></a>

### `SignatureImportDeclarationMismatch`


Local detection/handling phase and implementation owner:

- `Destination<'a>::imported` — `src/advanced/signature/binding.rs`. Enclosing true branch: `contract.mechanism_number() != descriptor.mechanism || contract.constants_edition() != parameters.edition || contract.mutates_key() != parameters.mutates_key`.


<a id="cause-SignatureInitialOperands"></a>

### `SignatureInitialOperands`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`. Enclosing true branch: `route == MessageRoute::Multipart && initial.is_some() || kind == Kind::VerifySignature && signature.is_none() || kind == Kind::Sign && signature.is_some()`.


<a id="cause-SignatureInputAbsent"></a>

### `SignatureInputAbsent`


Local detection/handling phase and implementation owner:

- `SignatureOperation::drive` — `src/advanced/signature.rs`. Enclosing true branch: `submitted`.


<a id="cause-SignatureInputAccounting"></a>

### `SignatureInputAccounting`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::allocation_bytes` — `src/advanced/signature/checkpoint.rs`.
- `RecordPlan<'a>::allocation_bytes` — `src/advanced/signature/checkpoint.rs`.
- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`.
- `prepare_input` (module-level helper) — `src/advanced/signature/api/preparation.rs`.
- `prepare_input` (module-level helper) — `src/advanced/signature/api/preparation.rs`.


<a id="cause-SignatureInputBoundaryUnavailable"></a>

### `SignatureInputBoundaryUnavailable`


Local detection/handling phase and implementation owner:

- `check_owner` (module-level helper) — `src/advanced/signature/api/preparation.rs`. Enclosing true branch: `!body.input.is_open() || !body.input.incremental || body.pending() || body.stage != Stage::Ready || body.fragment.is_some()`.


<a id="cause-SignatureIsNotWaitingForStorage"></a>

### `SignatureIsNotWaitingForStorage`


Local detection/handling phase and implementation owner:

- `SignatureOperation::output_preparation` — `src/advanced/signature.rs`.


<a id="cause-SignatureLengthWidth"></a>

### `SignatureLengthWidth`


Local detection/handling phase and implementation owner:

- `RecordPlan<'a>::bind` — `src/advanced/signature/checkpoint.rs`.


<a id="cause-SignatureNativeInputMutation"></a>

### `SignatureNativeInputMutation`


Local detection/handling phase and implementation owner:

- `SignatureOperation::drive` — `src/advanced/signature.rs`. Enclosing true branch: `!self.unchanged()`.
- `attempt` (module-level helper) — `src/advanced/signature/competing_init.rs`. Enclosing false branch: `call.data.operation.unchanged()`.


<a id="cause-SignatureNativeLengthWidth"></a>

### `SignatureNativeLengthWidth`


Local detection/handling phase and implementation owner:

- `SignatureOperation::drive` — `src/advanced/signature.rs`. Enclosing true branch: `self.kind == Kind::Sign && stage == Stage::Terminal && (rv == CKR_BUFFER_TOO_SMALL || rv == CKR_OK && matches!(self.plan, SignatureOutputPlan::LengthOnly))`.


<a id="cause-SignatureNativeTerminationUncertain"></a>

### `SignatureNativeTerminationUncertain`


Local detection/handling phase and implementation owner:

- `SignatureOperation::drive` — `src/advanced/signature.rs`. Enclosing true branch: `completion == Completion::Uncertain`.


<a id="cause-SignatureNotAtACapturableBoundary"></a>

### `SignatureNotAtACapturableBoundary`


Local detection/handling phase and implementation owner:

- `SignatureOperation::snapshot_shape` — `src/advanced/signature/snapshot.rs`. Enclosing true branch: `!matches!( self.stage, Stage::Ready | Stage::Update | Stage::Terminal | Stage::Waiting(_) ) || self.pending() || self.native_inactive() || self.revocation.is_some() || !self.returned.is_empty() || self.observer != super::Observer::Ticket`.


<a id="cause-SignatureOperationAccounting"></a>

### `SignatureOperationAccounting`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`.
- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`.


<a id="cause-SignatureOutputAlignment"></a>

### `SignatureOutputAlignment`


Local detection/handling phase and implementation owner:

- `output_offset` (module-level helper) — `src/advanced/signature.rs`. Enclosing true branch: `offset >= alignment`.


<a id="cause-SignatureOutputAlignmentAccounting"></a>

### `SignatureOutputAlignmentAccounting`


Local detection/handling phase and implementation owner:

- `output_storage_bytes` (module-level helper) — `src/advanced/signature.rs`.


<a id="cause-SignatureOutputCapacity"></a>

### `SignatureOutputCapacity`

Detected during local signature-owner preparation: capacity exceeds the
caller's maximum_output, or verification was given nonzero signature output
capacity. No prepared owner is installed by this check. Correct the request's
representation/ceiling before a new local start; waiting for resources is not
a remedy. This is not a post-Sign buffer request and grants no replay authority.


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`. Enclosing true branch: `capacity > maximum_output || kind != Kind::Sign && capacity != 0`.


<a id="cause-SignatureOutputCeiling"></a>

### `SignatureOutputCeiling`


Local detection/handling phase and implementation owner:

- `SignatureOperation::output_preparation` — `src/advanced/signature.rs`. Enclosing true branch: `capacity > self.maximum_output`.


<a id="cause-SignaturePhaseNotSerializable"></a>

### `SignaturePhaseNotSerializable`


Local detection/handling phase and implementation owner:

- `SignatureOperation::phase` — `src/advanced/signature/checkpoint.rs`. Enclosing match alternative: `_`.


<a id="cause-SignaturePreparedOutputWidth"></a>

### `SignaturePreparedOutputWidth`


Local detection/handling phase and implementation owner:

- `SignatureOperation::attach_output` — `src/advanced/signature.rs`. Enclosing true branch: `output.as_slice().len() != self.output_storage_bytes(capacity)?`.


<a id="cause-SignatureReconstructionAccounting"></a>

### `SignatureReconstructionAccounting`


Local detection/handling phase and implementation owner:

- `total` (module-level helper) — `src/advanced/signature/checkpoint.rs`.


<a id="cause-SignatureResultAlreadyPublished"></a>

### `SignatureResultAlreadyPublished`


Local detection/handling phase and implementation owner:

- `SignatureOperation::result` — `src/advanced/signature.rs`.


<a id="cause-SignatureResultIncomplete"></a>

### `SignatureResultIncomplete`


Local detection/handling phase and implementation owner:

- `SignatureOperation::result` — `src/advanced/signature.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-SignatureRevocationAccounting"></a>

### `SignatureRevocationAccounting`


Local detection/handling phase and implementation owner:

- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`.
- `start_retained` (module-level helper) — `src/advanced/signature/preparation.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-SignatureRolesNotPrepared"></a>

### `SignatureRolesNotPrepared`


Local detection/handling phase and implementation owner:

- `Destination<'a>::try_access` — `src/advanced/signature/binding.rs`. Enclosing false branch: `self.source.is_some()`.


<a id="cause-SignatureSnapshotAccounting"></a>

### `SignatureSnapshotAccounting`


Local detection/handling phase and implementation owner:

- `overflow` (module-level helper) — `src/advanced/signature/snapshot.rs`.


<a id="cause-SignatureSnapshotShapeChanged"></a>

### `SignatureSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `Packet::copy_from` — `src/advanced/signature/snapshot.rs`. Enclosing true branch: `source.snapshot_shape(entry)? != self.shape`.


<a id="cause-SignatureStreamExtensionRoute"></a>

### `SignatureStreamExtensionRoute`


Local detection/handling phase and implementation owner:

- `Session::begin_extension_signature_stream` — `src/advanced/signature/api.rs`. Enclosing match alternative: `_`.
- `AdvancedSession::begin_extension_signature_stream` — `src/advanced/signature/api.rs`. Enclosing match alternative: `_`.


<a id="cause-SingleSignatureExtensionRoute"></a>

### `SingleSignatureExtensionRoute`


Local detection/handling phase and implementation owner:

- `Session::begin_extension_signature_single` — `src/advanced/signature/single.rs`. Enclosing match alternative: `_`.
- `AdvancedSession::begin_extension_signature_single` — `src/advanced/signature/single.rs`. Enclosing match alternative: `_`.


<a id="cause-UncopiedSignatureSnapshot"></a>

### `UncopiedSignatureSnapshot`


Local detection/handling phase and implementation owner:

- `Packet::materialize` — `src/advanced/signature/snapshot.rs`.


<a id="cause-UnsubmittedSignatureBindingCannotBeDuplicated"></a>

### `UnsubmittedSignatureBindingCannotBeDuplicated`


Local detection/handling phase and implementation owner:

- `Binding::duplicate` — `src/advanced/signature/binding.rs`. Enclosing true branch: `self.revocation.is_some()`.


<a id="cause-VerificationSignatureNotSupplied"></a>

### `VerificationSignatureNotSupplied`


Local detection/handling phase and implementation owner:

- `SignatureOperation::drive` — `src/advanced/signature.rs`. Enclosing true branch: `self.kind != Kind::Sign && self.signature.is_none()`.

