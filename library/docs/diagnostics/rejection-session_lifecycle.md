Cause contracts for `SessionLifecycleRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CAsyncCompleteUnavailable"></a>

### `CAsyncCompleteUnavailable`


Local detection/handling phase and implementation owner:

- `JoinedCall::poll` — `src/advanced/asynchronous.rs`.
- `AdvancedSession::poll_cancellation` — `src/advanced/cancellation.rs`.
- `drive_digest` (module-level helper) — `src/advanced/digest.rs`. Enclosing true branch: `op.activity.pending()`.
- `Capture::drive` — `src/advanced/validation.rs`. Enclosing true branch: `completing`.
- `Admission::drive` — `src/advanced/admission/progression.rs`. Enclosing true branch: `self.pending`.
- `DualOperation::drive` — `src/advanced/dual/operation.rs`. Enclosing true branch: `self.pending`.
- `AeadMessageOperation::drive_inner` — `src/advanced/gcm/progression.rs`. Enclosing true branch: `self.pending()`.
- `MacOperation::drive_inner` — `src/advanced/messages/progression.rs`. Enclosing true branch: `self.pending()`.
- `StateIo::drive_selected` — `src/advanced/state_io/progression.rs`. Enclosing true branch: `self.pending`.
- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing match alternative: `ClosePhase::Pending`.


<a id="cause-CFindObjectsUnavailable"></a>

### `CFindObjectsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::reference_search_functions` — `src/session/references.rs`.
- `SearchOwner::check_functions` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `access.native.table.C_FindObjects.is_none()`.


<a id="cause-CFindObjectsFinalUnavailable"></a>

### `CFindObjectsFinalUnavailable`


Local detection/handling phase and implementation owner:

- `Session::reference_search_functions` — `src/session/references.rs`.
- `SearchOwner::check_functions` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `access.native.table.C_FindObjectsFinal.is_none()`.


<a id="cause-CFindObjectsInitUnavailable"></a>

### `CFindObjectsInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::reference_search_functions` — `src/session/references.rs`.
- `SearchOwner::check_functions` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `access.native.table.C_FindObjectsInit.is_none()`.


<a id="cause-CGetSessionValidationFlagsUnavailable"></a>

### `CGetSessionValidationFlagsUnavailable`


Local detection/handling phase and implementation owner:

- `Session::validation_flags` in `src/session/validation_observation.rs`.


<a id="cause-CSignUnavailable"></a>

### `CSignUnavailable`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`. Enclosing false branch: `multipart`.
- `Session::sign_pss_selected` — `src/session/pss.rs`.
- `Session::sign_pss_selected` — `src/session/pss.rs`.
- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing false branch: `multipart`.


<a id="cause-CSignInitUnavailable"></a>

### `CSignInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::sign_native_frame` — `src/crypto/native_signature.rs`.
- `Session::sign_pss_selected` — `src/session/pss.rs`.
- `Session::sign_pss_selected` — `src/session/pss.rs`.
- `Session::pqc_sign_parts_guarded` — `src/crypto/pqc/frame.rs`.


<a id="cause-CVerifyUnavailable"></a>

### `CVerifyUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`. Enclosing false branch: `multipart`.
- `Session::verify_pss` — `src/session/pss.rs`.
- `Session::verify_pss` — `src/session/pss.rs`.
- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`. Enclosing false branch: `multipart`.


<a id="cause-CVerifyInitUnavailable"></a>

### `CVerifyInitUnavailable`


Local detection/handling phase and implementation owner:

- `Session::verify_native_mechanism` — `src/crypto/ecdsa.rs`.
- `Session::verify_pss` — `src/session/pss.rs`.
- `Session::verify_pss` — `src/session/pss.rs`.
- `Session::pqc_verify_parts_guarded` — `src/crypto/pqc/frame.rs`.


<a id="cause-Digest32RequiresSha256"></a>

### `Digest32RequiresSha256`


Local detection/handling phase and implementation owner:

- `PssParams::checked` — `src/session/pss.rs`. Enclosing true branch: `self.hash != CKM_SHA256 as u64`.


<a id="cause-PqcExportOwnerKind"></a>

### `PqcExportOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::pqc_export_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_pqc_export` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-PssInputChanged"></a>

### `PssInputChanged`


Local detection/handling phase and implementation owner:

- `Session::sign_pss_selected` — `src/session/pss.rs`. Enclosing true branch: `!call.parameters_unchanged(params) || call.digest.0 != *expected_digest`.


<a id="cause-PssInputChangedDuringContextAuthentication"></a>

### `PssInputChangedDuringContextAuthentication`


Local detection/handling phase and implementation owner:

- `Session::sign_pss_selected` — `src/session/pss.rs`. Enclosing true branch: `!call.parameters_unchanged(params) || call.digest.0 != *expected_digest`.


<a id="cause-PssInputDescriptorChanged"></a>

### `PssInputDescriptorChanged`


Local detection/handling phase and implementation owner:

- `Session::sign_pss_selected` — `src/session/pss.rs`. Enclosing true branch: `!call.parameters_unchanged(params)`.
- `Session::verify_pss` — `src/session/pss.rs`. Enclosing true branch: `!call.parameters_unchanged(params)`.


<a id="cause-PssStorageAccounting"></a>

### `PssStorageAccounting`


Local detection/handling phase and implementation owner:

- `Storage::prepare` — `src/session/pss_preparation.rs`.
- `Storage::prepare` — `src/session/pss_preparation.rs`.
- `Storage::prepare` — `src/session/pss_preparation.rs`.
- `Storage::prepare` — `src/session/pss_preparation.rs`.


<a id="cause-PssVerificationInputChanged"></a>

### `PssVerificationInputChanged`


Local detection/handling phase and implementation owner:

- `Session::verify_pss` — `src/session/pss.rs`. Enclosing true branch: `!call.parameters_unchanged(params) || call.digest.0 != *expected_digest || call.signature.as_slice() != signature`.


<a id="cause-RsaObjectsOwnerKind"></a>

### `RsaObjectsOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::rsa_objects_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-RsaSignatureAllocation"></a>

### `RsaSignatureAllocation`


Local detection/handling phase and implementation owner:

- `Storage::prepare` — `src/session/pss_preparation.rs`.


<a id="cause-RsaSignatureCapacity"></a>

### `RsaSignatureCapacity`


Local detection/handling phase and implementation owner:

- `Session::sign_pss_selected` — `src/session/pss.rs`. Enclosing true branch: `rv == fe11_sys::CKR_OK`.
- `Session::sign_pss_selected` — `src/session/pss.rs`.


<a id="cause-RsaSignatureLength"></a>

### `RsaSignatureLength`


Local detection/handling phase and implementation owner:

- `Session::sign_pss_selected` — `src/session/pss.rs`. Enclosing true branch: `length != capacity`.


<a id="cause-Sha256DigestLength"></a>

### `Sha256DigestLength`


Local detection/handling phase and implementation owner:

- `Digest32::from_bytes` — `src/session/pss.rs`.


<a id="cause-AsynchronousSessionRequiresOwnedDispatch"></a>

### `AsynchronousSessionRequiresOwnedDispatch`


Local detection/handling phase and implementation owner:

- `Session::entry` — `src/session/access.rs`. Enclosing true branch: `self.entry.mode == crate::AdvancedSessionMode::Asynchronous`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `self.entry.mode == AdvancedSessionMode::Asynchronous`.


<a id="cause-AttributeObservationAbsent"></a>

### `AttributeObservationAbsent`


Local detection/handling phase and implementation owner:

- `Registry::get` — `src/session/recovery/observations.rs`.


<a id="cause-AttributeObservationRetired"></a>

### `AttributeObservationRetired`


Local detection/handling phase and implementation owner:

- `Coordination::check` — `src/session/recovery/observations.rs`. Enclosing true branch: `!self.live.load(Ordering::Acquire) || self.withdrawn.load(Ordering::Acquire)`.


<a id="cause-AttributeOwnerKind"></a>

### `AttributeOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::flat_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_flat` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::content_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_content` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::legacy_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_legacy` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::fingerprint_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_fingerprint` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ContextAuthenticationPreparationMismatch"></a>

### `ContextAuthenticationPreparationMismatch`


Local detection/handling phase and implementation owner:

- `PreparedContextLogin<'a>::from_prepared` — `src/session/context_authentication.rs`. Enclosing match alternative: `_`.


<a id="cause-ContextAuthenticationRequiresTokenWriter"></a>

### `ContextAuthenticationRequiresTokenWriter`


Local detection/handling phase and implementation owner:

- `PreparedContextLogin<'a>::from_prepared` — `src/session/context_authentication.rs`. Enclosing true branch: `!access.context_writer_held()`.


<a id="cause-ContextAuthenticationStorageAccounting"></a>

### `ContextAuthenticationStorageAccounting`


Local detection/handling phase and implementation owner:

- `accounting` (module-level helper) — `src/session/context_authentication/preparation.rs`.


<a id="cause-ContextLoginAlreadyPerformed"></a>

### `ContextLoginAlreadyPerformed`


Local detection/handling phase and implementation owner:

- `PreparedContextLogin<'a>::perform` — `src/session/context_authentication.rs`.


<a id="cause-ControlFrameAccounting"></a>

### `ControlFrameAccounting`


Local detection/handling phase and implementation owner:

- `Session::prepare_control_candidate` in `src/session/control_preparation.rs`.


<a id="cause-CreationOwnerKind"></a>

### `CreationOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::creation_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationProtectionInCryptographicContinuation"></a>

### `CreationProtectionInCryptographicContinuation`


Local detection/handling phase and implementation owner:

- `ObjectRoleLease::retain_role_credits` — `src/session/ownership.rs`. Enclosing true branch: `protections.creation.is_some()`.


<a id="cause-DerivationOwnerKind"></a>

### `DerivationOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::derivation_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ForeignContextualAuthenticationSession"></a>

### `ForeignContextualAuthenticationSession`


Local detection/handling phase and implementation owner:

- `PreparedContextLogin<'a>::perform` — `src/session/context_authentication.rs`. Enclosing true branch: `!body.access.owns_session(session)`.


<a id="cause-ForeignInventoryProtection"></a>

### `ForeignInventoryProtection`


Local detection/handling phase and implementation owner:

- `ObservationProtection::inventory` — `src/session/observation_protection.rs`. Enclosing true branch: `!inventory.belongs_to(&session.inner, session.uid)`.


<a id="cause-ForeignMutationPossession"></a>

### `ForeignMutationPossession`


Local detection/handling phase and implementation owner:

- `MutationProtection::take` — `src/session/observation_protection.rs`. Enclosing true branch: `!access.owns_session(session)`.


<a id="cause-ForeignMutationProtection"></a>

### `ForeignMutationProtection`


Local detection/handling phase and implementation owner:

- `MutationProtection::destination_reservation` — `src/session/observation_protection.rs`. Enclosing true branch: `self.uid != session.uid`.
- `MutationProtection::forget_object` — `src/session/observation_protection.rs`. Enclosing true branch: `self.uid != session.uid`.


<a id="cause-ForeignObservationCredit"></a>

### `ForeignObservationCredit`


Local detection/handling phase and implementation owner:

- `Prepared::allocate` — `src/session/recovery/observations.rs`. Enclosing true branch: `!budget.same_account(credit.budget())`.


<a id="cause-ForeignObservationSelection"></a>

### `ForeignObservationSelection`


Local detection/handling phase and implementation owner:

- `ObservationProtection::selection_retained` — `src/session/observation_protection.rs`. Enclosing true branch: `!selected.belongs_to(&session.inner, session.uid)`.


<a id="cause-ForeignReferenceObservationBudget"></a>

### `ForeignReferenceObservationBudget`


Local detection/handling phase and implementation owner:

- `ReferenceAdmission<'_>::objects_with_storage_observing` — `src/session/references.rs`. Enclosing true branch: `!observation.same_account(&self.session.inner.symmetric_budget)`.


<a id="cause-InventoryOwnerKind"></a>

### `InventoryOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::inventory_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_inventory` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-LegacyParallelFunctionUnavailable"></a>

### `LegacyParallelFunctionUnavailable`


Local detection/handling phase and implementation owner:

- `Session::legacy_call` in `src/session/legacy.rs`.


<a id="cause-LifecycleDiagnosticAlreadyConsumed"></a>

### `LifecycleDiagnosticAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Loan::completion` — `src/session/lifecycle_diagnostics.rs`.


<a id="cause-LifecycleSecondaryDiagnosticAlreadyConsumed"></a>

### `LifecycleSecondaryDiagnosticAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Loan::completions` — `src/session/lifecycle_diagnostics.rs`.


<a id="cause-ManagedCopyOwnerKind"></a>

### `ManagedCopyOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::copy_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDestructionOwnerKind"></a>

### `ManagedDestructionOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::destruction_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryOwnerKind"></a>

### `ManagedDiscoveryOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::discovery_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_discovery` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedLabelOwnerKind"></a>

### `ManagedLabelOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::label_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_label` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedSetAttributesOwnerKind"></a>

### `ManagedSetAttributesOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::set_attributes_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_set_attributes` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ModuleAcceptedACompetingObjectSearch"></a>

### `ModuleAcceptedACompetingObjectSearch`


Local detection/handling phase and implementation owner:

- `Registry::search_initialized` — `src/session/recovery/observations.rs`.


<a id="cause-MutationProtectionAbsent"></a>

### `MutationProtectionAbsent`


Local detection/handling phase and implementation owner:

- `MutationProtection::take` — `src/session/observation_protection.rs`. Enclosing true branch: `(objects.resources.is_none() && objects.source_free.is_none()) || objects.creation.is_none()`.
- `MutationProtection::destination_reservation` — `src/session/observation_protection.rs`.
- `MutationProtection::forget_object` — `src/session/observation_protection.rs`.


<a id="cause-NativeOutputsOwnerKind"></a>

### `NativeOutputsOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::outputs_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeSearchOwnerKind"></a>

### `NativeSearchOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::native_search_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeSearchOwnershipChanged"></a>

### `NativeSearchOwnershipChanged`


Local detection/handling phase and implementation owner:

- `Registry::search_terminated` — `src/session/recovery/observations.rs`.


<a id="cause-NativeSearchStreamOwnerKind"></a>

### `NativeSearchStreamOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::native_search_stream_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-NativeSessionHandleRetired"></a>

### `NativeSessionHandleRetired`


Local detection/handling phase and implementation owner:

- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing true branch: `entry.native_handle_retired() && !matches!( control.as_ref().map(|control| control.phase), Some(ClosePhase::Returned { .. }) )`.


<a id="cause-ObjectActivityOwnersAllocation"></a>

### `ObjectActivityOwnersAllocation`


Local detection/handling phase and implementation owner:

- `DynamicReadStorage::allocate` — `src/session/activity/dynamic.rs`.
- `DynamicReadStorage::allocate` — `src/session/activity/dynamic.rs`.


<a id="cause-ObjectActivityStorageAccounting"></a>

### `ObjectActivityStorageAccounting`


Local detection/handling phase and implementation owner:

- `bytes` (module-level helper) — `src/session/activity/dynamic.rs`.


<a id="cause-ObjectActivityStorageShapeChanged"></a>

### `ObjectActivityStorageShapeChanged`


Local detection/handling phase and implementation owner:

- `DynamicReadPlan<I>::pin` — `src/session/activity/dynamic.rs`. Enclosing true branch: `prepared.readers.len() != self.count || prepared.permits.len() != self.count`.


<a id="cause-ObjectPermissionStorageAccounting"></a>

### `ObjectPermissionStorageAccounting`


Local detection/handling phase and implementation owner:

- `PermissionStorage::requested` — `src/session/activity/roles.rs`.


<a id="cause-ObjectPermissionStorageAllocation"></a>

### `ObjectPermissionStorageAllocation`


Local detection/handling phase and implementation owner:

- `PermissionStorage::allocate` — `src/session/activity/roles.rs`.


<a id="cause-ObjectPermissionStorageShape"></a>

### `ObjectPermissionStorageShape`


Local detection/handling phase and implementation owner:

- `RolePlan<'k, N>::acquire_into_on` — `src/session/activity/roles.rs`. Enclosing true branch: `permissions.len() != N`.


<a id="cause-ObjectProtectionsAlreadyRetained"></a>

### `ObjectProtectionsAlreadyRetained`


Local detection/handling phase and implementation owner:

- `SessionAccess<'_, T>::object_protections` — `src/session/access.rs`. Enclosing true branch: `self.guards.retained_objects.values.get().is_some()`.


<a id="cause-ObjectResourceRolesAlreadyRetained"></a>

### `ObjectResourceRolesAlreadyRetained`


Local detection/handling phase and implementation owner:

- `SessionAccess<'_, T>::retain_resources` — `src/session/access.rs`. Enclosing true branch: `objects.resources.is_some()`.


<a id="cause-ObservationPreparationAbsent"></a>

### `ObservationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Registry::publish_retained` — `src/session/recovery/observations.rs`.


<a id="cause-ObservationSelectionAbsent"></a>

### `ObservationSelectionAbsent`


Local detection/handling phase and implementation owner:

- `ObservationProtection::selection_retained` — `src/session/observation_protection.rs`.


<a id="cause-OperationDestinationsAlreadyRetained"></a>

### `OperationDestinationsAlreadyRetained`


Local detection/handling phase and implementation owner:

- `SessionAccess<'_, T>::retain_creation_activity` — `src/session/access.rs`. Enclosing true branch: `objects.creation.is_some()`.


<a id="cause-OperationLeaseRequiresOrdinaryAdmission"></a>

### `OperationLeaseRequiresOrdinaryAdmission`


Local detection/handling phase and implementation owner:

- `SessionAccess<'_>::lease_admission` — `src/session/access.rs`. Enclosing match alternative: `AccessProvenance::Cleanup | AccessProvenance::Administrative | AccessProvenance::ContextAuthentication`.


<a id="cause-PolicyObservationOwnerKind"></a>

### `PolicyObservationOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::policy_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_policy` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicFingerprintOwnerKind"></a>

### `PublicFingerprintOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::public_fingerprint_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_public_fingerprint` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceAdmissionAbsent"></a>

### `ReferenceAdmissionAbsent`


Local detection/handling phase and implementation owner:

- `ReferenceAdmission<'_>::into_prepaid_managed_retained` — `src/session/references.rs`.


<a id="cause-ReferenceOwnerKind"></a>

### `ReferenceOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::reference_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_reference` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceReservationAbsent"></a>

### `ReferenceReservationAbsent`


Local detection/handling phase and implementation owner:

- `ManagedReferences::into_permit_retained` — `src/session/references.rs`.
- `ReferenceAdmission<'_>::into_prepaid_managed_retained` — `src/session/references.rs`.


<a id="cause-RetainedRoleProtectionsAbsent"></a>

### `RetainedRoleProtectionsAbsent`


Local detection/handling phase and implementation owner:

- `ObjectRoleLease::retain_role_credits` — `src/session/ownership.rs`.


<a id="cause-RetainedSourceAbsent"></a>

### `RetainedSourceAbsent`


Local detection/handling phase and implementation owner:

- `AdmissionProgress::retain_additional` — `src/session/admission_progress.rs`.


<a id="cause-RetainedSourceAlreadyAttached"></a>

### `RetainedSourceAlreadyAttached`


Local detection/handling phase and implementation owner:

- `AdmissionProgress::retaining` — `src/session/admission_progress.rs`. Enclosing true branch: `self.retained_source.is_some()`.


<a id="cause-SearchRetirementOwnerKind"></a>

### `SearchRetirementOwnerKind`


Local detection/handling phase and implementation owner:

- `Registry::retire_native_search` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-SequenceContextUnavailable"></a>

### `SequenceContextUnavailable`


Local detection/handling phase and implementation owner:

- `Sequence<'a>::check_context` — `src/session/sequence.rs`.


<a id="cause-SequenceOutcomeUncertain"></a>

### `SequenceOutcomeUncertain`


Local detection/handling phase and implementation owner:

- `Sequence<'a>::check_context` — `src/session/sequence.rs`. Enclosing true branch: `self.completion.get() == Completion::Uncertain`.


<a id="cause-SessionCloseAlreadyAttempted"></a>

### `SessionCloseAlreadyAttempted`


Local detection/handling phase and implementation owner:

- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing true branch: `entry.close_attempted.load(Ordering::Acquire) && control.is_none()`.


<a id="cause-SessionClosed"></a>

### `SessionClosed`


Local detection/handling phase and implementation owner:

- `Session::entry_common` — `src/session/access.rs`. Enclosing true branch: `e.closed.load(Ordering::Acquire)`.
- `context_admitted` (module-level helper) — `src/session/activity.rs`. Enclosing true branch: `entry.closed.load(std::sync::atomic::Ordering::Acquire)`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `self.entry.closed.load(Ordering::Acquire)`.
- `close_entry` (module-level helper) — `src/session/close.rs`. Enclosing true branch: `entry.closed.load(Ordering::Acquire) && control.is_none()`.


<a id="cause-SessionClosingOrCloseFailed"></a>

### `SessionClosingOrCloseFailed`


Local detection/handling phase and implementation owner:

- `Session::entry_common` — `src/session/access.rs`. Enclosing true branch: `e.close_attempted.load(Ordering::Acquire)`.
- `context_admitted` (module-level helper) — `src/session/activity.rs`. Enclosing true branch: `entry .close_attempted .load(std::sync::atomic::Ordering::Acquire)`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `self.entry.close_attempted.load(Ordering::Acquire)`.


<a id="cause-SessionGenerationMismatch"></a>

### `SessionGenerationMismatch`


Local detection/handling phase and implementation owner:

- `Session::entry_common` — `src/session/access.rs`. Enclosing true branch: `e.generation != self.snapshot.generation || e.slot as u64 != self.snapshot.capabilities.identity.slot`.
- `context_admitted` (module-level helper) — `src/session/activity.rs`. Enclosing true branch: `entry.generation != session.snapshot.generation || entry.slot as u64 != session.snapshot.capabilities.identity.slot`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `self.entry.generation != self.snapshot.generation || self.entry.slot as u64 != self.snapshot.capabilities.identity.slot`.


<a id="cause-SessionLifecycleDiagnosticAbsent"></a>

### `SessionLifecycleDiagnosticAbsent`


Local detection/handling phase and implementation owner:

- `close_entry` (module-level helper) — `src/session/close.rs`.


<a id="cause-SessionLifecycleStorageAccounting"></a>

### `SessionLifecycleStorageAccounting`


Local detection/handling phase and implementation owner:

- `Store::including` — `src/session/lifecycle_diagnostics.rs`.


<a id="cause-SessionStateUncertain"></a>

### `SessionStateUncertain`


Local detection/handling phase and implementation owner:

- `Session::entry_common` — `src/session/access.rs`. Enclosing true branch: `e.poisoned.load(Ordering::Acquire)`.
- `context_admitted` (module-level helper) — `src/session/activity.rs`. Enclosing true branch: `entry.poisoned.load(std::sync::atomic::Ordering::Acquire)`.
- `LocalOwnership<'_>::validate` — `src/session/ownership.rs`. Enclosing true branch: `self.state.native.is_uncertain() || entry.poisoned.load(Ordering::Acquire) || entry.closed.load(Ordering::Acquire) || entry.close_attempted.load(Ordering::Acquire) || entry.close_pending.load(Ordering::Acquire)`.
- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `self.entry.poisoned.load(Ordering::Acquire)`.


<a id="cause-SignatureWriterCapabilityAbsent"></a>

### `SignatureWriterCapabilityAbsent`


Local detection/handling phase and implementation owner:

- `ObjectRoleLease::transfer_writer` — `src/session/ownership.rs`.


<a id="cause-SignatureWriterNotInstalled"></a>

### `SignatureWriterNotInstalled`


Local detection/handling phase and implementation owner:

- `ObjectRoleLease::transfer_writer` — `src/session/ownership.rs`.


<a id="cause-SigningSelectionOwnerKind"></a>

### `SigningSelectionOwnerKind`


Local detection/handling phase and implementation owner:

- `Owner::key_readmission_mut` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.
- `Owner::into_key_readmission` — `src/session/recovery/observations.rs`. Enclosing match alternative: `_`.


<a id="cause-SourceFreeRolesAlreadyRetained"></a>

### `SourceFreeRolesAlreadyRetained`


Local detection/handling phase and implementation owner:

- `SessionAccess<'_, T>::retain_prepared_permissions` — `src/session/access.rs`. Enclosing true branch: `objects.source_free.is_some()`.


<a id="cause-SynchronousAdmissionRequiresASynchronousSession"></a>

### `SynchronousAdmissionRequiresASynchronousSession`


Local detection/handling phase and implementation owner:

- `Session::reference_context` — `src/session/references.rs`. Enclosing true branch: `matches!(mode, ReferenceMode::SynchronousAdmission) && self.entry.mode != AdvancedSessionMode::Synchronous`.
- `run_synchronous` (module-level helper) — `src/advanced/admission/synchronous.rs`. Enclosing true branch: `session.entry.mode != AdvancedSessionMode::Synchronous`.


<a id="cause-UnplannedProtectionInCryptographicContinuation"></a>

### `UnplannedProtectionInCryptographicContinuation`


Local detection/handling phase and implementation owner:

- `ObjectRoleLease::retain_role_credits` — `src/session/ownership.rs`. Enclosing match alternative: `Some( ResourceProtection::One { .. } | ResourceProtection::Readers { .. } | ResourceProtection::Observation { .. }, )`.


<a id="cause-ValidationFlagsTypeConversion"></a>

### `ValidationFlagsTypeConversion`


Local detection/handling phase and implementation owner:

- `Session::validation_flags` in `src/session/validation_observation.rs`.
