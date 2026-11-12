Cause contracts for `ObjectReferencesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGetObjectSizeUnavailable"></a>

### `CGetObjectSizeUnavailable`


Local detection/handling phase and implementation owner:

- `Session::managed_object_size_prepared` — `src/managed/size.rs`.


<a id="cause-RsaObservedPublicationAbsent"></a>

### `RsaObservedPublicationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::RsaEvidence { read, .. }`.


<a id="cause-RsaPrivateEvidenceAbsent"></a>

### `RsaPrivateEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `observe_private_rsa` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-RsaReadmissionStorageSize"></a>

### `RsaReadmissionStorageSize`


Local detection/handling phase and implementation owner:

- `Plan<'_>::requested` — `src/managed/key_readmission/preparation.rs`. Enclosing match alternative: `Self::PrivateRsa(spec)`.
- `Initial::allocated_bytes` — `src/managed/key_readmission/preparation.rs`. Enclosing match alternative: `Self::PrivateRsa { first, second }`.


<a id="cause-RsaReferencePreparationAbsent"></a>

### `RsaReferencePreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::RsaEvidence { report, handle, read, }`.


<a id="cause-RsaReferenceQuotaTransferred"></a>

### `RsaReferenceQuotaTransferred`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::RsaEvidence { report, handle, read, }`.


<a id="cause-DestinationAggregateAccounting"></a>

### `DestinationAggregateAccounting`


Local detection/handling phase and implementation owner:

- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.
- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.
- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`. Enclosing true branch: `actual > admitted`.
- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing true branch: `actual > admitted`.
- `Reservation::prepare_with_native_roles_prepaid` — `src/managed/mutations/possession/prepaid.rs`.
- `Reservation::prepare_with_native_roles_prepaid` — `src/managed/mutations/possession/prepaid.rs`.
- `execute` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`.
- `execute` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`.
- `execute` (module-level helper) — `src/managed/mutations/copy/resident/preparation.rs`. Enclosing true branch: `actual > admitted`.
- `prepare_creation` (module-level helper) — `src/managed/mutations/create/resident/private.rs`.
- `prepare_creation` (module-level helper) — `src/managed/mutations/create/resident/private.rs`.
- `prepare_creation` (module-level helper) — `src/managed/mutations/create/resident/private.rs`. Enclosing true branch: `actual > admitted`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`. Enclosing true branch: `actual > admitted`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`. Enclosing true branch: `actual > admitted`.
- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-DestructionAlreadyDispatched"></a>

### `DestructionAlreadyDispatched`


Local detection/handling phase and implementation owner:

- `DestructionOwner::destroy` — `src/managed/destruction/resident.rs`.


<a id="cause-DestructionDiagnosticAlreadyConsumed"></a>

### `DestructionDiagnosticAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `DestructionDiagnostic::take` — `src/managed/destruction/preparation.rs`.


<a id="cause-DestructionObservationAbsent"></a>

### `DestructionObservationAbsent`


Local detection/handling phase and implementation owner:

- `DestructionOwner::read` — `src/managed/destruction/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-DestructionOwnerAbsent"></a>

### `DestructionOwnerAbsent`


Local detection/handling phase and implementation owner:

- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.
- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.


<a id="cause-DestructionPossessionAbsent"></a>

### `DestructionPossessionAbsent`


Local detection/handling phase and implementation owner:

- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.


<a id="cause-DestructionPreparationAccounting"></a>

### `DestructionPreparationAccounting`


Local detection/handling phase and implementation owner:

- `prepare_destruction` (module-level helper) — `src/managed/destruction/preparation.rs`.


<a id="cause-DestructionResourceNeedAbsent"></a>

### `DestructionResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.


<a id="cause-DestructionStorageSize"></a>

### `DestructionStorageSize`


Local detection/handling phase and implementation owner:

- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.
- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.
- `destroy` (module-level helper) — `src/managed/destruction/resident.rs`.


<a id="cause-DiscoveryActivityAlreadyBound"></a>

### `DiscoveryActivityAlreadyBound`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_discovered` — `src/managed/native_identity.rs`.


<a id="cause-DiscoveryIdentityAlreadyShared"></a>

### `DiscoveryIdentityAlreadyShared`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_discovered` — `src/managed/native_identity.rs`.


<a id="cause-DiscoveryIdentityMismatch"></a>

### `DiscoveryIdentityMismatch`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_discovered` — `src/managed/native_identity.rs`. Enclosing true branch: `handle == CK_INVALID_HANDLE || identity.handle != CK_INVALID_HANDLE || identity.session != session.uid || identity.slot != session.entry.slot || identity.generation != session.snapshot.generation || !matches!(identity.initial_creator, ObjectCreator::UnknownPersistence)`.


<a id="cause-ForeignDestructionResource"></a>

### `ForeignDestructionResource`


Local detection/handling phase and implementation owner:

- `Session::destroy_resource_with` — `src/managed/destruction.rs`. Enclosing true branch: `resource.session != self.uid || resource.slot != entry.slot || resource.generation != self.snapshot.generation || session_handle != entry.handle || resource.handle == CK_INVALID_HANDLE`.


<a id="cause-ForeignNativeObject"></a>

### `ForeignNativeObject`


Local detection/handling phase and implementation owner:

- `Session::native_object_handle` — `src/managed.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &object.inner)`.
- `Session::destroy_native_object` — `src/managed/destruction.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &object.inner)`.
- `observe_native` (module-level helper) — `src/managed/discovery/runner.rs`. Enclosing true branch: `!Arc::ptr_eq(&session.inner, &object.inner)`.


<a id="cause-ForeignOrStaleManagedObject"></a>

### `ForeignOrStaleManagedObject`


Local detection/handling phase and implementation owner:

- `Session::managed_identity_handle` — `src/managed.rs`. Enclosing true branch: `self.uid != identity.session || e.slot != identity.slot || self.snapshot.generation != identity.generation || identity.revoked.load(Ordering::Acquire)`.


<a id="cause-ForeignOrStaleNativeObject"></a>

### `ForeignOrStaleNativeObject`


Local detection/handling phase and implementation owner:

- `Session::native_identity_handle` — `src/managed.rs`. Enclosing true branch: `identity.handle == CK_INVALID_HANDLE || self.uid != identity.session || entry.slot != identity.slot || self.snapshot.generation != identity.generation || identity.revoked.load(Ordering::Acquire)`.


<a id="cause-InvalidAdmittedHandle"></a>

### `InvalidAdmittedHandle`


Local detection/handling phase and implementation owner:

- `Session::observed_key_reference` — `src/managed.rs`. Enclosing true branch: `handle == CK_INVALID_HANDLE`.


<a id="cause-InvalidReturnedNativeHandle"></a>

### `InvalidReturnedNativeHandle`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_into` — `src/managed/native_identity.rs`. Enclosing true branch: `handle == CK_INVALID_HANDLE`.


<a id="cause-InventorySortCapacity"></a>

### `InventorySortCapacity`


Local detection/handling phase and implementation owner:

- `sort` (module-level helper) — `src/managed/metadata.rs`. Enclosing true branch: `!order.is_empty() || order.capacity() < rows.len()`.


<a id="cause-KeyEvidencePreparationAbsent"></a>

### `KeyEvidencePreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::Search(read)`.


<a id="cause-KeyPublicationAbsent"></a>

### `KeyPublicationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/managed/key_readmission.rs`.


<a id="cause-KeyReadmissionCandidateKind"></a>

### `KeyReadmissionCandidateKind`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/key_readmission/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyReadmissionCompletionPhase"></a>

### `KeyReadmissionCompletionPhase`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyReadmissionContinuationChanged"></a>

### `KeyReadmissionContinuationChanged`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/key_readmission/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-KeyReadmissionIncomplete"></a>

### `KeyReadmissionIncomplete`


Local detection/handling phase and implementation owner:

- `Owner::result` — `src/managed/key_readmission.rs`. Enclosing match alternative: `_`.


<a id="cause-KeyReadmissionNeedAbsent"></a>

### `KeyReadmissionNeedAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-KeyReadmissionOwnerAbsent"></a>

### `KeyReadmissionOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/key_readmission/runner.rs`.
- `run` (module-level helper) — `src/managed/key_readmission/runner.rs`. Enclosing true branch: `need == Need::SecondSelection`.
- `run` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-KeyReadmissionPossessionAbsent"></a>

### `KeyReadmissionPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-KeyReadmissionStopped"></a>

### `KeyReadmissionStopped`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-KeyReadmissionStorageSize"></a>

### `KeyReadmissionStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-KeyReferencePreparationAbsent"></a>

### `KeyReferencePreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::PublicEvidence { report, handle, read, }`.


<a id="cause-KeyReferenceQuotaTransferred"></a>

### `KeyReferenceQuotaTransferred`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::PublicEvidence { report, handle, read, }`.


<a id="cause-KeyTypeWidth"></a>

### `KeyTypeWidth`


Local detection/handling phase and implementation owner:

- `Session::observed_key_reference` — `src/managed.rs`.
- `key_type` (module-level helper) — `src/managed/discovery.rs`. Enclosing true branch: `class.has_key_type()`.


<a id="cause-NativeCreationAlreadyPublished"></a>

### `NativeCreationAlreadyPublished`


Local detection/handling phase and implementation owner:

- `SinglePublication::publish` — `src/managed/native_identity.rs`.


<a id="cause-NativeCreationNotPublished"></a>

### `NativeCreationNotPublished`


Local detection/handling phase and implementation owner:

- `SinglePublication::reference` — `src/managed/native_identity.rs`.


<a id="cause-NativeIdentityActivityAlreadyBound"></a>

### `NativeIdentityActivityAlreadyBound`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_into` — `src/managed/native_identity.rs`.


<a id="cause-NativeIdentityNotPublished"></a>

### `NativeIdentityNotPublished`


Local detection/handling phase and implementation owner:

- `NativeIdentity::activity` — `src/managed/native_identity.rs`.


<a id="cause-NativeIdentityPreparationAlreadyShared"></a>

### `NativeIdentityPreparationAlreadyShared`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_into` — `src/managed/native_identity.rs`.


<a id="cause-NativeIdentityPreparationMismatch"></a>

### `NativeIdentityPreparationMismatch`


Local detection/handling phase and implementation owner:

- `NativeIdentity::publish_into` — `src/managed/native_identity.rs`. Enclosing true branch: `identity.handle != CK_INVALID_HANDLE || identity.slot != entry.slot || identity.generation != entry.generation || !matches!(&identity.initial_creator, ObjectCreator::Known(creator) if std::ptr::eq(creator.as_ptr(), entry))`.


<a id="cause-ObjectObservationLifetimeChanged"></a>

### `ObjectObservationLifetimeChanged`


Local detection/handling phase and implementation owner:

- `NativeIdentity::observed_object` — `src/managed/native_identity.rs`. Enclosing true branch: `existing.handle != handle || existing.session != session.uid || !Arc::ptr_eq(existing.activity()?, &activity)`.


<a id="cause-ObjectSizeAggregateAccountingOverflow"></a>

### `ObjectSizeAggregateAccountingOverflow`


Local detection/handling phase and implementation owner:

- `Session::managed_object_size_prepared` — `src/managed/size.rs`.


<a id="cause-ObjectSizeMetadataAccountingOverflow"></a>

### `ObjectSizeMetadataAccountingOverflow`


Local detection/handling phase and implementation owner:

- `Session::managed_object_size_prepared` — `src/managed/size.rs`.


<a id="cause-ObservationNativeHandleChanged"></a>

### `ObservationNativeHandleChanged`


Local detection/handling phase and implementation owner:

- `Session::publish_managed_observation` — `src/managed.rs`. Enclosing true branch: `native.handle != o`.


<a id="cause-PublicFingerprintCandidateKind"></a>

### `PublicFingerprintCandidateKind`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::attach` — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicFingerprintCompletionPhase"></a>

### `PublicFingerprintCompletionPhase`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::advance` — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicFingerprintContentPhase"></a>

### `PublicFingerprintContentPhase`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::attach` — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicFingerprintContinuationChanged"></a>

### `PublicFingerprintContinuationChanged`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::attach` — `src/managed/public_fingerprint.rs`. Enclosing true branch: `self.need()? != Some(need)`.


<a id="cause-PublicFingerprintIncomplete"></a>

### `PublicFingerprintIncomplete`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::result` — `src/managed/public_fingerprint.rs`.


<a id="cause-PublicFingerprintNeedAbsent"></a>

### `PublicFingerprintNeedAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.


<a id="cause-PublicFingerprintOwnerAbsent"></a>

### `PublicFingerprintOwnerAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.
- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.


<a id="cause-PublicFingerprintPossessionAbsent"></a>

### `PublicFingerprintPossessionAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.


<a id="cause-PublicFingerprintSearchPhase"></a>

### `PublicFingerprintSearchPhase`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::attach` — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicFingerprintStopped"></a>

### `PublicFingerprintStopped`


Local detection/handling phase and implementation owner:

- `PublicFingerprintOwner::advance` — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-PublicFingerprintStorageSize"></a>

### `PublicFingerprintStorageSize`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `Need::Header`.
- `prepare` (module-level helper) — `src/managed/public_fingerprint.rs`. Enclosing match alternative: `Need::Header`.
- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.
- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.
- `observe` (module-level helper) — `src/managed/public_fingerprint.rs`.


<a id="cause-PublicKeyEvidenceAbsent"></a>

### `PublicKeyEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `observe_public` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-ReadmissionSelectionAbsent"></a>

### `ReadmissionSelectionAbsent`


Local detection/handling phase and implementation owner:

- `Owner::protection` — `src/managed/key_readmission.rs`.


<a id="cause-ReferenceCandidateKind"></a>

### `ReferenceCandidateKind`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::attach` — `src/reference_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceCardinalityWidth"></a>

### `ReferenceCardinalityWidth`


Local detection/handling phase and implementation owner:

- `SearchEvidence::observe` — `src/reference_controls/evaluation.rs`. Enclosing match alternative: `Some(found)`.


<a id="cause-ReferenceCompletionPhase"></a>

### `ReferenceCompletionPhase`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::advance` — `src/reference_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceContentPhase"></a>

### `ReferenceContentPhase`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::attach` — `src/reference_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceContinuationChanged"></a>

### `ReferenceContinuationChanged`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::attach` — `src/reference_controls/resident.rs`. Enclosing true branch: `self.need()? != Some(need)`.


<a id="cause-ReferenceDiagnosticStorageSize"></a>

### `ReferenceDiagnosticStorageSize`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.


<a id="cause-ReferenceFingerprintPhase"></a>

### `ReferenceFingerprintPhase`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::attach` — `src/reference_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceFingerprintSelection"></a>

### `ReferenceFingerprintSelection`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/reference_controls/resident/preparation.rs`. Enclosing match alternative: `Need::Fingerprint(need)`.


<a id="cause-ReferenceIncomplete"></a>

### `ReferenceIncomplete`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::result` — `src/reference_controls/resident.rs`.


<a id="cause-ReferenceMetadataAllocation"></a>

### `ReferenceMetadataAllocation`


Local detection/handling phase and implementation owner:

- `bytes` (module-level helper) — `src/reference_controls.rs`.
- `bound` (module-level helper) — `src/reference_controls/evaluation.rs`.


<a id="cause-ReferenceMetadataPhase"></a>

### `ReferenceMetadataPhase`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::attach` — `src/reference_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceMetadataSize"></a>

### `ReferenceMetadataSize`


Local detection/handling phase and implementation owner:

- `bound_requested_bytes` (module-level helper) — `src/reference_controls/evaluation.rs`. Enclosing true branch: `bound_requested(selection, object, key)`.
- `bound_allocated_bytes` (module-level helper) — `src/reference_controls/evaluation.rs`.
- `bound_allocated_bytes` (module-level helper) — `src/reference_controls/evaluation.rs`.


<a id="cause-ReferenceObservationRequiresPreparedOwner"></a>

### `ReferenceObservationRequiresPreparedOwner`


Local detection/handling phase and implementation owner:

- `ObjectReferenceReport::observe_local` — `src/reference_controls.rs`. Enclosing true branch: `resident::preparation::Initial::requires_preparation( &selection, object, resident::content_plan(&content), )?`.


<a id="cause-ReferenceObservationStopped"></a>

### `ReferenceObservationStopped`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::advance` — `src/reference_controls/resident.rs`. Enclosing match alternative: `Stage::Stopped`.


<a id="cause-ReferenceOwnerAbsent"></a>

### `ReferenceOwnerAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.
- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.


<a id="cause-ReferencePossessionAbsent"></a>

### `ReferencePossessionAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.


<a id="cause-ReferencePreparationAlreadyBound"></a>

### `ReferencePreparationAlreadyBound`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/reference_controls/resident/preparation.rs`. Enclosing match alternative: `InitialSearch::Bound(_) | InitialSearch::Consumed`.


<a id="cause-ReferencePreparationAlreadyConsumed"></a>

### `ReferencePreparationAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Initial::bind_prechecked_retained` — `src/reference_controls/resident/preparation.rs`. Enclosing true branch: `matches!(self.search, InitialSearch::Consumed) || content.is_none() || protection.is_none()`.


<a id="cause-ReferencePreparationInvalidated"></a>

### `ReferencePreparationInvalidated`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.


<a id="cause-ReferenceResourceNeedAbsent"></a>

### `ReferenceResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.


<a id="cause-ReferenceSearchPhase"></a>

### `ReferenceSearchPhase`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::attach` — `src/reference_controls/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-ReferenceSearchPreparationAbsent"></a>

### `ReferenceSearchPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Initial::allocated_bytes` — `src/reference_controls/resident/preparation.rs`. Enclosing match alternative: `InitialSearch::Storage { storage, .. }`.


<a id="cause-ReferenceSnapshotLength"></a>

### `ReferenceSnapshotLength`


Local detection/handling phase and implementation owner:

- `CurrentEvidence::observe` — `src/reference_controls/evaluation.rs`. Enclosing true branch: `observed.len() != selection.attributes.len()`.


<a id="cause-ReferenceSourceChanged"></a>

### `ReferenceSourceChanged`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::advance` — `src/reference_controls/resident.rs`. Enclosing true branch: `handle != self.handle`.


<a id="cause-ReferenceStorageSize"></a>

### `ReferenceStorageSize`


Local detection/handling phase and implementation owner:

- `metadata` (module-level helper) — `src/reference_controls/resident/preparation.rs`.
- `metadata` (module-level helper) — `src/reference_controls/resident/preparation.rs`.
- `Initial::requested` — `src/reference_controls/resident/preparation.rs`.
- `Initial::allocated_bytes` — `src/reference_controls/resident/preparation.rs`.
- `Initial::bind_prechecked_retained` — `src/reference_controls/resident/preparation.rs`.
- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.
- `observe` (module-level helper) — `src/reference_controls/resident/runner.rs`.


<a id="cause-RevocationPreparationAlreadyConsumed"></a>

### `RevocationPreparationAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `PreparedRevocations::populate` — `src/managed/destruction/prepared.rs`.


<a id="cause-RevocationReferenceAllocation"></a>

### `RevocationReferenceAllocation`


Local detection/handling phase and implementation owner:

- `RevocationShape::allocate` — `src/managed/destruction/prepared.rs`.
- `RevocationShape::allocate` — `src/managed/destruction/prepared.rs`.


<a id="cause-RevocationReferenceStorageAccounting"></a>

### `RevocationReferenceStorageAccounting`


Local detection/handling phase and implementation owner:

- `bytes` (module-level helper) — `src/managed/destruction/prepared.rs`.


<a id="cause-RevocationRetentionAccounting"></a>

### `RevocationRetentionAccounting`


Local detection/handling phase and implementation owner:

- `RevocationShape::allocation_bytes` — `src/managed/destruction/prepared.rs`.
- `RevocationStorage::allocated_bytes` — `src/managed/destruction/prepared.rs`.


<a id="cause-RevocationRetentionAllocation"></a>

### `RevocationRetentionAllocation`


Local detection/handling phase and implementation owner:

- `RevocationShape::allocate` — `src/managed/destruction/prepared.rs`.
- `RevocationShape::allocate` — `src/managed/destruction/prepared.rs`.


<a id="cause-RevocationRetentionAlreadyConsumed"></a>

### `RevocationRetentionAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `PreparedRevocations::populate` — `src/managed/destruction/prepared.rs`.


<a id="cause-RevocationSetStorageAccounting"></a>

### `RevocationSetStorageAccounting`


Local detection/handling phase and implementation owner:

- `sum` (module-level helper) — `src/managed/destruction/revocation_set.rs`.


<a id="cause-SecondRsaSearchPreparationAbsent"></a>

### `SecondRsaSearchPreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::select_again` — `src/managed/key_readmission.rs`.


<a id="cause-SecondRsaSelectionPhase"></a>

### `SecondRsaSelectionPhase`


Local detection/handling phase and implementation owner:

- `Owner::select_again` — `src/managed/key_readmission.rs`.


<a id="cause-SecondSelectionPreparationAbsent"></a>

### `SecondSelectionPreparationAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/key_readmission/runner.rs`. Enclosing true branch: `need == Need::SecondSelection`.


<a id="cause-SelectionIsNotAStorageRequest"></a>

### `SelectionIsNotAStorageRequest`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/key_readmission/runner.rs`. Enclosing match alternative: `Need::SecondSelection`.


<a id="cause-SigningEvidenceAbsent"></a>

### `SigningEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/key_readmission/runner.rs`.


<a id="cause-SigningReferencePreparationAbsent"></a>

### `SigningReferencePreparationAbsent`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::Evidence { report, read: signing, }`.


<a id="cause-SigningReferenceQuotaTransferred"></a>

### `SigningReferenceQuotaTransferred`


Local detection/handling phase and implementation owner:

- `Owner::advance` — `src/managed/key_readmission.rs`. Enclosing match alternative: `Phase::Evidence { report, read: signing, }`.


<a id="cause-UnselectedReferenceContent"></a>

### `UnselectedReferenceContent`


Local detection/handling phase and implementation owner:

- `ReferenceOwner::advance` — `src/reference_controls/resident.rs`. Enclosing match alternative: `Stage::NeedContent(observed)`.
