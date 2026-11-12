Cause contracts for `ObjectCreationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-KemCallAbsent"></a>

### `KemCallAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::take_kem` — `src/managed/mutations/create/resident.rs`.


<a id="cause-KemCompletionPhase"></a>

### `KemCompletionPhase`


Local detection/handling phase and implementation owner:

- `CreationOwner::kem_returned` — `src/managed/mutations/create/resident.rs`.


<a id="cause-KemCompletionUnknown"></a>

### `KemCompletionUnknown`


Local detection/handling phase and implementation owner:

No direct construction site is present in the current sources. This public
variant remains available; the common error contract still governs handling.


<a id="cause-KemDispatchPhase"></a>

### `KemDispatchPhase`


Local detection/handling phase and implementation owner:

- `CreationOwner::take_kem` — `src/managed/mutations/create/resident.rs`.


<a id="cause-KemNativeOutcomeAbsent"></a>

### `KemNativeOutcomeAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::begin_post` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `PostCreation::Derived(read)`.


<a id="cause-KemObservationStorageSize"></a>

### `KemObservationStorageSize`


Local detection/handling phase and implementation owner:

- `InitialKem::requested` — `src/managed/mutations/create/resident/kem.rs`.


<a id="cause-KemOutputEvidenceAbsent"></a>

### `KemOutputEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `KemContinuation<'a>::finish` — `src/managed/mutations/create/resident/kem.rs`.


<a id="cause-MlKemNativeCiphertextLength"></a>

### `MlKemNativeCiphertextLength`


Local detection/handling phase and implementation owner:

- `CreationOwner::kem_returned` — `src/managed/mutations/create/resident.rs`. Enclosing true branch: `completed.length != completed.expected_length`.
- `CreationOwner::begin_post` — `src/managed/mutations/create/resident.rs`. Enclosing true branch: `length != expected_length`.


<a id="cause-TlsOutputKind"></a>

### `TlsOutputKind`


Local detection/handling phase and implementation owner:

- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.


<a id="cause-AttributeMutationActivityChanged"></a>

### `AttributeMutationActivityChanged`


Local detection/handling phase and implementation owner:

- `prepare_attribute_mutation_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing true branch: `!Arc::ptr_eq(&tracked, identity.activity()?)`.


<a id="cause-AttributeMutationActivityChangedAfterReturn"></a>

### `AttributeMutationActivityChangedAfterReturn`


Local detection/handling phase and implementation owner:

- `PreparedAttributeMutation::finish` — `src/managed/mutations/origins.rs`. Enclosing true branch: `!Arc::ptr_eq(&activity, &self.activity)`.


<a id="cause-AttributeMutationActivityUnavailable"></a>

### `AttributeMutationActivityUnavailable`


Local detection/handling phase and implementation owner:

- `prepare_attribute_mutation_in` (module-level helper) — `src/managed/mutations/origins.rs`.


<a id="cause-AttributeMutationActivityUnavailableAfterReturn"></a>

### `AttributeMutationActivityUnavailableAfterReturn`


Local detection/handling phase and implementation owner:

- `PreparedAttributeMutation::finish` — `src/managed/mutations/origins.rs`.


<a id="cause-AttributeMutationCreatorChanged"></a>

### `AttributeMutationCreatorChanged`


Local detection/handling phase and implementation owner:

- `prepare_attribute_mutation_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), creator)`.


<a id="cause-AttributeMutationCreatorChangedAfterReturn"></a>

### `AttributeMutationCreatorChangedAfterReturn`


Local detection/handling phase and implementation owner:

- `PreparedAttributeMutation::finish` — `src/managed/mutations/origins.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), creator)`.


<a id="cause-AttributeMutationCreatorLostAfterReturn"></a>

### `AttributeMutationCreatorLostAfterReturn`


Local detection/handling phase and implementation owner:

- `PreparedAttributeMutation::finish` — `src/managed/mutations/origins.rs`. Enclosing true branch: `let PreparedRename::Known { inner, resource, creator, .. } = &self.rename`.


<a id="cause-AttributeMutationCreatorUnavailable"></a>

### `AttributeMutationCreatorUnavailable`


Local detection/handling phase and implementation owner:

- `prepare_attribute_mutation_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing match alternative: `(Some(destination), ObjectCreator::Known(creator))`.


<a id="cause-AttributeMutationDestinationReservation"></a>

### `AttributeMutationDestinationReservation`


Local detection/handling phase and implementation owner:

- `prepare_attribute_mutation_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing match alternative: `(Some(destination), ObjectCreator::Known(creator))`.


<a id="cause-AttributeMutationMetadataOwner"></a>

### `AttributeMutationMetadataOwner`


Local detection/handling phase and implementation owner:

- `prepare_attribute_mutation_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing true branch: `!Arc::ptr_eq(inner, &session.inner) || resource.session != session.uid || resource.slot != session.entry.slot || resource.generation != session.snapshot.generation`.


<a id="cause-AttributeMutationModuleReleased"></a>

### `AttributeMutationModuleReleased`


Local detection/handling phase and implementation owner:

- `PreparedAttributeMutation::finish` — `src/managed/mutations/origins.rs`.


<a id="cause-AttributeMutationPreparedOriginOwner"></a>

### `AttributeMutationPreparedOriginOwner`


Local detection/handling phase and implementation owner:

- `PreparedAttributeMutation::finish` — `src/managed/mutations/origins.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(inner, &self.inner) || *resource != self.resource`.


<a id="cause-ConflictingCreationClasses"></a>

### `ConflictingCreationClasses`


Local detection/handling phase and implementation owner:

- `object_class` (module-level helper) — `src/managed/mutations/create.rs`. Enclosing true branch: `selected.is_some_and(|previous| previous != class)`.


<a id="cause-CoordinationCopyAllocation"></a>

### `CoordinationCopyAllocation`


Local detection/handling phase and implementation owner:

- `CreationAllocation::allocate` — `src/managed/mutations/origins/preparation.rs`.
- `CreationAllocation::allocate` — `src/managed/mutations/origins/preparation.rs`.


<a id="cause-CopyDiagnosticsAbsent"></a>

### `CopyDiagnosticsAbsent`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`. Enclosing match alternative: `Call::Copy(call)`.


<a id="cause-CopySourceAbsent"></a>

### `CopySourceAbsent`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`. Enclosing true branch: `matches!(&call, Call::Copy(_))`.


<a id="cause-CreatedObjectAbsent"></a>

### `CreatedObjectAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::created` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `_`.
- `CreationOwner::advance` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `Phase::Class { read, .. }`.


<a id="cause-CreatedObjectHandles"></a>

### `CreatedObjectHandles`


Local detection/handling phase and implementation owner:

- `CreationTicket::register_handles` — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `!count_valid || handles .iter() .enumerate() .any(|(i, handle)| *handle == CK_INVALID_HANDLE || handles[..i].contains(handle))`.


<a id="cause-CreatedObjectRecordChanged"></a>

### `CreatedObjectRecordChanged`


Local detection/handling phase and implementation owner:

- `CreationTicket::register_handles` — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(&Arc::downgrade(&pending.creator), &self.creator) || pending.authentication != self.authentication`.


<a id="cause-CreatedObjectRecordMissing"></a>

### `CreatedObjectRecordMissing`


Local detection/handling phase and implementation owner:

- `CreationTicket::prepare_group` — `src/managed/mutations/origins/binding.rs`.
- `CreationTicket::register_handles` — `src/managed/mutations/origins/binding.rs`.
- `CreationTicket::register_handles` — `src/managed/mutations/origins/binding.rs`.


<a id="cause-CreatingSessionClosed"></a>

### `CreatingSessionClosed`


Local detection/handling phase and implementation owner:

- `check_creator` (module-level helper) — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `e.closed.load(Ordering::Acquire)`.


<a id="cause-CreatingSessionClosingOrUncertain"></a>

### `CreatingSessionClosingOrUncertain`


Local detection/handling phase and implementation owner:

- `check_creator` (module-level helper) — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `e.close_attempted.load(Ordering::Acquire)`.


<a id="cause-CreatingSessionReleased"></a>

### `CreatingSessionReleased`


Local detection/handling phase and implementation owner:

- `check_creator` (module-level helper) — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `let ObjectCreator::Known(creator) = creator`.


<a id="cause-CreationActivityAllocation"></a>

### `CreationActivityAllocation`


Local detection/handling phase and implementation owner:

- `CreationAllocation::allocate` — `src/managed/mutations/origins/preparation.rs`.
- `CreationAllocation::allocate` — `src/managed/mutations/origins/preparation.rs`.


<a id="cause-CreationAdmissionPhase"></a>

### `CreationAdmissionPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationAdmissionPreparationAbsent"></a>

### `CreationAdmissionPreparationAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::admit` — `src/managed/mutations/create/resident.rs`.


<a id="cause-CreationAggregateAccounting"></a>

### `CreationAggregateAccounting`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`.
- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`. Enclosing true branch: `actual > admitted`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`. Enclosing true branch: `actual > admitted`.
- `Session::create_content` — `src/managed/mutations/storage.rs`.
- `Session::create_content` — `src/managed/mutations/storage.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-CreationCandidateKind"></a>

### `CreationCandidateKind`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationClassAbiRepresentation"></a>

### `CreationClassAbiRepresentation`


Local detection/handling phase and implementation owner:

- `object_class` (module-level helper) — `src/managed/mutations/create.rs`.


<a id="cause-CreationClassIsRequired"></a>

### `CreationClassIsRequired`


Local detection/handling phase and implementation owner:

- `object_class` (module-level helper) — `src/managed/mutations/create.rs`.


<a id="cause-CreationCleanupSize"></a>

### `CreationCleanupSize`


Local detection/handling phase and implementation owner:

- `Initial::requested` — `src/managed/mutations/create/resident.rs`.
- `Initial::allocated_bytes` — `src/managed/mutations/create/resident.rs`.


<a id="cause-CreationCompletionPhase"></a>

### `CreationCompletionPhase`


Local detection/handling phase and implementation owner:

- `CreationOwner::advance` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationContinuationChanged"></a>

### `CreationContinuationChanged`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-CreationDestination"></a>

### `CreationDestination`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_creation_before_access` — `src/managed/mutations/origins/preparation.rs`. Enclosing match alternative: `Some(recipe)`.
- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`. Enclosing true branch: `keys.len() > storage.keys.capacity() || keys.len() > storage.activities.capacity() || keys.len() > storage.selected.capacity() || keys.len() > storage.resources.len()`.
- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`.
- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`. Enclosing true branch: `position >= self.activities.len()`.


<a id="cause-CreationDestinationPhase"></a>

### `CreationDestinationPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationDiagnosticAbsent"></a>

### `CreationDiagnosticAbsent`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`. Enclosing match alternative: `Call::Create(call)`.
- `CreationOwner::advance` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `Phase::Destination(read)`.


<a id="cause-CreationMetadataPhase"></a>

### `CreationMetadataPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-CreationMetadataStorageAccounting"></a>

### `CreationMetadataStorageAccounting`


Local detection/handling phase and implementation owner:

- `CreationAllocation::bytes` — `src/managed/mutations/origins/preparation.rs`.
- `CreationAllocation::bytes` — `src/managed/mutations/origins/preparation.rs`.
- `CreationAllocation::bind` — `src/managed/mutations/origins/preparation.rs`.
- `creation_metadata_bytes` (module-level helper) — `src/managed/mutations/origins.rs`.


<a id="cause-CreationNativeLifetimeAbsent"></a>

### `CreationNativeLifetimeAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::admit` — `src/managed/mutations/create/resident.rs`.


<a id="cause-CreationOriginUnavailableForCleanup"></a>

### `CreationOriginUnavailableForCleanup`


Local detection/handling phase and implementation owner:

- `check_creation_for_cleanup` (module-level helper) — `src/managed/mutations/origins/binding.rs`.


<a id="cause-CreationOwnerAbsent"></a>

### `CreationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`.
- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing true branch: `need == Need::Kem`.
- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing true branch: `need == Need::Unwrap`.
- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`.
- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`. Enclosing true branch: `published`.


<a id="cause-CreationOwnerChangedBeforeCleanup"></a>

### `CreationOwnerChangedBeforeCleanup`


Local detection/handling phase and implementation owner:

- `check_creation_for_cleanup` (module-level helper) — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `creation.session != session.uid`.


<a id="cause-CreationOwnerUnavailable"></a>

### `CreationOwnerUnavailable`


Local detection/handling phase and implementation owner:

- `CreationTicket::release_uncreated` — `src/managed/mutations/origins/binding.rs`.
- `CreationTicket::destroyed` — `src/managed/mutations/origins/binding.rs`.
- `CreationTicket::prepare_group` — `src/managed/mutations/origins/binding.rs`.
- `CreationTicket::register_handles` — `src/managed/mutations/origins/binding.rs`.
- `PendingSlots::limit` — `src/managed/mutations/origins.rs`.
- `PreparedCreation::begin` — `src/managed/mutations/origins.rs`.


<a id="cause-CreationPossessionAbsent"></a>

### `CreationPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`.


<a id="cause-CreationPreparationAlreadyConsumed"></a>

### `CreationPreparationAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`.
- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`. Enclosing match alternative: `CreationPreparation::Ticket(prepared)`.


<a id="cause-CreationPublicationAccounting"></a>

### `CreationPublicationAccounting`


Local detection/handling phase and implementation owner:

- `PublicationSlots::consume` — `src/managed/mutations/origins/capacity.rs`.


<a id="cause-CreationPublicationCapacity"></a>

### `CreationPublicationCapacity`


Local detection/handling phase and implementation owner:

- `PublicationSlots::new` — `src/managed/mutations/origins/capacity.rs`.


<a id="cause-CreationPublicationCapacityChanged"></a>

### `CreationPublicationCapacityChanged`


Local detection/handling phase and implementation owner:

- `PublicationSlots::check` — `src/managed/mutations/origins/capacity.rs`. Enclosing true branch: `count > self.remaining.load(Ordering::Relaxed) || count > catalog.publication_reserved || catalog .origins .capacity() .saturating_sub(catalog.origins.len()) < count || catalog .resource_activities .capacity() .saturating_sub(catalog.resource_activities.len()) < count`.


<a id="cause-CreationPublicationQuotaAbsent"></a>

### `CreationPublicationQuotaAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::publish_native_object` — `src/managed/mutations/create/resident.rs`.


<a id="cause-CreationPublicationQuotaTransferred"></a>

### `CreationPublicationQuotaTransferred`


Local detection/handling phase and implementation owner:

- `CreationOwner::admit` — `src/managed/mutations/create/resident.rs`.


<a id="cause-CreationPublicationSlotExhausted"></a>

### `CreationPublicationSlotExhausted`


Local detection/handling phase and implementation owner:

- `PublicationSlots::consume` — `src/managed/mutations/origins/capacity.rs`.


<a id="cause-CreationRecordChanged"></a>

### `CreationRecordChanged`


Local detection/handling phase and implementation owner:

- `CreationTicket::release_uncreated` — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), &self.creator) || origin.authentication != self.authentication || !catalog.occupied.contains(key)`.


<a id="cause-CreationRecordMissing"></a>

### `CreationRecordMissing`


Local detection/handling phase and implementation owner:

- `CreationTicket::release_uncreated` — `src/managed/mutations/origins/binding.rs`.


<a id="cause-CreationResourceNeedAbsent"></a>

### `CreationResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `run_with_native` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`.


<a id="cause-CreationSessionReleased"></a>

### `CreationSessionReleased`


Local detection/handling phase and implementation owner:

- `CreationTicket::creator` — `src/managed/mutations/origins/binding.rs`.


<a id="cause-CreationStorageSize"></a>

### `CreationStorageSize`


Local detection/handling phase and implementation owner:

- `Initial::fixed_bytes` — `src/managed/mutations/create/resident.rs`.
- `Initial::requested` — `src/managed/mutations/create/resident.rs`.
- `Initial::requested` — `src/managed/mutations/create/resident.rs`. Enclosing true branch: `post_class`.
- `Initial::allocated_bytes` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `PostCreation::Public { read, publication }`.
- `Initial::allocated_bytes` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `PostCreation::Private { read, public, .. }`.
- `Initial::allocated_bytes` — `src/managed/mutations/create/resident.rs`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`.
- `create` (module-level helper) — `src/managed/mutations/create/resident/typed.rs`.


<a id="cause-ForeignCreationReservation"></a>

### `ForeignCreationReservation`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.inner) || keys.is_empty() || keys.iter().any(|key| !self.keys.contains(key))`.
- `Reservation::prepare_selected_creation` — `src/managed/mutations/origins/preparation.rs`. Enclosing true branch: `ticket.keys != keys || !ticket.creator.ptr_eq(&Arc::downgrade(&session.entry))`.


<a id="cause-ForeignForgottenResource"></a>

### `ForeignForgottenResource`


Local detection/handling phase and implementation owner:

- `forget_object_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing true branch: `!Arc::ptr_eq(inner, &session.inner) || resource.session != session.uid || resource.slot != session.entry.slot || resource.generation != session.snapshot.generation`.


<a id="cause-GeneratedObjectAbsent"></a>

### `GeneratedObjectAbsent`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`.


<a id="cause-GeneratedOutputKind"></a>

### `GeneratedOutputKind`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`.


<a id="cause-GeneratedPrivateObjectAbsent"></a>

### `GeneratedPrivateObjectAbsent`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.


<a id="cause-GeneratedPublicObjectAbsent"></a>

### `GeneratedPublicObjectAbsent`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.


<a id="cause-GroupCreationScope"></a>

### `GroupCreationScope`


Local detection/handling phase and implementation owner:

- `CreationTicket::prepare_group` — `src/managed/mutations/origins/binding.rs`. Enclosing true branch: `self.keys.len() != 1 || self.group_resources.len() != capacity`.


<a id="cause-KeyGenerationStorageAccounting"></a>

### `KeyGenerationStorageAccounting`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`.
- `Session::generate_native_key_selected` — `src/managed/mutations/generation.rs`.


<a id="cause-KeyMaterialObservationLayout"></a>

### `KeyMaterialObservationLayout`


Local detection/handling phase and implementation owner:

- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`. Enclosing true branch: `observations.as_slice().len() != count`.


<a id="cause-KeyMaterialRequestAccounting"></a>

### `KeyMaterialRequestAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-KeyMaterialResultAccounting"></a>

### `KeyMaterialResultAccounting`


Local detection/handling phase and implementation owner:

- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.
- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.


<a id="cause-KeyMaterialResultAllocation"></a>

### `KeyMaterialResultAllocation`


Local detection/handling phase and implementation owner:

- `Session::derive_tls_key_material_selected` — `src/managed/mutations/key_material.rs`.


<a id="cause-KeyPairGenerationStorageAccounting"></a>

### `KeyPairGenerationStorageAccounting`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.
- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.


<a id="cause-LogoutAliasSnapshotAllocation"></a>

### `LogoutAliasSnapshotAllocation`


Local detection/handling phase and implementation owner:

- `forget_private_origins` (module-level helper) — `src/managed/mutations/origins/binding.rs`.


<a id="cause-LogoutAliasSnapshotSize"></a>

### `LogoutAliasSnapshotSize`


Local detection/handling phase and implementation owner:

- `forget_private_origins` (module-level helper) — `src/managed/mutations/origins/binding.rs`.


<a id="cause-MutationModuleReleased"></a>

### `MutationModuleReleased`


Local detection/handling phase and implementation owner:

- `DurableReservation::forget_object` — `src/managed/mutations/origins.rs`.
- `DurableReservation::prepare_attribute_mutation` — `src/managed/mutations/origins.rs`.
- `DurableReservation::prepare_rename` — `src/managed/mutations/origins.rs`.


<a id="cause-NativeCreationAggregateAccounting"></a>

### `NativeCreationAggregateAccounting`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`.
- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-NativeCreationStorageAccounting"></a>

### `NativeCreationStorageAccounting`


Local detection/handling phase and implementation owner:

- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`.
- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`.
- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`.
- `execute` (module-level helper) — `src/managed/mutations/native_object.rs`.


<a id="cause-ObjectAlreadyCreated"></a>

### `ObjectAlreadyCreated`


Local detection/handling phase and implementation owner:

- `CreationOwner::advance` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `Phase::Destination(read)`.


<a id="cause-ObjectCreationIncomplete"></a>

### `ObjectCreationIncomplete`


Local detection/handling phase and implementation owner:

- `CreationOwner::result` — `src/managed/mutations/create/resident.rs`.


<a id="cause-ObjectCreationStopped"></a>

### `ObjectCreationStopped`


Local detection/handling phase and implementation owner:

- `CreationOwner::advance` — `src/managed/mutations/create/resident.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-ObjectCreatorAllocation"></a>

### `ObjectCreatorAllocation`


Local detection/handling phase and implementation owner:

- `PublicationSlots::new` — `src/managed/mutations/origins/capacity.rs`.
- `PendingSlots::limit` — `src/managed/mutations/origins.rs`.
- `PendingSlots::limit` — `src/managed/mutations/origins.rs`.
- `PendingSlots::new` — `src/managed/mutations/origins.rs`.
- `PendingSlots::new` — `src/managed/mutations/origins.rs`.
- `PreparedCreation::begin` — `src/managed/mutations/origins.rs`. Enclosing true branch: `slots.remaining != ticket.keys.len() || catalog.pending_reserved < slots.remaining || catalog .pending_creations .capacity() .saturating_sub(catalog.pending_creations.len()) < slots.remaining`.


<a id="cause-ObjectCreatorAlreadyRecorded"></a>

### `ObjectCreatorAlreadyRecorded`


Local detection/handling phase and implementation owner:

- `PreparedCreation::begin` — `src/managed/mutations/origins.rs`.
- `PreparedCreation::begin` — `src/managed/mutations/origins.rs`. Enclosing true branch: `ticket.keys.iter().any(|key| { catalog.pending_creations.contains_key(key) || !catalog.occupied.contains(key) })`.


<a id="cause-PairAuxiliaryOutputOwner"></a>

### `PairAuxiliaryOutputOwner`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`.


<a id="cause-PairParameterPreparationChanged"></a>

### `PairParameterPreparationChanged`


Local detection/handling phase and implementation owner:

- `Session::generate_native_key_pair_owned` — `src/managed/mutations/generation.rs`. Enclosing match alternative: `_`.


<a id="cause-PrivateCreationObservationStorageSize"></a>

### `PrivateCreationObservationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/mutations/create/resident/private.rs`.


<a id="cause-PrivateImportEvidenceAbsent"></a>

### `PrivateImportEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `PreparedPrivateCreation<'a>::finish` — `src/managed/mutations/create/resident/private.rs`.


<a id="cause-PrivateObservationStorageSize"></a>

### `PrivateObservationStorageSize`


Local detection/handling phase and implementation owner:

- `containing_bytes` (module-level helper) — `src/managed/mutations/create/resident/private/observation.rs`.


<a id="cause-PublicDerPublicationPairing"></a>

### `PublicDerPublicationPairing`


Local detection/handling phase and implementation owner:

- `create_public_with_publication` (module-level helper) — `src/managed/mutations/create/resident/public.rs`. Enclosing match alternative: `_`.


<a id="cause-PublicCreationStorageSize"></a>

### `PublicCreationStorageSize`


Local detection/handling phase and implementation owner:

- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`.
- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`.


<a id="cause-PublicImportMechanismReportAbsent"></a>

### `PublicImportMechanismReportAbsent`


Local detection/handling phase and implementation owner:

- `create_public_prepared` (module-level helper) — `src/managed/mutations/create/resident/public.rs`.


<a id="cause-RenameCreatorChanged"></a>

### `RenameCreatorChanged`


Local detection/handling phase and implementation owner:

- `PreparedRename::finish` — `src/managed/mutations/origins.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), &creator)`.
- `prepare_rename_in` (module-level helper) — `src/managed/mutations/origins.rs`. Enclosing true branch: `!std::sync::Weak::ptr_eq(&Arc::downgrade(&origin.creator), creator)`.


<a id="cause-RenameCreatorUnavailable"></a>

### `RenameCreatorUnavailable`


Local detection/handling phase and implementation owner:

- `PreparedRename::finish` — `src/managed/mutations/origins.rs`.
- `prepare_rename_in` (module-level helper) — `src/managed/mutations/origins.rs`.


<a id="cause-RenameDestinationReservation"></a>

### `RenameDestinationReservation`


Local detection/handling phase and implementation owner:

- `prepare_rename_in` (module-level helper) — `src/managed/mutations/origins.rs`.


<a id="cause-RenameModuleReleased"></a>

### `RenameModuleReleased`


Local detection/handling phase and implementation owner:

- `PreparedRename::finish` — `src/managed/mutations/origins.rs`.


<a id="cause-RestorationEvidenceAbsent"></a>

### `RestorationEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `Restoration<'a>::finish` — `src/managed/mutations/create/resident/restoration.rs`.


<a id="cause-RestorationObservationStorageSize"></a>

### `RestorationObservationStorageSize`


Local detection/handling phase and implementation owner:

- `InitialRestoration::requested` — `src/managed/mutations/create/resident/restoration.rs`.
- `InitialRestoration::allocated_bytes` — `src/managed/mutations/create/resident/restoration.rs`.


<a id="cause-SigningImportEvidenceAbsent"></a>

### `SigningImportEvidenceAbsent`


Local detection/handling phase and implementation owner:

- `PreparedPrivateCreation<'a>::finish_signing` — `src/managed/mutations/create/resident/private.rs`.


<a id="cause-UnexpectedKemUnwrap"></a>

### `UnexpectedKemUnwrap`


Local detection/handling phase and implementation owner:

- `KemContinuation<'a>::finish` — `src/managed/mutations/create/resident/kem.rs`.


<a id="cause-UnexpectedNativeKem"></a>

### `UnexpectedNativeKem`


Local detection/handling phase and implementation owner:

- `run_with_effect` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`.


<a id="cause-UnexpectedNativeUnwrap"></a>

### `UnexpectedNativeUnwrap`


Local detection/handling phase and implementation owner:

- `run_with_effect` (module-level helper) — `src/managed/mutations/create/resident/runner.rs`.


<a id="cause-UnexpectedRestorationKem"></a>

### `UnexpectedRestorationKem`


Local detection/handling phase and implementation owner:

- `Restoration<'a>::finish` — `src/managed/mutations/create/resident/restoration.rs`.


<a id="cause-UnexpectedSigningEvidence"></a>

### `UnexpectedSigningEvidence`


Local detection/handling phase and implementation owner:

- `PreparedPrivateCreation<'a>::finish` — `src/managed/mutations/create/resident/private.rs`.


<a id="cause-UnwrapCallAbsent"></a>

### `UnwrapCallAbsent`


Local detection/handling phase and implementation owner:

- `CreationOwner::take_unwrap` — `src/managed/mutations/create/resident.rs`.


<a id="cause-UnwrapCompletionPhase"></a>

### `UnwrapCompletionPhase`


Local detection/handling phase and implementation owner:

- `CreationOwner::unwrap_returned` — `src/managed/mutations/create/resident.rs`.


<a id="cause-UnwrapCompletionUnknown"></a>

### `UnwrapCompletionUnknown`


Local detection/handling phase and implementation owner:

No direct construction site is present in the current sources. This public
variant remains available; the common error contract still governs handling.


<a id="cause-UnwrapDispatchPhase"></a>

### `UnwrapDispatchPhase`


Local detection/handling phase and implementation owner:

- `CreationOwner::take_unwrap` — `src/managed/mutations/create/resident.rs`.

