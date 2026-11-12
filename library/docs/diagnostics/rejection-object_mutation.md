Cause contracts for `ObjectMutationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CSetAttributeValueUnavailable"></a>

### `CSetAttributeValueUnavailable`


Local detection/handling phase and implementation owner:

- `call_set` (module-level helper) — `src/managed/mutations/generic.rs`.
- `Session::set_attributes` — `src/managed/mutations/generic.rs`. Enclosing true branch: `state.native.table.C_SetAttributeValue.is_none()`.
- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.


<a id="cause-AttributeMutationAlreadyDispatched"></a>

### `AttributeMutationAlreadyDispatched`


Local detection/handling phase and implementation owner:

- `SetAttributesOwner::dispatch` — `src/managed/mutations/generic/resident.rs`.


<a id="cause-AttributeMutationCandidateKind"></a>

### `AttributeMutationCandidateKind`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeMutationCompletionPhase"></a>

### `AttributeMutationCompletionPhase`


Local detection/handling phase and implementation owner:

- `SetAttributesOwner::advance` — `src/managed/mutations/generic/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeMutationContinuationChanged"></a>

### `AttributeMutationContinuationChanged`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-AttributeMutationIncomplete"></a>

### `AttributeMutationIncomplete`


Local detection/handling phase and implementation owner:

- `SetAttributesOwner::result` — `src/managed/mutations/generic/resident.rs`.


<a id="cause-AttributeMutationInputChanged"></a>

### `AttributeMutationInputChanged`


Local detection/handling phase and implementation owner:

- `Session::set_attributes` — `src/managed/mutations/generic.rs`. Enclosing true branch: `returned.inputs_changed()`.
- `Session::set_attributes` — `src/managed/mutations/generic.rs`. Enclosing true branch: `returned.inputs_changed()`.
- `Session::set_native_attributes` — `src/managed/mutations/generic.rs`. Enclosing true branch: `returned.inputs_changed()`.
- `Session::set_native_attributes` — `src/managed/mutations/generic.rs`. Enclosing true branch: `returned.inputs_changed()`.
- `LabelOwner::dispatch` — `src/managed/mutations/label.rs`. Enclosing true branch: `returned.inputs_changed()`.
- `SetAttributesOwner::dispatch` — `src/managed/mutations/generic/resident.rs`. Enclosing true branch: `returned.inputs_changed()`.


<a id="cause-AttributeMutationOwnerAbsent"></a>

### `AttributeMutationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.


<a id="cause-AttributeMutationPossessionAbsent"></a>

### `AttributeMutationPossessionAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.


<a id="cause-AttributeMutationPreparationAccounting"></a>

### `AttributeMutationPreparationAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/mutations/generic/preparation.rs`.
- `prepare` (module-level helper) — `src/managed/mutations/generic/preparation.rs`.
- `prepare` (module-level helper) — `src/managed/mutations/generic/preparation.rs`.
- `prepare` (module-level helper) — `src/managed/mutations/generic/preparation.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-AttributeMutationResourceNeedAbsent"></a>

### `AttributeMutationResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.


<a id="cause-AttributeMutationStopped"></a>

### `AttributeMutationStopped`


Local detection/handling phase and implementation owner:

- `SetAttributesOwner::advance` — `src/managed/mutations/generic/resident.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-AttributeMutationStorageSize"></a>

### `AttributeMutationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`.


<a id="cause-CertificateDer"></a>

### `CertificateDer`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`.


<a id="cause-CertificateCategoryNativeWidth"></a>

### `CertificateCategoryNativeWidth`


Local detection/handling phase and implementation owner:

- `Session::create_certificate` — `src/managed/mutations/storage.rs`.


<a id="cause-CertificateEncoding"></a>

### `CertificateEncoding`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`.


<a id="cause-CertificateSize"></a>

### `CertificateSize`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`. Enclosing true branch: `der.is_empty()`.


<a id="cause-ContentClassAbsent"></a>

### `ContentClassAbsent`


Local detection/handling phase and implementation owner:

- `Session::create_content` — `src/managed/mutations/storage.rs`.


<a id="cause-ContentCreationStorageSize"></a>

### `ContentCreationStorageSize`


Local detection/handling phase and implementation owner:

- `Session::create_content` — `src/managed/mutations/storage.rs`.
- `Session::create_content` — `src/managed/mutations/storage.rs`.
- `Session::create_content` — `src/managed/mutations/storage.rs`.


<a id="cause-DataTypeOid"></a>

### `DataTypeOid`


Local detection/handling phase and implementation owner:

- `type_oid` (module-level helper) — `src/managed/mutations/storage.rs`. Enclosing true branch: `!der.is_empty()`.


<a id="cause-DataTypeOidEncoding"></a>

### `DataTypeOidEncoding`


Local detection/handling phase and implementation owner:

- `type_oid` (module-level helper) — `src/managed/mutations/storage.rs`. Enclosing true branch: `!der.is_empty()`.


<a id="cause-DestinationAllocation"></a>

### `DestinationAllocation`


Local detection/handling phase and implementation owner:

- `CloseReservation::reserve_catalog` — `src/managed/mutations/closing.rs`.
- `Catalog::reserve_admitted_owners` — `src/managed/mutations/inventory.rs`.


<a id="cause-DestinationClassExceedsNativeWidth"></a>

### `DestinationClassExceedsNativeWidth`


Local detection/handling phase and implementation owner:

- `DestinationRecipe<'a>::with_parts` — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-DestinationClassTupleShape"></a>

### `DestinationClassTupleShape`


Local detection/handling phase and implementation owner:

- `DestinationRecipe<'a>::new` — `src/managed/mutations/reservation_preparation.rs`. Enclosing true branch: `parts.len() != expected`.


<a id="cause-DestinationCount"></a>

### `DestinationCount`


Local detection/handling phase and implementation owner:

- `Catalog::check_admitted_owners` — `src/managed/mutations/inventory.rs`.
- `Catalog::check_admitted_owners` — `src/managed/mutations/inventory.rs`.


<a id="cause-DestinationOutsideReservation"></a>

### `DestinationOutsideReservation`


Local detection/handling phase and implementation owner:

- `Reservation::destination` — `src/managed/mutations/reservation.rs`.


<a id="cause-DestinationPreparationAllocation"></a>

### `DestinationPreparationAllocation`


Local detection/handling phase and implementation owner:

- `DestinationAllocation<'a>::allocate` — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-DestinationProbeAlreadyConsumed"></a>

### `DestinationProbeAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_with_native_roles_prepaid` — `src/managed/mutations/possession/prepaid.rs`.


<a id="cause-DestinationQuotaExceeded"></a>

### `DestinationQuotaExceeded`


Local detection/handling phase and implementation owner:

- `Catalog::check_admitted_owners` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `!cleanup && self .maximum_destinations .is_some_and(|maximum| count > maximum)`.


<a id="cause-DuplicateSelection"></a>

### `DuplicateSelection`


Local detection/handling phase and implementation owner:

- `Catalog::begin_select` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `keys[..i].contains(k)`.


<a id="cause-DynamicReaderAggregateAccounting"></a>

### `DynamicReaderAggregateAccounting`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_with_readers_prepaid` — `src/managed/mutations/possession/readers.rs`.


<a id="cause-ForeignInventoryPreparation"></a>

### `ForeignInventoryPreparation`


Local detection/handling phase and implementation owner:

- `PreparedInventory::publish_retained` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `!owner.inner.ptr_eq(&Arc::downgrade(&session.inner)) || owner.key != (session.entry.slot, session.snapshot.generation) || owner.session != session.uid`.


<a id="cause-ForeignOperationDestination"></a>

### `ForeignOperationDestination`


Local detection/handling phase and implementation owner:

- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `*owner != uid`.


<a id="cause-ForeignOperationReservation"></a>

### `ForeignOperationReservation`


Local detection/handling phase and implementation owner:

- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, inner) || self .keys .iter() .any(|key| key.slot != entry.slot || key.generation != entry.generation)`.
- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `candidate.keys != self.keys || candidate.activities.len() != self.activities.len() || !candidate .activities .iter() .zip(&self.activities) .all(|(prepared, source)| Arc::ptr_eq(prepared, source))`.
- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `candidate.writers.len() != self.activities.len() || !candidate .writers .iter() .zip(&self.activities) .all(|(writer, activity)| writer.owns_activity(activity))`.
- `Reservation::check_operation_session` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, &session.inner) || self.keys.iter().any(|k| { k.slot != session.entry.slot || k.generation != session.snapshot.generation })`.
- `Reservation::transfer_to_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `objects.len() != self.activities.len() || !objects .iter() .zip(&self.activities) .all(|(permit, activity)| permit.owns_activity(activity))`.


<a id="cause-ForeignOperationSelection"></a>

### `ForeignOperationSelection`


Local detection/handling phase and implementation owner:

- `SelectionGuard::into_owned_retained` — `src/managed/mutations.rs`. Enclosing true branch: `!Arc::ptr_eq(&self.inner, inner) || self.session != entry.credit.uid()`.


<a id="cause-ForeignPreparedSelection"></a>

### `ForeignPreparedSelection`


Local detection/handling phase and implementation owner:

- `PreparedManagedSelection::select_retained` — `src/managed/mutations.rs`. Enclosing true branch: `self.keys.iter().any(|key| { key.slot != session.entry.slot || key.generation != session.snapshot.generation })`.


<a id="cause-GenerationCoordinationAccounting"></a>

### `GenerationCoordinationAccounting`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_source_plan_prepaid` — `src/managed/mutations/possession/generation.rs`.
- `Reservation::prepare_source_plan_prepaid` — `src/managed/mutations/possession/generation.rs`.


<a id="cause-GenerationDestinationAccounting"></a>

### `GenerationDestinationAccounting`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_source_plan_prepaid` — `src/managed/mutations/possession/generation.rs`.


<a id="cause-GenerationProbeAlreadyConsumed"></a>

### `GenerationProbeAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Reservation::prepare_source_plan_prepaid` — `src/managed/mutations/possession/generation.rs`.


<a id="cause-InvalidResourceActivityHandle"></a>

### `InvalidResourceActivityHandle`


Local detection/handling phase and implementation owner:

- `object_activity` (module-level helper) — `src/managed/mutations.rs`. Enclosing true branch: `handle == CK_INVALID_HANDLE`.


<a id="cause-InventoryAllocation"></a>

### `InventoryAllocation`


Local detection/handling phase and implementation owner:

- `Catalog::begin_scan` — `src/managed/mutations/inventory.rs`.


<a id="cause-InventoryCount"></a>

### `InventoryCount`


Local detection/handling phase and implementation owner:

- `Catalog::begin_scan` — `src/managed/mutations/inventory.rs`.


<a id="cause-InventoryOwnerAllocation"></a>

### `InventoryOwnerAllocation`


Local detection/handling phase and implementation owner:

- `PreparedInventory::publish_retained` — `src/managed/mutations/inventory.rs`.


<a id="cause-InventoryOwnerSize"></a>

### `InventoryOwnerSize`


Local detection/handling phase and implementation owner:

- `PreparedInventory::allocation_bytes` — `src/managed/mutations/inventory.rs`.


<a id="cause-InventoryPreparationAlreadyPublished"></a>

### `InventoryPreparationAlreadyPublished`


Local detection/handling phase and implementation owner:

- `PreparedInventory::publish_retained` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `prepared.registered`.


<a id="cause-InventoryPreparationAlreadyShared"></a>

### `InventoryPreparationAlreadyShared`


Local detection/handling phase and implementation owner:

- `PreparedInventory::publish_retained` — `src/managed/mutations/inventory.rs`.


<a id="cause-IssuerEncoding"></a>

### `IssuerEncoding`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`.


<a id="cause-KeySelectionClass"></a>

### `KeySelectionClass`


Local detection/handling phase and implementation owner:

- `ManagedSelectionStorage<'a>::allocate_key` — `src/managed/mutations.rs`. Enclosing true branch: `!matches!( class, ManagedClass::PublicKey | ManagedClass::PrivateKey | ManagedClass::SecretKey )`.


<a id="cause-LabelAdmissionPhase"></a>

### `LabelAdmissionPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-LabelAdmissionPreparationAbsent"></a>

### `LabelAdmissionPreparationAbsent`


Local detection/handling phase and implementation owner:

- `LabelOwner::admit` — `src/managed/mutations/label.rs`.


<a id="cause-LabelAlreadyDispatched"></a>

### `LabelAlreadyDispatched`


Local detection/handling phase and implementation owner:

- `LabelOwner::dispatch` — `src/managed/mutations/label.rs`.


<a id="cause-LabelCandidateKind"></a>

### `LabelCandidateKind`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-LabelClassPreparationAbsent"></a>

### `LabelClassPreparationAbsent`


Local detection/handling phase and implementation owner:

- `LabelOwner::dispatch` — `src/managed/mutations/label.rs`.


<a id="cause-LabelContinuationChanged"></a>

### `LabelContinuationChanged`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing true branch: `owner.need()? != Some(need)`.


<a id="cause-LabelDestinationPhase"></a>

### `LabelDestinationPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-LabelDestinationPreparationAbsent"></a>

### `LabelDestinationPreparationAbsent`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `(Need::StartDestination, Candidate::StartDestination)`.


<a id="cause-LabelMetadataPhase"></a>

### `LabelMetadataPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-LabelMutationCompletionPhase"></a>

### `LabelMutationCompletionPhase`


Local detection/handling phase and implementation owner:

- `LabelOwner::advance` — `src/managed/mutations/label.rs`. Enclosing match alternative: `_`.


<a id="cause-LabelMutationIncomplete"></a>

### `LabelMutationIncomplete`


Local detection/handling phase and implementation owner:

- `LabelOwner::result` — `src/managed/mutations/label.rs`.


<a id="cause-LabelMutationStopped"></a>

### `LabelMutationStopped`


Local detection/handling phase and implementation owner:

- `LabelOwner::advance` — `src/managed/mutations/label.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-LabelMutationStorageSize"></a>

### `LabelMutationStorageSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/mutations/label/runner.rs`.


<a id="cause-LabelOwnerAbsent"></a>

### `LabelOwnerAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.
- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.


<a id="cause-LabelPossessionAbsent"></a>

### `LabelPossessionAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.


<a id="cause-LabelPublicationQuotaTransferred"></a>

### `LabelPublicationQuotaTransferred`


Local detection/handling phase and implementation owner:

- `LabelOwner::admit` — `src/managed/mutations/label.rs`.


<a id="cause-LabelReferencePhase"></a>

### `LabelReferencePhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-LabelResourceNeedAbsent"></a>

### `LabelResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`.


<a id="cause-ManagedSelectionAllocation"></a>

### `ManagedSelectionAllocation`


Local detection/handling phase and implementation owner:

- `ManagedSelectionStorage<'a>::bind` — `src/managed/mutations.rs`.


<a id="cause-MutationContentPhase"></a>

### `MutationContentPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-MutationDestinationPhase"></a>

### `MutationDestinationPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-MutationFingerprintPhase"></a>

### `MutationFingerprintPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-MutationFingerprintSelection"></a>

### `MutationFingerprintSelection`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `Need::Fingerprint(need)`.


<a id="cause-MutationMetadataPhase"></a>

### `MutationMetadataPhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-MutationObservationFieldCount"></a>

### `MutationObservationFieldCount`


Local detection/handling phase and implementation owner:

- `MutationObservationPlan::observed_values` — `src/mutation_controls.rs`. Enclosing true branch: `values.len() != self.attributes.len()`.


<a id="cause-MutationObservationRequiresPreparedOwner"></a>

### `MutationObservationRequiresPreparedOwner`


Local detection/handling phase and implementation owner:

- `snapshot` (module-level helper) — `src/mutation_controls.rs`. Enclosing true branch: `!plan.attributes.is_empty()`.


<a id="cause-MutationOwnerAbsent"></a>

### `MutationOwnerAbsent`


Local detection/handling phase and implementation owner:

- `set` (module-level helper) — `src/managed/mutations/label/runner.rs`. Enclosing true branch: `matches!(need, Need::StartDestination)`.
- `set` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing true branch: `matches!(need, Need::StartReference)`.


<a id="cause-MutationReferencePhase"></a>

### `MutationReferencePhase`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-MutationSourcePreparationAbsent"></a>

### `MutationSourcePreparationAbsent`


Local detection/handling phase and implementation owner:

- `attach` (module-level helper) — `src/managed/mutations/generic/resident/runner.rs`. Enclosing match alternative: `(Need::StartReference, Candidate::StartReference)`.


<a id="cause-NoncanonicalCertificate"></a>

### `NoncanonicalCertificate`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`. Enclosing true branch: `certificate.to_der().map_err(|_| { Error::Rejected(crate::RejectionReason::ObjectMutation( crate::ObjectMutationRejection::CertificateEncoding, )) })? != der`.


<a id="cause-NoncanonicalDataType"></a>

### `NoncanonicalDataType`


Local detection/handling phase and implementation owner:

- `type_oid` (module-level helper) — `src/managed/mutations/storage.rs`. Enclosing true branch: `oid.to_der().map_err(|_| { Error::Rejected(crate::RejectionReason::ObjectMutation( crate::ObjectMutationRejection::DataTypeOidEncoding, )) })? != der`.


<a id="cause-ObjectDestinationReserved"></a>

### `ObjectDestinationReserved`


Local detection/handling phase and implementation owner:

- `Catalog::check_admitted_owners` — `src/managed/mutations/inventory.rs`. Enclosing true branch: `keys.clone().enumerate().any(|(i, key)| { self.occupied.iter().any(|occupied| key.overlaps(occupied)) || keys.clone().take(i).any(|prior| prior == key) })`.
- `prepare_grouped` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`. Enclosing true branch: `recipes.iter().enumerate().any(|(index, recipe)| { recipes[..index].iter().any(|previous| { previous.head() == recipe.head() && previous.operands() == recipe.operands() }) })`.


<a id="cause-OperationActivityAllocation"></a>

### `OperationActivityAllocation`


Local detection/handling phase and implementation owner:

- `Reservation::allocate_retention` — `src/managed/mutations/possession/storage.rs`.
- `Reservation::allocate_retention` — `src/managed/mutations/possession/storage.rs`.


<a id="cause-OperationDestinationAllocation"></a>

### `OperationDestinationAllocation`


Local detection/handling phase and implementation owner:

- `Plan::allocate` — `src/advanced/admission/generation/preparation.rs`.
- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`.
- `Reservation::try_operation_permits_retained` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `!objects.is_empty() || objects.capacity() < self.activities.len()`.
- `Reservation::transfer_to_operation` — `src/managed/mutations/reservation.rs`.
- `Reservation::allocate_retention` — `src/managed/mutations/possession/storage.rs`.


<a id="cause-OperationDestinationChanged"></a>

### `OperationDestinationChanged`


Local detection/handling phase and implementation owner:

- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `!catalog.occupied.contains(key)`.
- `Reservation::transfer_to_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `self .keys .iter() .any(|k| !catalog.occupied.contains(k) || catalog.owned.contains_key(k))`.


<a id="cause-OperationDestinationCount"></a>

### `OperationDestinationCount`


Local detection/handling phase and implementation owner:

- `Plan::new` — `src/advanced/admission/generation/preparation.rs`.
- `Plan::bind` — `src/advanced/admission/generation/preparation.rs`.
- `Storage::allocated_bytes` — `src/advanced/admission/generation/preparation.rs`.
- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`. Enclosing true branch: `let Some((owner, count)) = catalog.owned.get(key)`.


<a id="cause-OperationRetentionAbsent"></a>

### `OperationRetentionAbsent`


Local detection/handling phase and implementation owner:

- `Reservation::retain_for_operation` — `src/managed/mutations/reservation.rs`.


<a id="cause-OperationSelectionAllocation"></a>

### `OperationSelectionAllocation`


Local detection/handling phase and implementation owner:

- `SelectionGuard::into_owned_retained` — `src/managed/mutations.rs`.


<a id="cause-PairSelectionAllocation"></a>

### `PairSelectionAllocation`


Local detection/handling phase and implementation owner:

- `PreparedManagedSelection::for_key_pair` — `src/managed/mutations.rs`.


<a id="cause-PublicPairSelectionPreparation"></a>

### `PublicPairSelectionPreparation`


Local detection/handling phase and implementation owner:

- `PreparedManagedSelection::for_key_pair` — `src/managed/mutations.rs`. Enclosing true branch: `self.keys.len() != 1 || self.keys[0].class != Some(CKO_PUBLIC_KEY)`.


<a id="cause-RequestedDestinationOperandUnavailable"></a>

### `RequestedDestinationOperandUnavailable`


Local detection/handling phase and implementation owner:

- `DestinationRecipe<'_>::part` — `src/managed/mutations.rs`.
- `DestinationRecipe<'_>::template` — `src/managed/mutations.rs`. Enclosing true branch: `self.class == Some(CKO_DATA)`.


<a id="cause-ReservationActivityAllocation"></a>

### `ReservationActivityAllocation`


Local detection/handling phase and implementation owner:

- `prepare_grouped` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.
- `prepare_grouped` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ReservationActivityStorageSize"></a>

### `ReservationActivityStorageSize`


Local detection/handling phase and implementation owner:

- `prepare_grouped` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ReservationActivityVectorSize"></a>

### `ReservationActivityVectorSize`


Local detection/handling phase and implementation owner:

- `vector_bytes` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ReservationDestinationAllocation"></a>

### `ReservationDestinationAllocation`


Local detection/handling phase and implementation owner:

- `DestinationAllocation<'a>::allocate` — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ReservationPreparationSize"></a>

### `ReservationPreparationSize`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ReservationVectorSize"></a>

### `ReservationVectorSize`


Local detection/handling phase and implementation owner:

- `array_bytes` (module-level helper) — `src/managed/mutations/reservation_preparation.rs`.


<a id="cause-ResourceActivityAllocation"></a>

### `ResourceActivityAllocation`


Local detection/handling phase and implementation owner:

- `Catalog::resource_activity_prepared` — `src/managed/mutations/inventory.rs`.
- `PublicationSlots::new` — `src/managed/mutations/origins/capacity.rs`.


<a id="cause-ResourcePublicationCapacity"></a>

### `ResourcePublicationCapacity`


Local detection/handling phase and implementation owner:

- `Catalog::resource_activity_prepared` — `src/managed/mutations/inventory.rs`.


<a id="cause-SelectionAllocation"></a>

### `SelectionAllocation`


Local detection/handling phase and implementation owner:

- `Catalog::begin_select` — `src/managed/mutations/inventory.rs`.


<a id="cause-SelectionCount"></a>

### `SelectionCount`


Local detection/handling phase and implementation owner:

- `Catalog::begin_select` — `src/managed/mutations/inventory.rs`.


<a id="cause-SerialEncoding"></a>

### `SerialEncoding`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`.


<a id="cause-SubjectEncoding"></a>

### `SubjectEncoding`


Local detection/handling phase and implementation owner:

- `certificate_fields` (module-level helper) — `src/managed/mutations/storage.rs`.


<a id="cause-UnknownClassSelectionContract"></a>

### `UnknownClassSelectionContract`


Local detection/handling phase and implementation owner:

- `DestinationRecipe<'a>::class_scope` — `src/managed/mutations/reservation_preparation.rs`. Enclosing true branch: `matches!(class, ManagedClass::Other(_))`.
- `ManagedSelectionStorage<'a>::components` — `src/managed/mutations.rs`. Enclosing true branch: `matches!(class, ManagedClass::Other(_))`.


<a id="cause-UnobservedDestinationClass"></a>

### `UnobservedDestinationClass`


Local detection/handling phase and implementation owner:

- `DestinationRecipe<'_>::with_identity` — `src/managed/mutations.rs`. Enclosing false branch: `self.class == Some(CKO_DATA)`.
- `DestinationRecipe<'_>::template` — `src/managed/mutations.rs`.


<a id="cause-UnselectedMutationContent"></a>

### `UnselectedMutationContent`


Local detection/handling phase and implementation owner:

- `SetAttributesOwner::advance` — `src/managed/mutations/generic/resident.rs`. Enclosing match alternative: `ContentStorage::None`.
