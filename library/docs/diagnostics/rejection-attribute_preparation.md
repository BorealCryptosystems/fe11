Cause contracts for `AttributePreparationRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AttributeAbsentFromAdmissionSnapshot"></a>

### `AttributeAbsentFromAdmissionSnapshot`


Local detection/handling phase and implementation owner:

- `RequiredAttributes::bytes` — `src/attributes.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeAlignmentSize"></a>

### `AttributeAlignmentSize`


Local detection/handling phase and implementation owner:

- `AlignedOutput::new` — `src/attributes.rs`.
- `AlignedOutput::allocated_bytes` — `src/attributes.rs`.
- `ReadFrame::accept` — `src/advanced/admission/read.rs`. Enclosing true branch: `attr.ulValueLen != CK_UNAVAILABLE_INFORMATION`.
- `prepare_value` (module-level helper) — `src/attributes/owned/resident/preparation.rs`.


<a id="cause-AttributeAllocation"></a>

### `AttributeAllocation`


Local detection/handling phase and implementation owner:

- `reserved` (module-level helper) — `src/attributes.rs`.


<a id="cause-AttributeContinuationPhase"></a>

### `AttributeContinuationPhase`


Local detection/handling phase and implementation owner:

- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `state`.


<a id="cause-AttributeContinuationPreparationChanged"></a>

### `AttributeContinuationPreparationChanged`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing true branch: `self.need() != Some(need)`.


<a id="cause-AttributeExportFieldMissing"></a>

### `AttributeExportFieldMissing`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `( ReadState::NeedExport { call, .. }, ValueNeed::PublicCopy { index, length }, ValueCandidate::PublicCopy(copy), )`.
- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `ReadState::Export { call, mut next }`.


<a id="cause-AttributeExportLengthChanged"></a>

### `AttributeExportLengthChanged`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing true branch: `*completed != length`.


<a id="cause-AttributeExportSourceAbsent"></a>

### `AttributeExportSourceAbsent`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `( ReadState::NeedExport { call, .. }, ValueNeed::PublicCopy { index, length }, ValueCandidate::PublicCopy(copy), )`.


<a id="cause-AttributeFinalLength"></a>

### `AttributeFinalLength`

A completed-byte view or local attribute-storage length would exceed its
allocated capacity. The check publishes no slice and does not enlarge storage.
These helpers do not themselves establish native completion: their enclosing
attribute read/publication owner retains that evidence and its buffers. Preserve
AttributeReadInvalid/Interrupted or other complete enclosing errors where present.
Do not clamp the length, expose tail bytes or repeat an attribute call merely
because this local check refused publication.


Local detection/handling phase and implementation owner:

- `AlignedOutput::completed_bytes` — `src/attributes.rs`. Enclosing true branch: `length > self.capacity`.
- `AttributeBytes::set_length` — `src/attribute_values/storage.rs`. Enclosing true branch: `length > self.capacity`.


<a id="cause-AttributeNativeDescriptorOrCapacityChanged"></a>

### `AttributeNativeDescriptorOrCapacityChanged`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/attributes/owned.rs`. Enclosing true branch: `!data.descriptors_valid(phase, rv)`.
- `PreparedClassRead<'a>::check` — `src/attributes/owned.rs`. Enclosing true branch: `descriptor.r#type != CKA_CLASS || descriptor.pValue != pointer || !bounded`.


<a id="cause-AttributeObservationAccessOwner"></a>

### `AttributeObservationAccessOwner`


Local detection/handling phase and implementation owner:

- `PreparedClassRead<'a>::from_storage` — `src/attributes/owned.rs`. Enclosing true branch: `!access.owns_session(session)`.


<a id="cause-AttributeObservationOutputKind"></a>

### `AttributeObservationOutputKind`


Local detection/handling phase and implementation owner:

- `LegacyOwner::history_result` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `_`.
- `LegacyOwner::precise_result` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `_`.
- `LegacyOwner::public_result` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `_`.
- `LegacyOwner::object_observations_result` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `_`.
- `LegacyOwner::required_result` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `_`.
- `observe` (module-level helper) — `src/attributes/owned/resident/runner.rs`. Enclosing match alternative: `_`.
- `observe_controls` (module-level helper) — `src/attributes/owned/resident/runner.rs`. Enclosing match alternative: `_`.
- `observe_history_with` (module-level helper) — `src/attributes/owned/resident/runner.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeObservationStorageSize"></a>

### `AttributeObservationStorageSize`


Local detection/handling phase and implementation owner:

- `size` (module-level helper) — `src/attributes/owned/resident/preparation.rs`.
- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`.
- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`.


<a id="cause-AttributePreparationKindChanged"></a>

### `AttributePreparationKindChanged`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeProjectionCount"></a>

### `AttributeProjectionCount`


Local detection/handling phase and implementation owner:

- `AttributeSnapshot::from_parts` — `src/attributes/owned/resident/export.rs`. Enclosing true branch: `fields.len() != values.len()`.


<a id="cause-AttributeProjectionCreditAbsent"></a>

### `AttributeProjectionCreditAbsent`


Local detection/handling phase and implementation owner:

- `AttributeSnapshot::set_copy` — `src/attributes/owned/resident/export.rs`.


<a id="cause-AttributeProjectionLengthChanged"></a>

### `AttributeProjectionLengthChanged`


Local detection/handling phase and implementation owner:

- `AttributeSnapshot::set_copy` — `src/attributes/owned/resident/export.rs`. Enclosing true branch: `copy.bytes.len() != bytes.len()`.


<a id="cause-AttributeResidentStorageSize"></a>

### `AttributeResidentStorageSize`


Local detection/handling phase and implementation owner:

- `Storage::resident_bytes` — `src/attributes/owned/resident/preparation.rs`.


<a id="cause-AttributeSourceChanged"></a>

### `AttributeSourceChanged`


Local detection/handling phase and implementation owner:

- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Enclosing true branch: `handle != self.handle`.


<a id="cause-AttributeTotal"></a>

### `AttributeTotal`


Local detection/handling phase and implementation owner:

- `add_attribute_size` (module-level helper) — `src/attributes.rs`.
- `add_attribute_size` (module-level helper) — `src/attributes.rs`. Enclosing true branch: `next > budget`.
- `ReadCandidate::prepare` — `src/advanced/admission/read.rs`. Enclosing match alternative: `Some(length)`.
- `ReadFrame::validate_return` — `src/advanced/admission/read.rs`.
- `ReadFrame::accept` — `src/advanced/admission/read.rs`. Enclosing true branch: `attr.ulValueLen != CK_UNAVAILABLE_INFORMATION`.


<a id="cause-AttributeTotalBudget"></a>

### `AttributeTotalBudget`


Local detection/handling phase and implementation owner:

- `LegacyOwner::projected_total` — `src/attributes/owned/resident.rs`. Enclosing true branch: `next > maximum`. Fallback cause for readers outside an inventory; inventory children report `InventoryByteQuota`.
- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `RequestKind::Individual { .. }`. Subtracting the previously charged total fails; this accounting inconsistency retains the same cause in every reader context.


<a id="cause-AttributeTotalOverflow"></a>

### `AttributeTotalOverflow`


Local detection/handling phase and implementation owner:

- `LegacyOwner::projected_total` — `src/attributes/owned/resident.rs`.


<a id="cause-ClassObservationStorageSize"></a>

### `ClassObservationStorageSize`


Local detection/handling phase and implementation owner:

- `ClassReadStorage::storage_bytes` — `src/attributes/owned.rs`.


<a id="cause-EmptyPreciseObservation"></a>

### `EmptyPreciseObservation`


Local detection/handling phase and implementation owner:

- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`. Enclosing match alternative: `OutputKind::Precise`.


<a id="cause-FingerprintCompletedStorageMissing"></a>

### `FingerprintCompletedStorageMissing`


Local detection/handling phase and implementation owner:

- `FingerprintValues<'_>::get` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `PreciseAttributeValue::Available(_)`.


<a id="cause-FingerprintFieldIndex"></a>

### `FingerprintFieldIndex`


Local detection/handling phase and implementation owner:

- `FingerprintValues<'_>::get` — `src/attributes/owned/resident.rs`.


<a id="cause-FingerprintFieldMissing"></a>

### `FingerprintFieldMissing`


Local detection/handling phase and implementation owner:

- `FingerprintValues<'_>::get` — `src/attributes/owned/resident.rs`.


<a id="cause-FingerprintObservationIncomplete"></a>

### `FingerprintObservationIncomplete`


Local detection/handling phase and implementation owner:

- `LegacyOwner::fingerprint_result` — `src/attributes/owned/resident.rs`. Enclosing true branch: `!self.complete() || !matches!(self.output, OutputKind::Fingerprint)`.
- `FingerprintOwner::result` — `src/content_controls/fingerprint_observation/resident.rs`.


<a id="cause-FingerprintRequiresBorrowedResult"></a>

### `FingerprintRequiresBorrowedResult`


Local detection/handling phase and implementation owner:

- `LegacyOwner::result` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `OutputKind::Fingerprint`.
- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`. Enclosing match alternative: `OutputKind::Fingerprint`.


<a id="cause-KeyTypeIntegerEncoding"></a>

### `KeyTypeIntegerEncoding`


Local detection/handling phase and implementation owner:

- `RequiredAttributes::integer` — `src/attributes.rs`.


<a id="cause-KeyTypeMismatch"></a>

### `KeyTypeMismatch`


Local detection/handling phase and implementation owner:

- `RequiredAttributes::integer` — `src/attributes.rs`. Enclosing true branch: `CK_ULONG::from_ne_bytes(bytes) != expected`.
- `Admission::finish_terminal` — `src/advanced/admission/publication.rs`. Enclosing true branch: `let Err(cause) = result`.


<a id="cause-MechanismAttributeWidth"></a>

### `MechanismAttributeWidth`


Local detection/handling phase and implementation owner:

- `mechanism_chunks` (module-level helper) — `src/attributes.rs`. Enclosing true branch: `!matches!(WIDTH, 4 | 8) || bytes.len() % WIDTH != 0`.


<a id="cause-MechanismObservationField"></a>

### `MechanismObservationField`


Local detection/handling phase and implementation owner:

- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Enclosing true branch: `self.kinds.as_slice() != [CKA_ALLOWED_MECHANISMS]`.


<a id="cause-MechanismObservationStorageAbsent"></a>

### `MechanismObservationStorageAbsent`


Local detection/handling phase and implementation owner:

- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `PreciseAttributeValue::Available(_)`.


<a id="cause-MechanismProjectionCapacity"></a>

### `MechanismProjectionCapacity`


Local detection/handling phase and implementation owner:

- `MechanismValues::decode_prepared` — `src/attributes/owned/resident/export.rs`. Enclosing true branch: `!values.is_empty() || values.capacity() < bytes.len() / width`.
- `MechanismCopy::decode` — `src/attributes/owned/resident/export.rs`. Enclosing true branch: `count > self.values.capacity()`.


<a id="cause-MechanismProjectionLengthChanged"></a>

### `MechanismProjectionLengthChanged`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing true branch: `*completed != length`.


<a id="cause-MechanismProjectionSourceAbsent"></a>

### `MechanismProjectionSourceAbsent`


Local detection/handling phase and implementation owner:

- `LegacyOwner::attach` — `src/attributes/owned/resident.rs`. Enclosing match alternative: `( ReadState::NeedExport { call, .. }, ValueNeed::Mechanisms { length }, ValueCandidate::Mechanisms(copy), )`.


<a id="cause-MechanismProjectionWidth"></a>

### `MechanismProjectionWidth`


Local detection/handling phase and implementation owner:

- `MechanismCopy::prepare` — `src/attributes/owned/resident/export.rs`. Enclosing true branch: `length % width != 0`.


<a id="cause-MechanismTemplateAllocation"></a>

### `MechanismTemplateAllocation`


Local detection/handling phase and implementation owner:

- `Template::mechanisms` — `src/attributes.rs`.


<a id="cause-MutationClassIdentityChanged"></a>

### `MutationClassIdentityChanged`


Local detection/handling phase and implementation owner:

- `PreparedClassRead<'a>::check` — `src/attributes/owned.rs`. Enclosing true branch: `data.value != expected`.


<a id="cause-MutationClassObservationBudget"></a>

### `MutationClassObservationBudget`


Local detection/handling phase and implementation owner:

- `ClassReadStorage::allocation_bytes` — `src/attributes/owned.rs`. Enclosing true branch: `maximum_bytes < std::mem::size_of::<CK_OBJECT_CLASS>()`.


<a id="cause-MutationClassObservationUnavailableOrMalformed"></a>

### `MutationClassObservationUnavailableOrMalformed`


Local detection/handling phase and implementation owner:

- `PreparedClassRead<'a>::check` — `src/attributes/owned.rs`. Enclosing true branch: `data.descriptor.ulValueLen != std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG`.


<a id="cause-PreciseAttributeObservationCardinality"></a>

### `PreciseAttributeObservationCardinality`


Local detection/handling phase and implementation owner:

- `LegacyOwner::result` — `src/attributes/owned/resident.rs`. Enclosing true branch: `self.values.len() != 1 || self.kinds.len() != 1`.


<a id="cause-ReferenceTemplateBytesAllocation"></a>

### `ReferenceTemplateBytesAllocation`


Local detection/handling phase and implementation owner:

- `Template::try_identity_parts` — `src/attributes.rs`. Enclosing match alternative: `crate::IdentityAttribute::Id | crate::IdentityAttribute::Label | crate::IdentityAttribute::UniqueId | crate::IdentityAttribute::Application | crate::IdentityAttribute::ObjectId`.


<a id="cause-ReferenceTemplateFieldsAllocation"></a>

### `ReferenceTemplateFieldsAllocation`


Local detection/handling phase and implementation owner:

- `Template::try_identity_parts` — `src/attributes.rs`.


<a id="cause-ReferenceTemplateIntegerWidth"></a>

### `ReferenceTemplateIntegerWidth`


Local detection/handling phase and implementation owner:

- `Template::try_identity_parts` — `src/attributes.rs`. Enclosing match alternative: `crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType`.
- `Template::try_identity_parts` — `src/attributes.rs`. Enclosing match alternative: `crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType`.
- `DestinationIdentity<'_>::query_layout` — `src/destination_controls.rs`. Enclosing true branch: `value.len() != std::mem::size_of::<fe11_sys::CK_ULONG>()`.
- `identity_parts` (module-level helper) — `src/attributes/template_plan.rs`. Enclosing true branch: `matches!( field, crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType )`.
- `identity_attribute` (module-level helper) — `src/attributes/template_plan.rs`. Enclosing match alternative: `crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType`.
- `template` (module-level helper) — `src/reference_controls/evaluation.rs`. Enclosing match alternative: `IdentityAttribute::Class | IdentityAttribute::KeyType`.


<a id="cause-RequiredAttributeUnavailable"></a>

### `RequiredAttributeUnavailable`


Local detection/handling phase and implementation owner:

- `ObservedAttributes::require_all` — `src/attributes.rs`. Enclosing true branch: `!all_available`.


<a id="cause-TemplateAllocationSize"></a>

### `TemplateAllocationSize`


Local detection/handling phase and implementation owner:

- `KeySelectorStorage::bytes` — `src/attributes.rs`.
- `KeySelectorStorage::bind` — `src/attributes.rs`. Enclosing true branch: `id.len() > self.id.capacity()`.
- `Template::identity_allocation_bytes` — `src/attributes.rs`.
- `Template::retained_bytes` — `src/attributes.rs`.
- `Template::retained_bytes` — `src/attributes.rs`. Enclosing match alternative: `InputValue::Mechanisms(value)`.
- `Template::retained_bytes` — `src/attributes.rs`.
- `Template::descriptors_into` — `src/attributes.rs`. Enclosing true branch: `descriptors.capacity() < self.0.len() || !descriptors.is_empty()`.
- `DestinationIdentity<'_>::query_layout` — `src/destination_controls.rs`. Enclosing false branch: `field == IdentityAttribute::KeyType`.
- `TemplateSize::add` — `src/attributes/template_plan.rs`. Enclosing match alternative: `_`.
- `TemplateSize::owned_bytes` — `src/attributes/template_plan.rs`.
- `TemplateSize::mechanism_numbers` — `src/attributes/template_plan.rs`.
- `TemplateSize::mechanisms` — `src/attributes/template_plan.rs`.
- `OwnedTemplateStorage::allocated_bytes` — `src/attributes/template_plan.rs`.
- `OwnedTemplateStorage::allocated_bytes` — `src/attributes/template_plan.rs`.


<a id="cause-TemplateByteAllocation"></a>

### `TemplateByteAllocation`


Local detection/handling phase and implementation owner:

- `Template::bytes` — `src/attributes.rs`. Enclosing true branch: `bytes.try_reserve_exact(v.len()).is_err()`.
- `Template::byte_parts` — `src/attributes/template_plan.rs`. Enclosing true branch: `bytes.try_reserve_exact(value.len()).is_err()`.


<a id="cause-TemplateByteLengthConversion"></a>

### `TemplateByteLengthConversion`


Local detection/handling phase and implementation owner:

- `Template::bytes` — `src/attributes.rs`. Enclosing true branch: `bounds::ck_length(v.len()).is_err()`.
- `Template::byte_parts` — `src/attributes/template_plan.rs`. Enclosing true branch: `bounds::ck_length(value.len()).is_err()`.
- `TemplateSize::byte_parts` — `src/attributes/template_plan.rs`. Enclosing true branch: `bounds::ck_length(value.len()).is_err()`.
- `TemplateSize::bytes` — `src/attributes/template_plan.rs`. Enclosing true branch: `bounds::ck_length(value.len()).is_err()`.


<a id="cause-TemplateDescriptorAllocation"></a>

### `TemplateDescriptorAllocation`


Local detection/handling phase and implementation owner:

- `Template::mechanisms` — `src/attributes.rs`.
- `Template::mechanism_numbers` — `src/attributes/template_plan.rs`.


<a id="cause-TemplateFieldAllocation"></a>

### `TemplateFieldAllocation`


Local detection/handling phase and implementation owner:

- `Template::push` — `src/attributes.rs`. Enclosing true branch: `self.0.try_reserve(1).is_err()`.
