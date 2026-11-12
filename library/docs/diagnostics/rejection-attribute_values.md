Cause contracts for `AttributeValuesRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-CGetAttributeValueUnavailable"></a>

### `CGetAttributeValueUnavailable`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/attributes/owned.rs`.
- `PreparedClassRead<'a>::from_storage` — `src/attributes/owned.rs`. Enclosing true branch: `access.native.table.C_GetAttributeValue.is_none()`.
- `PreparedClassRead<'a>::check` — `src/attributes/owned.rs`.
- `dispatch` (module-level helper) — `src/attribute_values/read.rs`.
- `dispatch` (module-level helper) — `src/content_controls/owned.rs`.
- `dispatch` (module-level helper) — `src/attribute_values/template/native.rs`.
- `read_prepared` (module-level helper) — `src/crypto/pqc_material/export.rs`.
- `export` (module-level helper) — `src/crypto/pqc_material/resident/runner.rs`.
- `observe_native` (module-level helper) — `src/managed/discovery/runner.rs`.


<a id="cause-AttributeAlignmentOverflow"></a>

### `AttributeAlignmentOverflow`


Local detection/handling phase and implementation owner:

- `AttributeBytes::allocation_bytes` — `src/attribute_values/storage.rs`.


<a id="cause-AttributeAllocatorAccountingOverflow"></a>

### `AttributeAllocatorAccountingOverflow`


Local detection/handling phase and implementation owner:

- `reserve_prepaid_entries` (module-level helper) — `src/attribute_values/storage.rs`.
- `AttributeBytesStorage::allocated_bytes` — `src/attribute_values/storage.rs`.
- `AttributeBytes::new_prepaid` — `src/attribute_values/storage.rs`.


<a id="cause-AttributeArenaConstructionOrder"></a>

### `AttributeArenaConstructionOrder`


Local detection/handling phase and implementation owner:

- `InputTemplatePlan<'a>::allocate` — `src/attribute_values/input/preparation.rs`. Enclosing true branch: `start.checked_add(offset) != Some(storage.witnesses.len())`.


<a id="cause-AttributeArenaRange"></a>

### `AttributeArenaRange`


Local detection/handling phase and implementation owner:

- `InputTemplatePlan<'a>::allocate` — `src/attribute_values/input/preparation.rs`. Enclosing match alternative: `AttributeInputValue::Template(children)`.


<a id="cause-AttributeArenaUnfinished"></a>

### `AttributeArenaUnfinished`


Local detection/handling phase and implementation owner:

- `InputTemplatePlan<'a>::allocate` — `src/attribute_values/input/preparation.rs`. Enclosing true branch: `cursor != self.measured.attributes || storage.witnesses.len() != self.measured.attributes || storage.prepared.len() != self.measured.values`.


<a id="cause-AttributeBatchHasUnfinishedResults"></a>

### `AttributeBatchHasUnfinishedResults`


Local detection/handling phase and implementation owner:

- `FlatAttributeBatch::finish` — `src/attribute_values/batch.rs`. Enclosing true branch: `self.entries.iter().any(Option::is_none)`.


<a id="cause-AttributeBooleanRepresentation"></a>

### `AttributeBooleanRepresentation`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::boolean` — `src/attribute_values.rs`. Enclosing match alternative: `_`.


<a id="cause-AttributeCallMetadataAccounting"></a>

### `AttributeCallMetadataAccounting`


Local detection/handling phase and implementation owner:

- `ReadCall::metadata_bytes` — `src/attribute_values/read.rs`.


<a id="cause-AttributeCallMetadataCapacity"></a>

### `AttributeCallMetadataCapacity`


Local detection/handling phase and implementation owner:

- `ReadCall::push` — `src/attribute_values/read.rs`. Enclosing true branch: `self.slots.len() == self.slots.capacity() || self.descriptors.len() == self.descriptors.capacity()`.


<a id="cause-AttributeDateWidth"></a>

### `AttributeDateWidth`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::date` — `src/attribute_values.rs`.


<a id="cause-AttributeDescriptorOrReturnedCapacityChanged"></a>

### `AttributeDescriptorOrReturnedCapacityChanged`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/attribute_values/read.rs`. Enclosing true branch: `!data.valid_return(code)`.


<a id="cause-AttributeExtensionBelongsToAnotherModuleInstance"></a>

### `AttributeExtensionBelongsToAnotherModuleInstance`


Local detection/handling phase and implementation owner:

- `AttributeType::check_scope` — `src/attribute_values/identity.rs`. Enclosing true branch: `Some(attribute.scope) != scope`.


<a id="cause-AttributeExtensionScopeExhausted"></a>

### `AttributeExtensionScopeExhausted`


Local detection/handling phase and implementation owner:

- `next_scope` (module-level helper) — `src/attribute_values/identity.rs`.


<a id="cause-AttributeExtensionScopeMissing"></a>

### `AttributeExtensionScopeMissing`


Local detection/handling phase and implementation owner:

- `module_scope` (module-level helper) — `src/attribute_values/identity.rs`.


<a id="cause-AttributeFirstCallProvenanceAbsent"></a>

### `AttributeFirstCallProvenanceAbsent`


Local detection/handling phase and implementation owner:

- `FlatOwner::advance` — `src/attribute_values/read/owner.rs`. Enclosing match alternative: `State::Second(call)`.


<a id="cause-AttributeInitialAllocationAccounting"></a>

### `AttributeInitialAllocationAccounting`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/attribute_values/read/preparation.rs`.


<a id="cause-AttributeInputByteLength"></a>

### `AttributeInputByteLength`


Local detection/handling phase and implementation owner:

- `AttributeBytes::copy_from` — `src/attribute_values/storage.rs`. Enclosing true branch: `bytes.len() != self.capacity`.


<a id="cause-AttributeInputCopyRange"></a>

### `AttributeInputCopyRange`


Local detection/handling phase and implementation owner:

- `AttributeBytes::copy_at` — `src/attribute_values/storage.rs`.


<a id="cause-AttributeInputRepresentation"></a>

### `AttributeInputRepresentation`


Local detection/handling phase and implementation owner:

- `value_size` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `input.attribute.layout() != AttributeLayout::Template`.
- `value_size` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `input.attribute.layout() != layout`.


<a id="cause-AttributeIntegerArraySize"></a>

### `AttributeIntegerArraySize`


Local detection/handling phase and implementation owner:

- `value_size` (module-level helper) — `src/attribute_values/input.rs`. Enclosing match alternative: `AttributeInputValue::UnsignedArray(values)`.


<a id="cause-AttributeIsNotAnUnsignedArray"></a>

### `AttributeIsNotAnUnsignedArray`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::unsigned_values` — `src/attribute_values.rs`. Enclosing true branch: `self.attribute.layout() != AttributeLayout::UnsignedArray`.


<a id="cause-AttributeMetadataAccountingOverflow"></a>

### `AttributeMetadataAccountingOverflow`


Local detection/handling phase and implementation owner:

- `reserve_prepaid_entries` (module-level helper) — `src/attribute_values/storage.rs`.
- `bytes` (module-level helper) — `src/attribute_values/input/preparation.rs`.


<a id="cause-AttributeMetadataAllocation"></a>

### `AttributeMetadataAllocation`


Local detection/handling phase and implementation owner:

- `BatchStorage::allocate` — `src/attribute_values/batch.rs`.
- `reserve_entries` (module-level helper) — `src/attribute_values/batch.rs`.
- `reserve_prepaid_entries` (module-level helper) — `src/attribute_values/storage.rs`.
- `reserve` (module-level helper) — `src/attribute_values/input/preparation.rs`.
- `entries` (module-level helper) — `src/attribute_values/read/preparation.rs`.


<a id="cause-AttributeMetadataCapacity"></a>

### `AttributeMetadataCapacity`


Local detection/handling phase and implementation owner:

- `reserve_entries` (module-level helper) — `src/attribute_values/batch.rs`.


<a id="cause-AttributeMetadataSize"></a>

### `AttributeMetadataSize`


Local detection/handling phase and implementation owner:

- `reserve_entries` (module-level helper) — `src/attribute_values/batch.rs`.


<a id="cause-AttributeNativeIntegerWidth"></a>

### `AttributeNativeIntegerWidth`


Local detection/handling phase and implementation owner:

- `native_unsigned` (module-level helper) — `src/attribute_values/input.rs`.


<a id="cause-AttributeNativeScalarWidth"></a>

### `AttributeNativeScalarWidth`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::bytes_for` — `src/attribute_values.rs`. Enclosing true branch: `value.len() != width`.


<a id="cause-AttributeNativeSizeWidth"></a>

### `AttributeNativeSizeWidth`


Local detection/handling phase and implementation owner:

- `reported_size` (module-level helper) — `src/attribute_values/read.rs`.


<a id="cause-AttributeObservationIncomplete"></a>

### `AttributeObservationIncomplete`


Local detection/handling phase and implementation owner:

- `LegacyOwner::result` — `src/attributes/owned/resident.rs`. Enclosing true branch: `!self.complete()`.
- `FlatOwner::result` — `src/attribute_values/read/owner.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-AttributeObservationOwnerAccounting"></a>

### `AttributeObservationOwnerAccounting`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/attribute_values/read/owner/preparation.rs`.


<a id="cause-AttributeObservationPhaseUnavailable"></a>

### `AttributeObservationPhaseUnavailable`


Local detection/handling phase and implementation owner:

- `FlatOwner::advance` — `src/attribute_values/read/owner.rs`. Enclosing match alternative: `state @ (State::NeedValue { .. } | State::Complete | State::InFlight | State::Uncertain | State::Stopped)`.


<a id="cause-AttributeOwnerAccounting"></a>

### `AttributeOwnerAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/attribute_values/read/runner.rs`.
- `prepare` (module-level helper) — `src/attribute_values/read/runner.rs`.


<a id="cause-AttributePossessionAbsent"></a>

### `AttributePossessionAbsent`


Local detection/handling phase and implementation owner:

- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`.
- `observe_batch` (module-level helper) — `src/attribute_values/read/runner.rs`.


<a id="cause-AttributePreparationLengthChanged"></a>

### `AttributePreparationLengthChanged`


Local detection/handling phase and implementation owner:

- `FlatOwner::attach` — `src/attribute_values/read/owner.rs`. Enclosing true branch: `bytes.capacity() != need.length`.


<a id="cause-AttributeRepresentationDoesNotMatchConversion"></a>

### `AttributeRepresentationDoesNotMatchConversion`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::bytes_for` — `src/attribute_values.rs`. Enclosing true branch: `self.attribute.layout() != layout`.


<a id="cause-AttributeRequestMetadataAllocation"></a>

### `AttributeRequestMetadataAllocation`


Local detection/handling phase and implementation owner:

- `Plan<'a>::allocate` — `src/attribute_values/read/owner/preparation.rs`.


<a id="cause-AttributeResultMetadataAccounting"></a>

### `AttributeResultMetadataAccounting`


Local detection/handling phase and implementation owner:

- `FlatAttributeBatch::metadata_bytes` — `src/attribute_values/batch.rs`.


<a id="cause-AttributeSizeUnavailable"></a>

### `AttributeSizeUnavailable`


Local detection/handling phase and implementation owner:

- `query_decision` (module-level helper) — `src/attribute_values/read.rs`.


<a id="cause-AttributeSourceWithdrawn"></a>

### `AttributeSourceWithdrawn`


Local detection/handling phase and implementation owner:

- `FlatOwner::handle` — `src/attribute_values/read/owner.rs`.


<a id="cause-AttributeTemplateCountCeiling"></a>

### `AttributeTemplateCountCeiling`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`.


<a id="cause-AttributeTemplateDepthCeiling"></a>

### `AttributeTemplateDepthCeiling`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `!children.is_empty()`.


<a id="cause-AttributeTemplateGroupCount"></a>

### `AttributeTemplateGroupCount`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `let AttributeInputValue::Template(children) = &attribute.value`.


<a id="cause-AttributeTemplateMetadataAccounting"></a>

### `AttributeTemplateMetadataAccounting`


Local detection/handling phase and implementation owner:

- `Measurement::peak_bytes` — `src/attribute_values/input.rs`.


<a id="cause-AttributeTemplateSpecificationDeferred"></a>

### `AttributeTemplateSpecificationDeferred`


Local detection/handling phase and implementation owner:

- `ExtensionAttribute::new` — `src/attribute_values/identity.rs`. Enclosing true branch: `matches!(kind, CKA_ENCAPSULATE_TEMPLATE | CKA_DECAPSULATE_TEMPLATE)`.


<a id="cause-AttributeTemplateTotalAccounting"></a>

### `AttributeTemplateTotalAccounting`


Local detection/handling phase and implementation owner:

- `Measurement::peak_bytes` — `src/attribute_values/input.rs`.
- `sum` (module-level helper) — `src/attribute_values/input/preparation.rs`.


<a id="cause-AttributeTemplateValueCeiling"></a>

### `AttributeTemplateValueCeiling`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `let Some(bytes) = value_size(attribute)?`.


<a id="cause-AttributeTraversalAllocation"></a>

### `AttributeTraversalAllocation`


Local detection/handling phase and implementation owner:

- `Walk<'a>::push` — `src/attribute_values/input.rs`. Enclosing true branch: `self.frames.len() == self.frames.capacity()`.


<a id="cause-AttributeTraversalAllocationSize"></a>

### `AttributeTraversalAllocationSize`


Local detection/handling phase and implementation owner:

- `Walk<'a>::push` — `src/attribute_values/input.rs`. Enclosing true branch: `self.frames.len() == self.frames.capacity()`.


<a id="cause-AttributeUnsignedArrayWidth"></a>

### `AttributeUnsignedArrayWidth`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::unsigned_values` — `src/attribute_values.rs`. Enclosing true branch: `bytes.len() % width != 0`.


<a id="cause-AttributeUnsignedWidth"></a>

### `AttributeUnsignedWidth`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::unsigned` — `src/attribute_values.rs`.


<a id="cause-AttributeValueAccounting"></a>

### `AttributeValueAccounting`


Local detection/handling phase and implementation owner:

- `FlatOwner::attach` — `src/attribute_values/read/owner.rs`. Enclosing match alternative: `Ok(bytes)`.


<a id="cause-AttributeValueAllocationAccounting"></a>

### `AttributeValueAllocationAccounting`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `let Some(bytes) = value_size(attribute)?`.


<a id="cause-AttributeValueCount"></a>

### `AttributeValueCount`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `let Some(bytes) = value_size(attribute)?`.


<a id="cause-AttributeValueNeedAbsent"></a>

### `AttributeValueNeedAbsent`


Local detection/handling phase and implementation owner:

- `observe_recipe` (module-level helper) — `src/attributes/owned/resident/runner.rs`.
- `observe_batch` (module-level helper) — `src/attribute_values/read/runner.rs`.


<a id="cause-AttributeValueOwnerAbsent"></a>

### `AttributeValueOwnerAbsent`


Local detection/handling phase and implementation owner:

- `FlatOwner::advance` — `src/attribute_values/read/owner.rs`. Enclosing match alternative: `State::Second(call)`.


<a id="cause-AttributeValueUnavailable"></a>

### `AttributeValueUnavailable`


Local detection/handling phase and implementation owner:

- `FlatAttributeObservation::bytes_for` — `src/attribute_values.rs`.
- `FlatAttributeObservation::unsigned_values` — `src/attribute_values.rs`.


<a id="cause-AttributeValueWitnessAccounting"></a>

### `AttributeValueWitnessAccounting`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/input.rs`. Enclosing true branch: `let Some(bytes) = value_size(attribute)?`.


<a id="cause-DirectAttributeBatchAllocationCeiling"></a>

### `DirectAttributeBatchAllocationCeiling`


Local detection/handling phase and implementation owner:

- `validate_requests` (module-level helper) — `src/attribute_values/read.rs`. Enclosing true branch: `let FlatAttributeReadPlan::Buffer { capacity } = request.plan`.


<a id="cause-DirectAttributeUnexpectedlyQueried"></a>

### `DirectAttributeUnexpectedlyQueried`


Local detection/handling phase and implementation owner:

- `query_decision` (module-level helper) — `src/attribute_values/read.rs`. Enclosing match alternative: `FlatAttributeReadPlan::Buffer { .. }`.


<a id="cause-ExtensionAttributeNativeIdentifierWidth"></a>

### `ExtensionAttributeNativeIdentifierWidth`


Local detection/handling phase and implementation owner:

- `ExtensionAttribute::new` — `src/attribute_values/identity.rs`.


<a id="cause-FlatAttributeCannotOwnChildDescriptors"></a>

### `FlatAttributeCannotOwnChildDescriptors`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `attribute.layout() != AttributeLayout::Template`.


<a id="cause-FlatInputRequired"></a>

### `FlatInputRequired`


Local detection/handling phase and implementation owner:

- `InputTemplatePlan<'a>::allocate` — `src/attribute_values/input/preparation.rs`. Enclosing match alternative: `source`.


<a id="cause-KnownTemplateValueTypeMissing"></a>

### `KnownTemplateValueTypeMissing`


Local detection/handling phase and implementation owner:

- `observe_node` (module-level helper) — `src/attribute_values/template/native.rs`. Enclosing match alternative: `Storage::Buffer(_)`.


<a id="cause-NestedAttributeDescriptorBytes"></a>

### `NestedAttributeDescriptorBytes`


Local detection/handling phase and implementation owner:

- `value_size` (module-level helper) — `src/attribute_values/input.rs`. Enclosing match alternative: `AttributeInputValue::Template(attributes)`.


<a id="cause-NestedAttributeRequiresARecursiveReader"></a>

### `NestedAttributeRequiresARecursiveReader`


Local detection/handling phase and implementation owner:

- `crate::Session::read_flat_attribute` — `src/attribute_values.rs`. Enclosing true branch: `attribute.layout() == AttributeLayout::Template`.
- `validate_requests` (module-level helper) — `src/attribute_values/read.rs`. Enclosing true branch: `request.attribute.layout() == AttributeLayout::Template`.


<a id="cause-NestedInputRequiresDescriptors"></a>

### `NestedInputRequiresDescriptors`


Local detection/handling phase and implementation owner:

- `encode` (module-level helper) — `src/attribute_values/input.rs`. Enclosing match alternative: `AttributeInputValue::Template(_)`.


<a id="cause-ProtectedAttributeAllocation"></a>

### `ProtectedAttributeAllocation`


Local detection/handling phase and implementation owner:

- `AttributeBytesStorage::allocate` — `src/attribute_values/storage.rs`.
- `AttributeBytes::new_prepaid` — `src/attribute_values/storage.rs`.


<a id="cause-RootAttributeIsNotATemplate"></a>

### `RootAttributeIsNotATemplate`


Local detection/handling phase and implementation owner:

- `ReadCall::prepare` — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `attribute.layout() != AttributeLayout::Template`.


<a id="cause-SingleAttributeResultMissing"></a>

### `SingleAttributeResultMissing`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/attribute_values/read.rs`.


<a id="cause-StandardAttributeLayoutCannotBeOverridden"></a>

### `StandardAttributeLayoutCannotBeOverridden`


Local detection/handling phase and implementation owner:

- `ExtensionAttribute::new` — `src/attribute_values/identity.rs`. Enclosing true branch: `StandardAttribute::from_identifier(identifier).is_some()`.


<a id="cause-TemplateAllocationAccountingOverflow"></a>

### `TemplateAllocationAccountingOverflow`


Local detection/handling phase and implementation owner:

- `add` (module-level helper) — `src/attribute_values/template/prepare.rs`.


<a id="cause-TemplateDescriptorPointerOrCapacityChanged"></a>

### `TemplateDescriptorPointerOrCapacityChanged`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/attribute_values/template/native.rs`. Enclosing true branch: `!body.data.valid_return(code)`.


<a id="cause-TemplateMeasuredChildRange"></a>

### `TemplateMeasuredChildRange`


Local detection/handling phase and implementation owner:

- `ReadCall::prepare` — `src/attribute_values/template/prepare.rs`. Enclosing match alternative: `TemplateAttributeSlot::Template { attribute, slots }`.


<a id="cause-TemplateMeasuredCountChanged"></a>

### `TemplateMeasuredCountChanged`


Local detection/handling phase and implementation owner:

- `ReadCall::prepare` — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `cursor != measured.nodes`.


<a id="cause-TemplateMetadataAccountingOverflow"></a>

### `TemplateMetadataAccountingOverflow`


Local detection/handling phase and implementation owner:

- `bytes` (module-level helper) — `src/attribute_values/template/prepare.rs`.


<a id="cause-TemplateReadCompletionUnknown"></a>

### `TemplateReadCompletionUnknown`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/attribute_values/template/native.rs`. Enclosing true branch: `!crate::native_return::attribute_completion_known(code)`.


<a id="cause-TemplateReadDepthLimit"></a>

### `TemplateReadDepthLimit`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `walk.frames.len() > limits.maximum_depth`.


<a id="cause-TemplateReadDescriptorLimit"></a>

### `TemplateReadDescriptorLimit`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `measured.nodes > limits.maximum_attributes`.


<a id="cause-TemplateReadReturnedNoAttributeResult"></a>

### `TemplateReadReturnedNoAttributeResult`


Local detection/handling phase and implementation owner:

- `dispatch` (module-level helper) — `src/attribute_values/template/native.rs`. Enclosing true branch: `!partial(code)`.


<a id="cause-TemplateReadValueLimit"></a>

### `TemplateReadValueLimit`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `measured.values > limits.maximum_value_bytes`.


<a id="cause-TemplateResultAllocation"></a>

### `TemplateResultAllocation`


Local detection/handling phase and implementation owner:

- `ReadCall::prepare` — `src/attribute_values/template/prepare.rs`.


<a id="cause-TemplateRootDescriptorLimit"></a>

### `TemplateRootDescriptorLimit`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `limits.maximum_attributes == 0`.


<a id="cause-TemplateTraversalAllocation"></a>

### `TemplateTraversalAllocation`


Local detection/handling phase and implementation owner:

- `Walk<'a>::push` — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `self.frames.len() == self.frames.capacity()`.


<a id="cause-TemplateValueNeedsChildDescriptors"></a>

### `TemplateValueNeedsChildDescriptors`


Local detection/handling phase and implementation owner:

- `measure` (module-level helper) — `src/attribute_values/template/prepare.rs`. Enclosing true branch: `attribute.layout() == AttributeLayout::Template`.


<a id="cause-ValidatedTemplateResultCouldNotBeRepresented"></a>

### `ValidatedTemplateResultCouldNotBeRepresented`


Local detection/handling phase and implementation owner:

- `ReadCall::finish` — `src/attribute_values/template/native.rs`.
