Cause contracts for `MechanismExtensionsRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-NullExtensionParameterCannotOwnUnreachableBlocks"></a>

### `NullExtensionParameterCannotOwnUnreachableBlocks`


Local detection/handling phase and implementation owner:

- `OwnedGraph::validate_structure` — `src/mechanism_extension/graph.rs`. Enclosing true branch: `input.root().is_none() && (input.block_count() != 0 || input.pointer_count() != 0 || input.output_count() != 0)`.


<a id="cause-RatchetMechanismFunctionMismatch"></a>

### `RatchetMechanismFunctionMismatch`


Local detection/handling phase and implementation owner:

- `crate::Module::declare_mechanism_extension` — `src/mechanism_extension.rs`. Enclosing true branch: `(mechanism == CKM_X2RATCHET_ENCRYPT && !matches!( operation, ExtensionOperation::Encrypt | ExtensionOperation::WrapKey )) || (mechanism == CKM_X2RATCHET_DECRYPT && !matches!( operation, ExtensionOperation::Decrypt | ExtensionOperation::UnwrapKey ))`.


<a id="cause-ChangedGraphCannotBeCaptured"></a>

### `ChangedGraphCannotBeCaptured`


Local detection/handling phase and implementation owner:

- `OwnedGraph::write_snapshot` — `src/mechanism_extension/graph/snapshot.rs`. Enclosing true branch: `!self.unchanged()`.


<a id="cause-ChangedMessageInitialization"></a>

### `ChangedMessageInitialization`


Local detection/handling phase and implementation owner:

- `Initialization::rebind` — `src/mechanism_extension/message/initialization.rs`. Enclosing true branch: `!self.unchanged(expected)`.


<a id="cause-ChangedParameterGraphCannotBeRebound"></a>

### `ChangedParameterGraphCannotBeRebound`


Local detection/handling phase and implementation owner:

- `RetainedParameterKeys::rebind` — `src/mechanism_extension/parameter_keys/rebind.rs`. Enclosing true branch: `!graph.unchanged() || !self.unchanged(graph)`.


<a id="cause-ChangedRetainedExtensionGraph"></a>

### `ChangedRetainedExtensionGraph`


Local detection/handling phase and implementation owner:

- `super::OwnedGraph::copy` — `src/mechanism_extension/graph/recipe.rs`. Enclosing true branch: `!self.unchanged()`.
- `super::OwnedGraph::visit_copies` — `src/mechanism_extension/graph/recipe.rs`. Enclosing true branch: `!self.unchanged()`.


<a id="cause-DigestExtensionHasNoContextualKeyAuthentication"></a>

### `DigestExtensionHasNoContextualKeyAuthentication`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `key.is_none() && authentication.is_some()`.


<a id="cause-DigestExtensionHasNoKey"></a>

### `DigestExtensionHasNoKey`


Local detection/handling phase and implementation owner:

- `crate::Module::declare_mechanism_extension` — `src/mechanism_extension.rs`. Enclosing true branch: `matches!( operation, ExtensionOperation::Digest | ExtensionOperation::DigestMultipart ) && mutates_key`.


<a id="cause-ExtensionAlignedAllocation"></a>

### `ExtensionAlignedAllocation`


Local detection/handling phase and implementation owner:

- `AlignedStorage::allocate` — `src/mechanism_extension/graph.rs`.


<a id="cause-ExtensionAllocationLayout"></a>

### `ExtensionAllocationLayout`


Local detection/handling phase and implementation owner:

- `AlignedStorage::layout` — `src/mechanism_extension/graph.rs`.


<a id="cause-ExtensionBlockAlignment"></a>

### `ExtensionBlockAlignment`


Local detection/handling phase and implementation owner:

- `AlignedStorage::layout` — `src/mechanism_extension/graph.rs`. Enclosing true branch: `!alignment.is_power_of_two()`.


<a id="cause-ExtensionCallAllocationAccounting"></a>

### `ExtensionCallAllocationAccounting`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`.
- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`.
- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`.
- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`.
- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `actual > admitted`.


<a id="cause-ExtensionDiagnosticRouteChanged"></a>

### `ExtensionDiagnosticRouteChanged`


Local detection/handling phase and implementation owner:

No direct construction site is present in the current sources. This public
variant remains available; the common error contract still governs handling.


<a id="cause-ExtensionGraphMetadataAllocation"></a>

### `ExtensionGraphMetadataAllocation`


Local detection/handling phase and implementation owner:

- `entries` (module-level helper) — `src/mechanism_extension/graph/preparation.rs`.


<a id="cause-ExtensionGraphRangeOrOverlap"></a>

### `ExtensionGraphRangeOrOverlap`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/mechanism_extension/graph.rs`.


<a id="cause-ExtensionInitializationInputMutation"></a>

### `ExtensionInitializationInputMutation`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `!data.unchanged(expected)`.


<a id="cause-ExtensionInputLengthOverflow"></a>

### `ExtensionInputLengthOverflow`


Local detection/handling phase and implementation owner:

- `checked_length` (module-level helper) — `src/mechanism_extension/operation/input.rs`.
- `Storage::allocated_bytes` — `src/mechanism_extension/operation/input.rs`. Enclosing match alternative: `Self::Multipart { value, witness }`.


<a id="cause-ExtensionInputMutationDuringAuthentication"></a>

### `ExtensionInputMutationDuringAuthentication`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `!data.unchanged(expected)`.


<a id="cause-ExtensionInputRouteChanged"></a>

### `ExtensionInputRouteChanged`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `single_input.is_some() != route.update().is_none()`.


<a id="cause-ExtensionMechanismAbiWidth"></a>

### `ExtensionMechanismAbiWidth`


Local detection/handling phase and implementation owner:

- `crate::Module::declare_mechanism_extension` — `src/mechanism_extension.rs`.


<a id="cause-ExtensionNativeInputMutation"></a>

### `ExtensionNativeInputMutation`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `!data.unchanged(expected)`.


<a id="cause-ExtensionOutputExceedsCapacity"></a>

### `ExtensionOutputExceedsCapacity`


Local detection/handling phase and implementation owner:

- `OwnedGraph::output_length` — `src/mechanism_extension/graph.rs`. Enclosing true branch: `length > region.capacity`.


<a id="cause-ExtensionPointerPlaceholderMustBeZero"></a>

### `ExtensionPointerPlaceholderMustBeZero`


Local detection/handling phase and implementation owner:

- `OwnedGraph::validate_indexed` — `src/mechanism_extension/graph.rs`. Enclosing true branch: `placeholder.iter().any(|byte| *byte != 0)`.


<a id="cause-ExtensionUpdateInputMutation"></a>

### `ExtensionUpdateInputMutation`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `!data.unchanged(expected)`.


<a id="cause-GraphSnapshotAbiOrVersion"></a>

### `GraphSnapshotAbiOrVersion`


Local detection/handling phase and implementation owner:

- `SnapshotRecipe<'a>::decode` — `src/mechanism_extension/graph/snapshot.rs`. Enclosing true branch: `reader.take(4)? != MAGIC || reader.take(4)? != [ size_of::<CK_VOID_PTR>() as u8, size_of::<CK_ULONG>() as u8, u8::from(cfg!(target_endian = "little")), 0, ]`.


<a id="cause-GraphValidationIndexAllocation"></a>

### `GraphValidationIndexAllocation`


Local detection/handling phase and implementation owner:

- `SnapshotIndex::allocate` — `src/mechanism_extension/graph/snapshot/index.rs`.


<a id="cause-GraphValidationIndexCapacity"></a>

### `GraphValidationIndexCapacity`


Local detection/handling phase and implementation owner:

- `SnapshotIndex::validate` — `src/mechanism_extension/graph/snapshot/index.rs`. Enclosing true branch: `recipe .blocks .checked_add(recipe.pointers) .ok_or_else(invalid)? > self.entries.capacity()`.


<a id="cause-KeyTransportNativeInputOrOutputCapacityViolation"></a>

### `KeyTransportNativeInputOrOutputCapacityViolation`

Detected after a native transport return when its saved input identity changed
or output capacity was violated. A nonzero native code is preserved alongside
the local cause; CKR_OK does not establish completed execution across an invalid
boundary. The object-uncertainty marker is retained where creation may have occurred.
Preserve the whole composite error and cleanup owner. No fallback, length clamp,
resize-and-replay or assumption that created objects were removed is authorized.


Local detection/handling phase and implementation owner:

- `KeyCreation::execute_prepared` — `src/mechanism_extension/transport.rs`. Enclosing true branch: `let CreationData::Encapsulate { bytes, length } = &mut data.data`.
- `KeyCreation::execute_prepared` — `src/mechanism_extension/transport.rs`. Enclosing true branch: `!unchanged || overflow`.


<a id="cause-KeyTransportReturnedAuxiliarySourceHandle"></a>

### `KeyTransportReturnedAuxiliarySourceHandle`


Local detection/handling phase and implementation owner:

- `KeyCreation::execute_prepared` — `src/mechanism_extension/transport.rs`. Enclosing true branch: `data.handle == source`.


<a id="cause-KeyTransportReturnedSourceHandle"></a>

### `KeyTransportReturnedSourceHandle`


Local detection/handling phase and implementation owner:

- `KeyCreation::execute_prepared` — `src/mechanism_extension/transport.rs`. Enclosing true branch: `data.handle == key && key != CK_INVALID_HANDLE`.


<a id="cause-KeyTransportStorageAccounting"></a>

### `KeyTransportStorageAccounting`


Local detection/handling phase and implementation owner:

- `KeyCreation::allocation_bytes` — `src/mechanism_extension/transport.rs`.
- `KeyCreationStorage<'a>::allocated_bytes` — `src/mechanism_extension/transport/preparation.rs`.


<a id="cause-MechanismExtensionModuleFunctionMismatch"></a>

### `MechanismExtensionModuleFunctionMismatch`


Local detection/handling phase and implementation owner:

- `MechanismExtension::check` — `src/mechanism_extension.rs`. Enclosing true branch: `!Weak::ptr_eq(&self.owner, &Arc::downgrade(inner)) || self.operation != operation`.


<a id="cause-NativeAlignedOutputAccounting"></a>

### `NativeAlignedOutputAccounting`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`.


<a id="cause-NativeOutputAlignment"></a>

### `NativeOutputAlignment`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `!alignment.is_power_of_two()`.


<a id="cause-NativeOutputAlignmentUnavailable"></a>

### `NativeOutputAlignmentUnavailable`


Local detection/handling phase and implementation owner:

- `execute_published` (module-level helper) — `src/mechanism_extension/operation/invocation.rs`. Enclosing true branch: `output_offset > alignment - 1`.


<a id="cause-NestedMechanismGraphAccounting"></a>

### `NestedMechanismGraphAccounting`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/mechanism_extension/nested.rs`.
- `from_transport` (module-level helper) — `src/mechanism_extension/transport/fixed_prefix.rs`.


<a id="cause-NestedMechanismParentHasNoRoot"></a>

### `NestedMechanismParentHasNoRoot`


Local detection/handling phase and implementation owner:

- `compose` (module-level helper) — `src/mechanism_extension/nested.rs`.


<a id="cause-SingleMessageFacadeResultShape"></a>

### `SingleMessageFacadeResultShape`


Local detection/handling phase and implementation owner:

- `NativeMessageResult::from_messages` — `src/mechanism_extension/message.rs`. Enclosing true branch: `body.len() != 1`.


<a id="cause-TransportInputAccounting"></a>

### `TransportInputAccounting`


Local detection/handling phase and implementation owner:

- `CreationInput<'_>::allocation_bytes` — `src/mechanism_extension/transport.rs`. Enclosing match alternative: `Self::Unwrap(bytes) | Self::Decapsulate(bytes)`.


<a id="cause-TypedParameterKeyBinding"></a>

### `TypedParameterKeyBinding`


Local detection/handling phase and implementation owner:

- `invalid` (module-level helper) — `src/mechanism_extension/parameter_keys.rs`.


<a id="cause-TypedSignaturePublicationRoute"></a>

### `TypedSignaturePublicationRoute`


Local detection/handling phase and implementation owner:

- `execute_with_sources_and_publish` (module-level helper) — `src/mechanism_extension/operation.rs`. Enclosing true branch: `!matches!( &input, ExtensionInput::Sign { .. } | ExtensionInput::SignMultipart { .. } )`.


<a id="cause-WrapAggregateStorageAccounting"></a>

### `WrapAggregateStorageAccounting`


Local detection/handling phase and implementation owner:

- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`.


<a id="cause-WrapFrameStorageAccounting"></a>

### `WrapFrameStorageAccounting`


Local detection/handling phase and implementation owner:

- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`.


<a id="cause-WrapNativeInputChanged"></a>

### `WrapNativeInputChanged`


Local detection/handling phase and implementation owner:

- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`. Enclosing false branch: `overflow`.


<a id="cause-WrapRevocationStorageAccounting"></a>

### `WrapRevocationStorageAccounting`


Local detection/handling phase and implementation owner:

- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`.


<a id="cause-WrapStorageAccounting"></a>

### `WrapStorageAccounting`


Local detection/handling phase and implementation owner:

- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`.
- `wrap_with_fixed_prefix` (module-level helper) — `src/mechanism_extension/transport.rs`.
