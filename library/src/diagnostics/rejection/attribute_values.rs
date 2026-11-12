// SPDX-License-Identifier: Apache-2.0
//! AttributeValues causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to attribute values.
#[doc = include_str!("../../../docs/diagnostics/rejection-attribute_values.md")]
pub enum AttributeValuesRejection {
    /// C_GetAttributeValue unavailable. [Detection, owner and recovery](#cause-CGetAttributeValueUnavailable).
    CGetAttributeValueUnavailable,
    /// Attribute alignment overflow. [Detection, owner and recovery](#cause-AttributeAlignmentOverflow).
    AttributeAlignmentOverflow,
    /// Attribute allocator accounting overflow. [Detection, owner and recovery](#cause-AttributeAllocatorAccountingOverflow).
    AttributeAllocatorAccountingOverflow,
    /// Attribute arena construction order. [Detection, owner and recovery](#cause-AttributeArenaConstructionOrder).
    AttributeArenaConstructionOrder,
    /// Attribute arena range. [Detection, owner and recovery](#cause-AttributeArenaRange).
    AttributeArenaRange,
    /// Attribute arena unfinished. [Detection, owner and recovery](#cause-AttributeArenaUnfinished).
    AttributeArenaUnfinished,
    /// Attribute batch has unfinished results. [Detection, owner and recovery](#cause-AttributeBatchHasUnfinishedResults).
    AttributeBatchHasUnfinishedResults,
    /// Attribute boolean representation. [Detection, owner and recovery](#cause-AttributeBooleanRepresentation).
    AttributeBooleanRepresentation,
    /// Attribute call metadata accounting. [Detection, owner and recovery](#cause-AttributeCallMetadataAccounting).
    AttributeCallMetadataAccounting,
    /// Attribute call metadata capacity. [Detection, owner and recovery](#cause-AttributeCallMetadataCapacity).
    AttributeCallMetadataCapacity,
    /// Attribute date width. [Detection, owner and recovery](#cause-AttributeDateWidth).
    AttributeDateWidth,
    /// Attribute descriptor or returned capacity changed. [Detection, owner and recovery](#cause-AttributeDescriptorOrReturnedCapacityChanged).
    AttributeDescriptorOrReturnedCapacityChanged,
    /// Attribute extension belongs to another module instance. [Detection, owner and recovery](#cause-AttributeExtensionBelongsToAnotherModuleInstance).
    AttributeExtensionBelongsToAnotherModuleInstance,
    /// Attribute extension scope exhausted. [Detection, owner and recovery](#cause-AttributeExtensionScopeExhausted).
    AttributeExtensionScopeExhausted,
    /// Attribute extension scope missing. [Detection, owner and recovery](#cause-AttributeExtensionScopeMissing).
    AttributeExtensionScopeMissing,
    /// Attribute first-call provenance absent. [Detection, owner and recovery](#cause-AttributeFirstCallProvenanceAbsent).
    AttributeFirstCallProvenanceAbsent,
    /// Attribute initial allocation accounting. [Detection, owner and recovery](#cause-AttributeInitialAllocationAccounting).
    AttributeInitialAllocationAccounting,
    /// Attribute input byte length. [Detection, owner and recovery](#cause-AttributeInputByteLength).
    AttributeInputByteLength,
    /// Attribute input copy range. [Detection, owner and recovery](#cause-AttributeInputCopyRange).
    AttributeInputCopyRange,
    /// Attribute input representation. [Detection, owner and recovery](#cause-AttributeInputRepresentation).
    AttributeInputRepresentation,
    /// Attribute integer array size. [Detection, owner and recovery](#cause-AttributeIntegerArraySize).
    AttributeIntegerArraySize,
    /// Attribute is not an unsigned array. [Detection, owner and recovery](#cause-AttributeIsNotAnUnsignedArray).
    AttributeIsNotAnUnsignedArray,
    /// Attribute metadata accounting overflow. [Detection, owner and recovery](#cause-AttributeMetadataAccountingOverflow).
    AttributeMetadataAccountingOverflow,
    /// Attribute metadata allocation. [Detection, owner and recovery](#cause-AttributeMetadataAllocation).
    AttributeMetadataAllocation,
    /// Attribute metadata capacity. [Detection, owner and recovery](#cause-AttributeMetadataCapacity).
    AttributeMetadataCapacity,
    /// Attribute metadata size. [Detection, owner and recovery](#cause-AttributeMetadataSize).
    AttributeMetadataSize,
    /// Attribute native integer width. [Detection, owner and recovery](#cause-AttributeNativeIntegerWidth).
    AttributeNativeIntegerWidth,
    /// Attribute native scalar width. [Detection, owner and recovery](#cause-AttributeNativeScalarWidth).
    AttributeNativeScalarWidth,
    /// Attribute native size width. [Detection, owner and recovery](#cause-AttributeNativeSizeWidth).
    AttributeNativeSizeWidth,
    /// Attribute observation incomplete. [Detection, owner and recovery](#cause-AttributeObservationIncomplete).
    AttributeObservationIncomplete,
    /// Attribute observation owner accounting. [Detection, owner and recovery](#cause-AttributeObservationOwnerAccounting).
    AttributeObservationOwnerAccounting,
    /// Attribute observation phase unavailable. [Detection, owner and recovery](#cause-AttributeObservationPhaseUnavailable).
    AttributeObservationPhaseUnavailable,
    /// Attribute owner accounting. [Detection, owner and recovery](#cause-AttributeOwnerAccounting).
    AttributeOwnerAccounting,
    /// Attribute possession absent. [Detection, owner and recovery](#cause-AttributePossessionAbsent).
    AttributePossessionAbsent,
    /// Attribute preparation length changed. [Detection, owner and recovery](#cause-AttributePreparationLengthChanged).
    AttributePreparationLengthChanged,
    /// Attribute representation does not match conversion. [Detection, owner and recovery](#cause-AttributeRepresentationDoesNotMatchConversion).
    AttributeRepresentationDoesNotMatchConversion,
    /// Attribute request metadata allocation. [Detection, owner and recovery](#cause-AttributeRequestMetadataAllocation).
    AttributeRequestMetadataAllocation,
    /// Attribute result metadata accounting. [Detection, owner and recovery](#cause-AttributeResultMetadataAccounting).
    AttributeResultMetadataAccounting,
    /// Attribute size unavailable. [Detection, owner and recovery](#cause-AttributeSizeUnavailable).
    AttributeSizeUnavailable,
    /// Attribute source withdrawn. [Detection, owner and recovery](#cause-AttributeSourceWithdrawn).
    AttributeSourceWithdrawn,
    /// Attribute template count ceiling. [Detection, owner and recovery](#cause-AttributeTemplateCountCeiling).
    AttributeTemplateCountCeiling,
    /// Attribute template depth ceiling. [Detection, owner and recovery](#cause-AttributeTemplateDepthCeiling).
    AttributeTemplateDepthCeiling,
    /// Attribute template group count. [Detection, owner and recovery](#cause-AttributeTemplateGroupCount).
    AttributeTemplateGroupCount,
    /// Attribute template metadata accounting. [Detection, owner and recovery](#cause-AttributeTemplateMetadataAccounting).
    AttributeTemplateMetadataAccounting,
    /// Attribute template specification deferred. [Detection, owner and recovery](#cause-AttributeTemplateSpecificationDeferred).
    AttributeTemplateSpecificationDeferred,
    /// Attribute template total accounting. [Detection, owner and recovery](#cause-AttributeTemplateTotalAccounting).
    AttributeTemplateTotalAccounting,
    /// Attribute template value ceiling. [Detection, owner and recovery](#cause-AttributeTemplateValueCeiling).
    AttributeTemplateValueCeiling,
    /// Attribute traversal allocation. [Detection, owner and recovery](#cause-AttributeTraversalAllocation).
    AttributeTraversalAllocation,
    /// Attribute traversal allocation size. [Detection, owner and recovery](#cause-AttributeTraversalAllocationSize).
    AttributeTraversalAllocationSize,
    /// Attribute unsigned array width. [Detection, owner and recovery](#cause-AttributeUnsignedArrayWidth).
    AttributeUnsignedArrayWidth,
    /// Attribute unsigned width. [Detection, owner and recovery](#cause-AttributeUnsignedWidth).
    AttributeUnsignedWidth,
    /// Attribute value accounting. [Detection, owner and recovery](#cause-AttributeValueAccounting).
    AttributeValueAccounting,
    /// Attribute value allocation accounting. [Detection, owner and recovery](#cause-AttributeValueAllocationAccounting).
    AttributeValueAllocationAccounting,
    /// Attribute value count. [Detection, owner and recovery](#cause-AttributeValueCount).
    AttributeValueCount,
    /// Attribute value need absent. [Detection, owner and recovery](#cause-AttributeValueNeedAbsent).
    AttributeValueNeedAbsent,
    /// Attribute value owner absent. [Detection, owner and recovery](#cause-AttributeValueOwnerAbsent).
    AttributeValueOwnerAbsent,
    /// Attribute value unavailable. [Detection, owner and recovery](#cause-AttributeValueUnavailable).
    AttributeValueUnavailable,
    /// Attribute value witness accounting. [Detection, owner and recovery](#cause-AttributeValueWitnessAccounting).
    AttributeValueWitnessAccounting,
    /// Direct attribute batch allocation ceiling. [Detection, owner and recovery](#cause-DirectAttributeBatchAllocationCeiling).
    DirectAttributeBatchAllocationCeiling,
    /// Direct attribute unexpectedly queried. [Detection, owner and recovery](#cause-DirectAttributeUnexpectedlyQueried).
    DirectAttributeUnexpectedlyQueried,
    /// Extension attribute native identifier width. [Detection, owner and recovery](#cause-ExtensionAttributeNativeIdentifierWidth).
    ExtensionAttributeNativeIdentifierWidth,
    /// Flat attribute cannot own child descriptors. [Detection, owner and recovery](#cause-FlatAttributeCannotOwnChildDescriptors).
    FlatAttributeCannotOwnChildDescriptors,
    /// Flat input required. [Detection, owner and recovery](#cause-FlatInputRequired).
    FlatInputRequired,
    /// Known template value type missing. [Detection, owner and recovery](#cause-KnownTemplateValueTypeMissing).
    KnownTemplateValueTypeMissing,
    /// Nested attribute descriptor bytes. [Detection, owner and recovery](#cause-NestedAttributeDescriptorBytes).
    NestedAttributeDescriptorBytes,
    /// Nested attribute requires a recursive reader. [Detection, owner and recovery](#cause-NestedAttributeRequiresARecursiveReader).
    NestedAttributeRequiresARecursiveReader,
    /// Nested input requires descriptors. [Detection, owner and recovery](#cause-NestedInputRequiresDescriptors).
    NestedInputRequiresDescriptors,
    /// Protected attribute allocation. [Detection, owner and recovery](#cause-ProtectedAttributeAllocation).
    ProtectedAttributeAllocation,
    /// Root attribute is not a template. [Detection, owner and recovery](#cause-RootAttributeIsNotATemplate).
    RootAttributeIsNotATemplate,
    /// Single attribute result missing. [Detection, owner and recovery](#cause-SingleAttributeResultMissing).
    SingleAttributeResultMissing,
    /// Standard attribute layout cannot be overridden. [Detection, owner and recovery](#cause-StandardAttributeLayoutCannotBeOverridden).
    StandardAttributeLayoutCannotBeOverridden,
    /// Template allocation accounting overflow. [Detection, owner and recovery](#cause-TemplateAllocationAccountingOverflow).
    TemplateAllocationAccountingOverflow,
    /// Template descriptor pointer or capacity changed. [Detection, owner and recovery](#cause-TemplateDescriptorPointerOrCapacityChanged).
    TemplateDescriptorPointerOrCapacityChanged,
    /// Template measured child range. [Detection, owner and recovery](#cause-TemplateMeasuredChildRange).
    TemplateMeasuredChildRange,
    /// Template measured count changed. [Detection, owner and recovery](#cause-TemplateMeasuredCountChanged).
    TemplateMeasuredCountChanged,
    /// Template metadata accounting overflow. [Detection, owner and recovery](#cause-TemplateMetadataAccountingOverflow).
    TemplateMetadataAccountingOverflow,
    /// Template read completion unknown. [Detection, owner and recovery](#cause-TemplateReadCompletionUnknown).
    TemplateReadCompletionUnknown,
    /// Template read depth limit. [Detection, owner and recovery](#cause-TemplateReadDepthLimit).
    TemplateReadDepthLimit,
    /// Template read descriptor limit. [Detection, owner and recovery](#cause-TemplateReadDescriptorLimit).
    TemplateReadDescriptorLimit,
    /// Template read returned no attribute result. [Detection, owner and recovery](#cause-TemplateReadReturnedNoAttributeResult).
    TemplateReadReturnedNoAttributeResult,
    /// Template read value limit. [Detection, owner and recovery](#cause-TemplateReadValueLimit).
    TemplateReadValueLimit,
    /// Template result allocation. [Detection, owner and recovery](#cause-TemplateResultAllocation).
    TemplateResultAllocation,
    /// Template root descriptor limit. [Detection, owner and recovery](#cause-TemplateRootDescriptorLimit).
    TemplateRootDescriptorLimit,
    /// Template traversal allocation. [Detection, owner and recovery](#cause-TemplateTraversalAllocation).
    TemplateTraversalAllocation,
    /// Template value needs child descriptors. [Detection, owner and recovery](#cause-TemplateValueNeedsChildDescriptors).
    TemplateValueNeedsChildDescriptors,
    /// Validated template result could not be represented. [Detection, owner and recovery](#cause-ValidatedTemplateResultCouldNotBeRepresented).
    ValidatedTemplateResultCouldNotBeRepresented,
}

impl std::fmt::Display for AttributeValuesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CGetAttributeValueUnavailable => f.write_str("C_GetAttributeValue unavailable"),
            Self::AttributeAlignmentOverflow => f.write_str("attribute alignment overflow"),
            Self::AttributeAllocatorAccountingOverflow => {
                f.write_str("attribute allocator accounting overflow")
            }
            Self::AttributeArenaConstructionOrder => {
                f.write_str("attribute arena construction order")
            }
            Self::AttributeArenaRange => f.write_str("attribute arena range"),
            Self::AttributeArenaUnfinished => f.write_str("attribute arena unfinished"),
            Self::AttributeBatchHasUnfinishedResults => {
                f.write_str("attribute batch has unfinished results")
            }
            Self::AttributeBooleanRepresentation => f.write_str("attribute boolean representation"),
            Self::AttributeCallMetadataAccounting => {
                f.write_str("attribute call metadata accounting")
            }
            Self::AttributeCallMetadataCapacity => f.write_str("attribute call metadata capacity"),
            Self::AttributeDateWidth => f.write_str("attribute date width"),
            Self::AttributeDescriptorOrReturnedCapacityChanged => {
                f.write_str("attribute descriptor or returned capacity changed")
            }
            Self::AttributeExtensionBelongsToAnotherModuleInstance => {
                f.write_str("attribute extension belongs to another module instance")
            }
            Self::AttributeExtensionScopeExhausted => {
                f.write_str("attribute extension scope exhausted")
            }
            Self::AttributeExtensionScopeMissing => {
                f.write_str("attribute extension scope missing")
            }
            Self::AttributeFirstCallProvenanceAbsent => {
                f.write_str("attribute first-call provenance absent")
            }
            Self::AttributeInitialAllocationAccounting => {
                f.write_str("attribute initial allocation accounting")
            }
            Self::AttributeInputByteLength => f.write_str("attribute input byte length"),
            Self::AttributeInputCopyRange => f.write_str("attribute input copy range"),
            Self::AttributeInputRepresentation => f.write_str("attribute input representation"),
            Self::AttributeIntegerArraySize => f.write_str("attribute integer array size"),
            Self::AttributeIsNotAnUnsignedArray => {
                f.write_str("attribute is not an unsigned array")
            }
            Self::AttributeMetadataAccountingOverflow => {
                f.write_str("attribute metadata accounting overflow")
            }
            Self::AttributeMetadataAllocation => f.write_str("attribute metadata allocation"),
            Self::AttributeMetadataCapacity => f.write_str("attribute metadata capacity"),
            Self::AttributeMetadataSize => f.write_str("attribute metadata size"),
            Self::AttributeNativeIntegerWidth => f.write_str("attribute native integer width"),
            Self::AttributeNativeScalarWidth => f.write_str("attribute native scalar width"),
            Self::AttributeNativeSizeWidth => f.write_str("attribute native size width"),
            Self::AttributeObservationIncomplete => f.write_str("attribute observation incomplete"),
            Self::AttributeObservationOwnerAccounting => {
                f.write_str("attribute observation owner accounting")
            }
            Self::AttributeObservationPhaseUnavailable => {
                f.write_str("attribute observation phase unavailable")
            }
            Self::AttributeOwnerAccounting => f.write_str("attribute owner accounting"),
            Self::AttributePossessionAbsent => f.write_str("attribute possession absent"),
            Self::AttributePreparationLengthChanged => {
                f.write_str("attribute preparation length changed")
            }
            Self::AttributeRepresentationDoesNotMatchConversion => {
                f.write_str("attribute representation does not match conversion")
            }
            Self::AttributeRequestMetadataAllocation => {
                f.write_str("attribute request metadata allocation")
            }
            Self::AttributeResultMetadataAccounting => {
                f.write_str("attribute result metadata accounting")
            }
            Self::AttributeSizeUnavailable => f.write_str("attribute size unavailable"),
            Self::AttributeSourceWithdrawn => f.write_str("attribute source withdrawn"),
            Self::AttributeTemplateCountCeiling => f.write_str("attribute template count ceiling"),
            Self::AttributeTemplateDepthCeiling => f.write_str("attribute template depth ceiling"),
            Self::AttributeTemplateGroupCount => f.write_str("attribute template group count"),
            Self::AttributeTemplateMetadataAccounting => {
                f.write_str("attribute template metadata accounting")
            }
            Self::AttributeTemplateSpecificationDeferred => {
                f.write_str("attribute template specification deferred")
            }
            Self::AttributeTemplateTotalAccounting => {
                f.write_str("attribute template total accounting")
            }
            Self::AttributeTemplateValueCeiling => f.write_str("attribute template value ceiling"),
            Self::AttributeTraversalAllocation => f.write_str("attribute traversal allocation"),
            Self::AttributeTraversalAllocationSize => {
                f.write_str("attribute traversal allocation size")
            }
            Self::AttributeUnsignedArrayWidth => f.write_str("attribute unsigned array width"),
            Self::AttributeUnsignedWidth => f.write_str("attribute unsigned width"),
            Self::AttributeValueAccounting => f.write_str("attribute value accounting"),
            Self::AttributeValueAllocationAccounting => {
                f.write_str("attribute value allocation accounting")
            }
            Self::AttributeValueCount => f.write_str("attribute value count"),
            Self::AttributeValueNeedAbsent => f.write_str("attribute value need absent"),
            Self::AttributeValueOwnerAbsent => f.write_str("attribute value owner absent"),
            Self::AttributeValueUnavailable => f.write_str("attribute value unavailable"),
            Self::AttributeValueWitnessAccounting => {
                f.write_str("attribute value witness accounting")
            }
            Self::DirectAttributeBatchAllocationCeiling => {
                f.write_str("direct attribute batch allocation ceiling")
            }
            Self::DirectAttributeUnexpectedlyQueried => {
                f.write_str("direct attribute unexpectedly queried")
            }
            Self::ExtensionAttributeNativeIdentifierWidth => {
                f.write_str("extension attribute native identifier width")
            }
            Self::FlatAttributeCannotOwnChildDescriptors => {
                f.write_str("flat attribute cannot own child descriptors")
            }
            Self::FlatInputRequired => f.write_str("flat input required"),
            Self::KnownTemplateValueTypeMissing => f.write_str("known template value type missing"),
            Self::NestedAttributeDescriptorBytes => {
                f.write_str("nested attribute descriptor bytes")
            }
            Self::NestedAttributeRequiresARecursiveReader => {
                f.write_str("nested attribute requires a recursive reader")
            }
            Self::NestedInputRequiresDescriptors => {
                f.write_str("nested input requires descriptors")
            }
            Self::ProtectedAttributeAllocation => f.write_str("protected attribute allocation"),
            Self::RootAttributeIsNotATemplate => f.write_str("root attribute is not a template"),
            Self::SingleAttributeResultMissing => f.write_str("single attribute result missing"),
            Self::StandardAttributeLayoutCannotBeOverridden => {
                f.write_str("standard attribute layout cannot be overridden")
            }
            Self::TemplateAllocationAccountingOverflow => {
                f.write_str("template allocation accounting overflow")
            }
            Self::TemplateDescriptorPointerOrCapacityChanged => {
                f.write_str("template descriptor pointer or capacity changed")
            }
            Self::TemplateMeasuredChildRange => f.write_str("template measured child range"),
            Self::TemplateMeasuredCountChanged => f.write_str("template measured count changed"),
            Self::TemplateMetadataAccountingOverflow => {
                f.write_str("template metadata accounting overflow")
            }
            Self::TemplateReadCompletionUnknown => f.write_str("template read completion unknown"),
            Self::TemplateReadDepthLimit => f.write_str("template read depth limit"),
            Self::TemplateReadDescriptorLimit => f.write_str("template read descriptor limit"),
            Self::TemplateReadReturnedNoAttributeResult => {
                f.write_str("template read returned no attribute result")
            }
            Self::TemplateReadValueLimit => f.write_str("template read value limit"),
            Self::TemplateResultAllocation => f.write_str("template result allocation"),
            Self::TemplateRootDescriptorLimit => f.write_str("template root descriptor limit"),
            Self::TemplateTraversalAllocation => f.write_str("template traversal allocation"),
            Self::TemplateValueNeedsChildDescriptors => {
                f.write_str("template value needs child descriptors")
            }
            Self::ValidatedTemplateResultCouldNotBeRepresented => {
                f.write_str("validated template result could not be represented")
            }
        }
    }
}
