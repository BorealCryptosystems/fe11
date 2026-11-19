// SPDX-License-Identifier: Apache-2.0
//! Public AttributeValuesRejection values retain identity through category conversion.
use fe11::{AttributeValuesRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        AttributeValuesRejection::CGetAttributeValueUnavailable,
        AttributeValuesRejection::AttributeAlignmentOverflow,
        AttributeValuesRejection::AttributeAllocatorAccountingOverflow,
        AttributeValuesRejection::AttributeArenaConstructionOrder,
        AttributeValuesRejection::AttributeArenaRange,
        AttributeValuesRejection::AttributeArenaUnfinished,
        AttributeValuesRejection::AttributeBatchHasUnfinishedResults,
        AttributeValuesRejection::AttributeBooleanRepresentation,
        AttributeValuesRejection::AttributeCallMetadataAccounting,
        AttributeValuesRejection::AttributeCallMetadataCapacity,
        AttributeValuesRejection::AttributeDateWidth,
        AttributeValuesRejection::AttributeDescriptorOrReturnedCapacityChanged,
        AttributeValuesRejection::AttributeExtensionBelongsToAnotherModuleInstance,
        AttributeValuesRejection::AttributeExtensionScopeExhausted,
        AttributeValuesRejection::AttributeExtensionScopeMissing,
        AttributeValuesRejection::AttributeFirstCallProvenanceAbsent,
        AttributeValuesRejection::AttributeInitialAllocationAccounting,
        AttributeValuesRejection::AttributeInputByteLength,
        AttributeValuesRejection::AttributeInputCopyRange,
        AttributeValuesRejection::AttributeInputRepresentation,
        AttributeValuesRejection::AttributeIntegerArraySize,
        AttributeValuesRejection::AttributeIsNotAnUnsignedArray,
        AttributeValuesRejection::AttributeMetadataAccountingOverflow,
        AttributeValuesRejection::AttributeMetadataAllocation,
        AttributeValuesRejection::AttributeMetadataCapacity,
        AttributeValuesRejection::AttributeMetadataSize,
        AttributeValuesRejection::AttributeNativeIntegerWidth,
        AttributeValuesRejection::AttributeNativeScalarWidth,
        AttributeValuesRejection::AttributeNativeSizeWidth,
        AttributeValuesRejection::AttributeObservationIncomplete,
        AttributeValuesRejection::AttributeObservationOwnerAccounting,
        AttributeValuesRejection::AttributeObservationPhaseUnavailable,
        AttributeValuesRejection::AttributeOwnerAccounting,
        AttributeValuesRejection::AttributePossessionAbsent,
        AttributeValuesRejection::AttributePreparationLengthChanged,
        AttributeValuesRejection::AttributeRepresentationDoesNotMatchConversion,
        AttributeValuesRejection::AttributeRequestMetadataAllocation,
        AttributeValuesRejection::AttributeResultMetadataAccounting,
        AttributeValuesRejection::AttributeSizeUnavailable,
        AttributeValuesRejection::AttributeSourceWithdrawn,
        AttributeValuesRejection::AttributeTemplateCountCeiling,
        AttributeValuesRejection::AttributeTemplateDepthCeiling,
        AttributeValuesRejection::AttributeTemplateGroupCount,
        AttributeValuesRejection::AttributeTemplateMetadataAccounting,
        AttributeValuesRejection::AttributeTemplateSpecificationDeferred,
        AttributeValuesRejection::AttributeTemplateTotalAccounting,
        AttributeValuesRejection::AttributeTemplateValueCeiling,
        AttributeValuesRejection::AttributeTraversalAllocation,
        AttributeValuesRejection::AttributeTraversalAllocationSize,
        AttributeValuesRejection::AttributeUnsignedArrayWidth,
        AttributeValuesRejection::AttributeUnsignedWidth,
        AttributeValuesRejection::AttributeValueAccounting,
        AttributeValuesRejection::AttributeValueAllocationAccounting,
        AttributeValuesRejection::AttributeValueCount,
        AttributeValuesRejection::AttributeValueNeedAbsent,
        AttributeValuesRejection::AttributeValueOwnerAbsent,
        AttributeValuesRejection::AttributeValueUnavailable,
        AttributeValuesRejection::AttributeValueWitnessAccounting,
        AttributeValuesRejection::DirectAttributeBatchAllocationCeiling,
        AttributeValuesRejection::DirectAttributeUnexpectedlyQueried,
        AttributeValuesRejection::ExtensionAttributeNativeIdentifierWidth,
        AttributeValuesRejection::FlatAttributeCannotOwnChildDescriptors,
        AttributeValuesRejection::FlatInputRequired,
        AttributeValuesRejection::KnownTemplateValueTypeMissing,
        AttributeValuesRejection::NestedAttributeDescriptorBytes,
        AttributeValuesRejection::NestedAttributeRequiresARecursiveReader,
        AttributeValuesRejection::NestedInputRequiresDescriptors,
        AttributeValuesRejection::ProtectedAttributeAllocation,
        AttributeValuesRejection::RootAttributeIsNotATemplate,
        AttributeValuesRejection::SingleAttributeResultMissing,
        AttributeValuesRejection::StandardAttributeLayoutCannotBeOverridden,
        AttributeValuesRejection::TemplateAllocationAccountingOverflow,
        AttributeValuesRejection::TemplateDescriptorPointerOrCapacityChanged,
        AttributeValuesRejection::TemplateMeasuredChildRange,
        AttributeValuesRejection::TemplateMeasuredCountChanged,
        AttributeValuesRejection::TemplateMetadataAccountingOverflow,
        AttributeValuesRejection::TemplateReadCompletionUnknown,
        AttributeValuesRejection::TemplateReadDepthLimit,
        AttributeValuesRejection::TemplateReadDescriptorLimit,
        AttributeValuesRejection::TemplateReadReturnedNoAttributeResult,
        AttributeValuesRejection::TemplateReadValueLimit,
        AttributeValuesRejection::TemplateResultAllocation,
        AttributeValuesRejection::TemplateRootDescriptorLimit,
        AttributeValuesRejection::TemplateTraversalAllocation,
        AttributeValuesRejection::TemplateValueNeedsChildDescriptors,
        AttributeValuesRejection::ValidatedTemplateResultCouldNotBeRepresented,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::AttributeValues(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::AttributeValues(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
