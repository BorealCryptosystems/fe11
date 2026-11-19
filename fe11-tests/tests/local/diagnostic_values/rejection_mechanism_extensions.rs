// SPDX-License-Identifier: Apache-2.0
//! Public MechanismExtensionsRejection values retain identity through category conversion.
use fe11::{Error, MechanismExtensionsRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        MechanismExtensionsRejection::NullExtensionParameterCannotOwnUnreachableBlocks,
        MechanismExtensionsRejection::RatchetMechanismFunctionMismatch,
        MechanismExtensionsRejection::ChangedGraphCannotBeCaptured,
        MechanismExtensionsRejection::ChangedMessageInitialization,
        MechanismExtensionsRejection::ChangedParameterGraphCannotBeRebound,
        MechanismExtensionsRejection::ChangedRetainedExtensionGraph,
        MechanismExtensionsRejection::DigestExtensionHasNoContextualKeyAuthentication,
        MechanismExtensionsRejection::DigestExtensionHasNoKey,
        MechanismExtensionsRejection::ExtensionAlignedAllocation,
        MechanismExtensionsRejection::ExtensionAllocationLayout,
        MechanismExtensionsRejection::ExtensionBlockAlignment,
        MechanismExtensionsRejection::ExtensionCallAllocationAccounting,
        MechanismExtensionsRejection::ExtensionDiagnosticRouteChanged,
        MechanismExtensionsRejection::ExtensionGraphMetadataAllocation,
        MechanismExtensionsRejection::ExtensionGraphRangeOrOverlap,
        MechanismExtensionsRejection::ExtensionInitializationInputMutation,
        MechanismExtensionsRejection::ExtensionInputLengthOverflow,
        MechanismExtensionsRejection::ExtensionInputMutationDuringAuthentication,
        MechanismExtensionsRejection::ExtensionInputRouteChanged,
        MechanismExtensionsRejection::ExtensionMechanismAbiWidth,
        MechanismExtensionsRejection::ExtensionNativeInputMutation,
        MechanismExtensionsRejection::ExtensionOutputExceedsCapacity,
        MechanismExtensionsRejection::ExtensionPointerPlaceholderMustBeZero,
        MechanismExtensionsRejection::ExtensionUpdateInputMutation,
        MechanismExtensionsRejection::GraphSnapshotAbiOrVersion,
        MechanismExtensionsRejection::GraphValidationIndexAllocation,
        MechanismExtensionsRejection::GraphValidationIndexCapacity,
        MechanismExtensionsRejection::KeyTransportNativeInputOrOutputCapacityViolation,
        MechanismExtensionsRejection::KeyTransportReturnedAuxiliarySourceHandle,
        MechanismExtensionsRejection::KeyTransportReturnedSourceHandle,
        MechanismExtensionsRejection::KeyTransportStorageAccounting,
        MechanismExtensionsRejection::MechanismExtensionModuleFunctionMismatch,
        MechanismExtensionsRejection::NativeAlignedOutputAccounting,
        MechanismExtensionsRejection::NativeOutputAlignment,
        MechanismExtensionsRejection::NativeOutputAlignmentUnavailable,
        MechanismExtensionsRejection::NestedMechanismGraphAccounting,
        MechanismExtensionsRejection::NestedMechanismParentHasNoRoot,
        MechanismExtensionsRejection::SingleMessageFacadeResultShape,
        MechanismExtensionsRejection::TransportInputAccounting,
        MechanismExtensionsRejection::TypedParameterKeyBinding,
        MechanismExtensionsRejection::TypedSignaturePublicationRoute,
        MechanismExtensionsRejection::WrapAggregateStorageAccounting,
        MechanismExtensionsRejection::WrapFrameStorageAccounting,
        MechanismExtensionsRejection::WrapNativeInputChanged,
        MechanismExtensionsRejection::WrapRevocationStorageAccounting,
        MechanismExtensionsRejection::WrapStorageAccounting,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::MechanismExtensions(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::MechanismExtensions(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
