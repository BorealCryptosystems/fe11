// SPDX-License-Identifier: Apache-2.0
//! Public ObjectPublicationRejection values retain identity through category conversion.
use fe11::{Error, ObjectPublicationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectPublicationRejection::Sp800OutputSlot,
        ObjectPublicationRejection::Sp800PublicationCapacity,
        ObjectPublicationRejection::TlsOutputSlot,
        ObjectPublicationRejection::TlsPublicationCapacity,
        ObjectPublicationRejection::TlsPublicationRole,
        ObjectPublicationRejection::DestinationByteAccounting,
        ObjectPublicationRejection::DestinationTupleAccounting,
        ObjectPublicationRejection::GenerationOutputConsumed,
        ObjectPublicationRejection::NativeAuxiliaryOutputAbsent,
        ObjectPublicationRejection::NativeCreationAlreadyDispatched,
        ObjectPublicationRejection::NativeDestinationOwner,
        ObjectPublicationRejection::NativeEffectIsNotAResourceRequest,
        ObjectPublicationRejection::NativeObjectLifetimeAbsent,
        ObjectPublicationRejection::NativeObjectsNotRegistered,
        ObjectPublicationRejection::NativeOutputAdmissionOwner,
        ObjectPublicationRejection::NativeOutputAdmissionState,
        ObjectPublicationRejection::NativeOutputCandidateKind,
        ObjectPublicationRejection::NativeOutputCompletionUnknown,
        ObjectPublicationRejection::NativeOutputContentLayout,
        ObjectPublicationRejection::NativeOutputContentOwner,
        ObjectPublicationRejection::NativeOutputContinuationChanged,
        ObjectPublicationRejection::NativeOutputDestinationIncomplete,
        ObjectPublicationRejection::NativeOutputDestinationPhase,
        ObjectPublicationRejection::NativeOutputDestinationPreparation,
        ObjectPublicationRejection::NativeOutputDestinationState,
        ObjectPublicationRejection::NativeOutputDispatchPhase,
        ObjectPublicationRejection::NativeOutputGraphSize,
        ObjectPublicationRejection::NativeOutputLifetimeAbsent,
        ObjectPublicationRejection::NativeOutputListEmpty,
        ObjectPublicationRejection::NativeOutputNeedAbsent,
        ObjectPublicationRejection::NativeOutputOperationStopped,
        ObjectPublicationRejection::NativeOutputOwnerAbsent,
        ObjectPublicationRejection::NativeOutputPossessionAbsent,
        ObjectPublicationRejection::NativeOutputPreparationAbsent,
        ObjectPublicationRejection::NativeOutputPreparationState,
        ObjectPublicationRejection::NativeOutputPublicationState,
        ObjectPublicationRejection::NativeOutputQuotaAbsent,
        ObjectPublicationRejection::NativeOutputReferenceIndex,
        ObjectPublicationRejection::NativeOutputReferenceOwner,
        ObjectPublicationRejection::NativeOutputReferencePreparation,
        ObjectPublicationRejection::NativeOutputReferenceUnavailable,
        ObjectPublicationRejection::NativeOutputRestorationState,
        ObjectPublicationRejection::NativeOutputReturnPhase,
        ObjectPublicationRejection::NativeOutputSearchOwner,
        ObjectPublicationRejection::NativeOutputSearchPhase,
        ObjectPublicationRejection::NativeOutputSlot,
        ObjectPublicationRejection::NativeOutputSlotAllocation,
        ObjectPublicationRejection::NativeOutputSlotSize,
        ObjectPublicationRejection::NativeOutputVectorKind,
        ObjectPublicationRejection::NativeOutputsIncomplete,
        ObjectPublicationRejection::NativePublicationAccounting,
        ObjectPublicationRejection::NativePublicationAllocation,
        ObjectPublicationRejection::NativePublicationCapacity,
        ObjectPublicationRejection::OutputCleanupCount,
        ObjectPublicationRejection::PairOutputSlot,
        ObjectPublicationRejection::RequestedObservationPreparationAbsent,
        ObjectPublicationRejection::RequestedObservationSelectionAbsent,
        ObjectPublicationRejection::TransportOutputConsumed,
        ObjectPublicationRejection::UnobservedNativeIdentityAbsent,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectPublication(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectPublication(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
