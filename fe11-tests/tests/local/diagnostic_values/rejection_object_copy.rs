// SPDX-License-Identifier: Apache-2.0
//! Public ObjectCopyRejection values retain identity through category conversion.
use fe11::{Error, ObjectCopyRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectCopyRejection::CCopyObjectUnavailable,
        ObjectCopyRejection::CopyAdmissionPhase,
        ObjectCopyRejection::CopyAdmissionPreparationAbsent,
        ObjectCopyRejection::CopyAlreadyDispatched,
        ObjectCopyRejection::CopyCandidateKind,
        ObjectCopyRejection::CopyCompletionPhase,
        ObjectCopyRejection::CopyContinuationChanged,
        ObjectCopyRejection::CopyDestinationClass,
        ObjectCopyRejection::CopyDestinationPhase,
        ObjectCopyRejection::CopyDestinationPreparationAbsent,
        ObjectCopyRejection::CopyDiagnosticsAlreadyConsumed,
        ObjectCopyRejection::CopyIncomplete,
        ObjectCopyRejection::CopyInputChanged,
        ObjectCopyRejection::CopyMetadataPhase,
        ObjectCopyRejection::CopyNativeLifetimeAbsent,
        ObjectCopyRejection::CopyOutputAbsent,
        ObjectCopyRejection::CopyOwnerAbsent,
        ObjectCopyRejection::CopyPossessionAbsent,
        ObjectCopyRejection::CopyPublicationQuotaAbsent,
        ObjectCopyRejection::CopyPublicationQuotaTransferred,
        ObjectCopyRejection::CopyReferencePhase,
        ObjectCopyRejection::CopyResourceNeedAbsent,
        ObjectCopyRejection::CopyReturnedInvalidIdentity,
        ObjectCopyRejection::CopyStopped,
        ObjectCopyRejection::CopyStorageSize,
        ObjectCopyRejection::CopyTemplateRecipeKind,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectCopy(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectCopy(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
