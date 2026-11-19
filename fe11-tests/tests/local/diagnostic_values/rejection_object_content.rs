// SPDX-License-Identifier: Apache-2.0
//! Public ObjectContentRejection values retain identity through category conversion.
use fe11::{Error, ObjectContentRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectContentRejection::ContentContinuationPhase,
        ObjectContentRejection::ContentNativeDescriptorOrCapacityChanged,
        ObjectContentRejection::ContentObservationIncomplete,
        ObjectContentRejection::ContentObservationRequiresPreparedOwner,
        ObjectContentRejection::ContentObservationStorageSize,
        ObjectContentRejection::ContentOwnerAbsent,
        ObjectContentRejection::ContentPossessionAbsent,
        ObjectContentRejection::ContentPreparationChanged,
        ObjectContentRejection::ContentReadPhase,
        ObjectContentRejection::ContentSourceChanged,
        ObjectContentRejection::ContentValueNeedAbsent,
        ObjectContentRejection::FingerprintAlreadyFinished,
        ObjectContentRejection::FingerprintByteBudget,
        ObjectContentRejection::FingerprintCandidateKind,
        ObjectContentRejection::FingerprintCompletionPhase,
        ObjectContentRejection::FingerprintContinuationStopped,
        ObjectContentRejection::FingerprintDigestPreparation,
        ObjectContentRejection::FingerprintHashAccounting,
        ObjectContentRejection::FingerprintHeaderCount,
        ObjectContentRejection::FingerprintMaterialCount,
        ObjectContentRejection::FingerprintMetadataNeed,
        ObjectContentRejection::FingerprintMetadataPhase,
        ObjectContentRejection::FingerprintOwnerAbsent,
        ObjectContentRejection::FingerprintOwnerStorageSize,
        ObjectContentRejection::FingerprintPossessionAbsent,
        ObjectContentRejection::FingerprintPreparationAccounting,
        ObjectContentRejection::FingerprintPreparationChanged,
        ObjectContentRejection::FingerprintPreparationNeedAbsent,
        ObjectContentRejection::FingerprintProtectedCallPhase,
        ObjectContentRejection::FingerprintProtectedValuePhase,
        ObjectContentRejection::FingerprintPublicValuePhase,
        ObjectContentRejection::FingerprintSourceChanged,
        ObjectContentRejection::FingerprintStateAllocation,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectContent(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectContent(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
