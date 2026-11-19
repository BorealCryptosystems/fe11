// SPDX-License-Identifier: Apache-2.0
//! Public ObjectDestinationRejection values retain identity through category conversion.
use fe11::{Error, ObjectDestinationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectDestinationRejection::DestinationCardinalityWidth,
        ObjectDestinationRejection::DestinationCompletionPhase,
        ObjectDestinationRejection::DestinationContinuationPhase,
        ObjectDestinationRejection::DestinationIncomplete,
        ObjectDestinationRejection::DestinationObservationRequiresPreparedOwner,
        ObjectDestinationRejection::DestinationPreparationAlreadyBound,
        ObjectDestinationRejection::DestinationPreparationAlreadyConsumed,
        ObjectDestinationRejection::DestinationProtectionAbsent,
        ObjectDestinationRejection::DestinationQueryReachedLocalReport,
        ObjectDestinationRejection::DestinationSearchPreparationAbsent,
        ObjectDestinationRejection::DestinationStorageSize,
        ObjectDestinationRejection::UnrequestedDestinationCount,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectDestination(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectDestination(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
