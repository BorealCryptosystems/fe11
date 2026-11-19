// SPDX-License-Identifier: Apache-2.0
//! Public ObjectCleanupRejection values retain identity through category conversion.
use fe11::{Error, ObjectCleanupRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectCleanupRejection::AbandonedReaderSnapshotAllocation,
        ObjectCleanupRejection::CoordinationVectorStorageAccounting,
        ObjectCleanupRejection::CreatorActivityCount,
        ObjectCleanupRejection::CreatorCloseBudgetOwner,
        ObjectCleanupRejection::CreatorCloseCapacityNotPrepared,
        ObjectCleanupRejection::CreatorClosePreparationAlreadyPresent,
        ObjectCleanupRejection::CreatorCloseTicketExhausted,
        ObjectCleanupRejection::CreatorParticipantCount,
        ObjectCleanupRejection::CreatorParticipantReservationExhausted,
        ObjectCleanupRejection::CreatorReservationCount,
        ObjectCleanupRejection::CreatorSnapshotAllocation,
        ObjectCleanupRejection::ForeignCreatorCloseCredit,
        ObjectCleanupRejection::ForeignCreatorClosePreparation,
        ObjectCleanupRejection::MutationCleanupOwnerAbsent,
        ObjectCleanupRejection::ReferenceCloseStorageAccounting,
        ObjectCleanupRejection::UnknownCreatorCloseAbsent,
        ObjectCleanupRejection::UnknownCreatorCloseAllocation,
        ObjectCleanupRejection::UnknownCreatorCloseCount,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectCleanup(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectCleanup(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
