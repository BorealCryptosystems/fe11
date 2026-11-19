// SPDX-License-Identifier: Apache-2.0
//! Public MechanismsRejection values retain identity through category conversion.
use fe11::{Error, MechanismsRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        MechanismsRejection::ConflictingMechanismProperties,
        MechanismsRejection::MechanismCatalogueAllocation,
        MechanismsRejection::MechanismNotAnnounced,
        MechanismsRejection::MechanismRequestAllocation,
        MechanismsRejection::MechanismRequestBudget,
        MechanismsRejection::MechanismRequestByteCount,
        MechanismsRejection::MechanismRequestWidth,
        MechanismsRejection::PolicyMechanismRecipeAbsent,
        MechanismsRejection::PolicyObservationCompletionPhase,
        MechanismsRejection::PolicyObservationIncomplete,
        MechanismsRejection::PolicyObservationNeedAbsent,
        MechanismsRejection::PolicyObservationOwnerAbsent,
        MechanismsRejection::PolicyObservationPhase,
        MechanismsRejection::PolicyObservationPossessionAbsent,
        MechanismsRejection::PolicyObservationSourceChanged,
        MechanismsRejection::PolicyObservationStopped,
        MechanismsRejection::PolicyObservationStorageSize,
        MechanismsRejection::RetainedMechanismRequestSize,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::Mechanisms(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::Mechanisms(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
