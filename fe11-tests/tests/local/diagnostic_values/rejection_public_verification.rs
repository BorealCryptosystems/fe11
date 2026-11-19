// SPDX-License-Identifier: Apache-2.0
//! Public PublicVerificationRejection values retain identity through category conversion.
use fe11::{Error, PublicVerificationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        PublicVerificationRejection::CCreateObjectUnavailable,
        PublicVerificationRejection::EcPointEncoding,
        PublicVerificationRejection::EddsaInstanceAndKeyCurveDiffer,
        PublicVerificationRejection::EdwardsPointEncoding,
        PublicVerificationRejection::MessageRsaVerificationKeyRequired,
        PublicVerificationRejection::NotAnEdwardsReference,
        PublicVerificationRejection::PublicSpkiDer,
        PublicVerificationRejection::PublicVerificationInputAllocation,
        PublicVerificationRejection::PublicVerificationOwnerSize,
        PublicVerificationRejection::VerificationEngineNotSelected,
        PublicVerificationRejection::VerificationEngineRequestFailed,
        PublicVerificationRejection::VerificationIdentityAlreadyObserved,
        PublicVerificationRejection::VerificationMaterialRequiresPublicIdentity,
        PublicVerificationRejection::VerificationPublicObservationIncomplete,
        PublicVerificationRejection::VerificationPublicationAbsent,
        PublicVerificationRejection::VerificationPublicationAllocation,
        PublicVerificationRejection::VerificationPublicationAlreadyTransferred,
        PublicVerificationRejection::VerificationPublicationSize,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::PublicVerification(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::PublicVerification(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
