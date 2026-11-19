// SPDX-License-Identifier: Apache-2.0
//! Public AuthenticationRejection values retain identity through category conversion.
use fe11::{AuthenticationRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        AuthenticationRejection::PinFrameAccounting,
        AuthenticationRejection::AuthenticationEpochChanged,
        AuthenticationRejection::AuthenticationEpochExhausted,
        AuthenticationRejection::ContextAuthenticationRequiresInitializedOperation,
        AuthenticationRejection::ForeignAuthenticationSession,
        AuthenticationRejection::ForeignOrConsumedOperationTicket,
        AuthenticationRejection::LogoutRequiresLiveSession,
        AuthenticationRejection::MissingContextualAuthentication,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::Authentication(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::Authentication(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
