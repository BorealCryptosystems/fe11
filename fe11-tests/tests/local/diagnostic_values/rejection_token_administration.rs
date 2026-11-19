// SPDX-License-Identifier: Apache-2.0
//! Public TokenAdministrationRejection values retain identity through category conversion.
use fe11::{Error, RejectionReason, TokenAdministrationRejection};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        TokenAdministrationRejection::CGetTokenInfoUnavailable,
        TokenAdministrationRejection::CInitPINUnavailable,
        TokenAdministrationRejection::CInitTokenUnavailable,
        TokenAdministrationRejection::CSetPINUnavailable,
        TokenAdministrationRejection::AdministrativeGenerationStale,
        TokenAdministrationRejection::AdministrativeTargetIdentityOrStateChanged,
        TokenAdministrationRejection::ChangedTokenSessionsRequireClose,
        TokenAdministrationRejection::DiscoveryPublicationReportAllocation,
        TokenAdministrationRejection::ForeignAdministrativeTarget,
        TokenAdministrationRejection::NativePinInputChanged,
        TokenAdministrationRejection::NativeTokenInitializationInputChanged,
        TokenAdministrationRejection::RefreshedTokenIdentityChanged,
        TokenAdministrationRejection::TargetTokenSessionsActive,
        TokenAdministrationRejection::TokenContextReplaced,
        TokenAdministrationRejection::TokenGenerationExhausted,
        TokenAdministrationRejection::TokenLabel,
        TokenAdministrationRejection::TokenRegistryAllocation,
        TokenAdministrationRejection::TokenRegistryCapacity,
        TokenAdministrationRejection::TokenRegistryChangedAfterDiscovery,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::TokenAdministration(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::TokenAdministration(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
