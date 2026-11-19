// SPDX-License-Identifier: Apache-2.0
//! Public CancellationRejection values retain identity through category conversion.
use fe11::{CancellationRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        CancellationRejection::CSessionCancelUnavailable,
        CancellationRejection::CancellationAbsent,
        CancellationRejection::CancellationControlAbsent,
        CancellationRejection::CancellationFlagCategory,
        CancellationRejection::CancellationFlagRange,
        CancellationRejection::CancellationNotPending,
        CancellationRejection::CancellationReturnUnproven,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::Cancellation(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::Cancellation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
