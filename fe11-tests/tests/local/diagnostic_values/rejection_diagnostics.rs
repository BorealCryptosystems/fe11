// SPDX-License-Identifier: Apache-2.0
//! Public DiagnosticsRejection values retain identity through category conversion.
use fe11::{DiagnosticsRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        DiagnosticsRejection::CleanupCauseNotUsed,
        DiagnosticsRejection::CleanupFailureNotUsed,
        DiagnosticsRejection::CleanupMarkerAllocation,
        DiagnosticsRejection::CleanupMarkerNotUsed,
        DiagnosticsRejection::CleanupNotDispatched,
        DiagnosticsRejection::CleanupStorageAccounting,
        DiagnosticsRejection::CompletionDiagnosticAlreadyConsumed,
        DiagnosticsRejection::CompletionDiagnosticNotUsed,
        DiagnosticsRejection::CompletionStorageAlreadyConsumed,
        DiagnosticsRejection::PrimaryFailureNotUsed,
        DiagnosticsRejection::SecondaryFailureNotUsed,
        DiagnosticsRejection::SequenceCauseNotUsed,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::Diagnostics(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::Diagnostics(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
