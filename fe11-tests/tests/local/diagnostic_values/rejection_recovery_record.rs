// SPDX-License-Identifier: Apache-2.0
//! Public RecoveryRecordRejection values retain identity through category conversion.
use fe11::{Error, RecoveryRecordRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        RecoveryRecordRejection::DetachedCapacityWidth,
        RecoveryRecordRejection::DetachedCaptureFunction,
        RecoveryRecordRejection::DetachedCaptureOutputCeiling,
        RecoveryRecordRejection::DetachedIdentifierWidth,
        RecoveryRecordRejection::DetachedNativeFunctionMismatch,
        RecoveryRecordRejection::DetachedNativeIdentifierWidth,
        RecoveryRecordRejection::DetachedOutputCapacityMismatch,
        RecoveryRecordRejection::DualRecoveryFamily,
        RecoveryRecordRejection::DualRecoveryHistoricalCompletion,
        RecoveryRecordRejection::DualRecoveryHistoricalObservation,
        RecoveryRecordRejection::DualRecoveryKind,
        RecoveryRecordRejection::DualRecoveryOutput,
        RecoveryRecordRejection::DualRecoveryProfile,
        RecoveryRecordRejection::DualRecoveryValidationCapacity,
        RecoveryRecordRejection::RecoveryExcessObservation,
        RecoveryRecordRejection::RecoveryFinalObservation,
        RecoveryRecordRejection::RecoveryHistoricalPrefix,
        RecoveryRecordRejection::RecoveryIdentityWidth,
        RecoveryRecordRejection::RecoveryManifestKind,
        RecoveryRecordRejection::RecoveryObservationAbsent,
        RecoveryRecordRejection::RecoveryObservationAssociation,
        RecoveryRecordRejection::RecoveryRecordKind,
        RecoveryRecordRejection::RecoveryTokenIdentity,
        RecoveryRecordRejection::RestoreCapacityWidth,
        RecoveryRecordRejection::RestoreIdentifierWidth,
        RecoveryRecordRejection::RestoreKeyEncoding,
        RecoveryRecordRejection::RestoreNativeIdentifierWidth,
        RecoveryRecordRejection::RestoreObservationSlotWidth,
        RecoveryRecordRejection::RestoreTransferCapacity,
        RecoveryRecordRejection::RestoreTransferFunction,
        RecoveryRecordRejection::RestoreTransferKeyRoles,
        RecoveryRecordRejection::RestoreTransferKind,
        RecoveryRecordRejection::TerminalObservationFunction,
        RecoveryRecordRejection::TerminalValidityCode,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::RecoveryRecord(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::RecoveryRecord(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
