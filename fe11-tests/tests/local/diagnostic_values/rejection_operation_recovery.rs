// SPDX-License-Identifier: Apache-2.0
//! Public OperationRecoveryRejection values retain identity through category conversion.
use fe11::{Error, OperationRecoveryRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        OperationRecoveryRejection::CSignRecoverUnavailable,
        OperationRecoveryRejection::CSignRecoverInitUnavailable,
        OperationRecoveryRejection::CVerifyRecoverUnavailable,
        OperationRecoveryRejection::CVerifyRecoverInitUnavailable,
        OperationRecoveryRejection::RecoveryAuthenticationKeyRequired,
        OperationRecoveryRejection::RecoveryCipherKeyAbsent,
        OperationRecoveryRejection::RecoveryEmptyBatch,
        OperationRecoveryRejection::RecoveryFrameAccountingOverflow,
        OperationRecoveryRejection::RecoveryFunctionsUnavailable,
        OperationRecoveryRejection::RecoveryIsNotWaitingForStorage,
        OperationRecoveryRejection::RecoveryMechanismDoesNotMatchRequestedApi,
        OperationRecoveryRejection::RecoveryMechanismWidth,
        OperationRecoveryRejection::RecoveryNativeInputIdentity,
        OperationRecoveryRejection::RecoveryNotCapturable,
        OperationRecoveryRejection::RecoveryOperationStorageSize,
        OperationRecoveryRejection::RecoveryOutcomeUncertain,
        OperationRecoveryRejection::RecoveryOutputCapacity,
        OperationRecoveryRejection::RecoveryOutputCeiling,
        OperationRecoveryRejection::RecoveryPrefixWidth,
        OperationRecoveryRejection::RecoveryRecordDescriptor,
        OperationRecoveryRejection::RecoveryRecordFamily,
        OperationRecoveryRejection::RecoveryRecordInputAbsent,
        OperationRecoveryRejection::RecoveryRecordInputCount,
        OperationRecoveryRejection::RecoveryRecordMechanismWidth,
        OperationRecoveryRejection::RecoveryRecordOutputProfile,
        OperationRecoveryRejection::RecoveryRecordParameterContract,
        OperationRecoveryRejection::RecoveryRecordPending,
        OperationRecoveryRejection::RecoveryRecordPhase,
        OperationRecoveryRejection::RecoveryRecordPrematureObservation,
        OperationRecoveryRejection::RecoveryRecordProgression,
        OperationRecoveryRejection::RecoveryReferenceRequired,
        OperationRecoveryRejection::RecoveryReportedLengthWidth,
        OperationRecoveryRejection::RecoveryResultAlreadyPublished,
        OperationRecoveryRejection::RecoveryResultConsumed,
        OperationRecoveryRejection::RecoveryResultIncomplete,
        OperationRecoveryRejection::RecoverySnapshotShapeChanged,
        OperationRecoveryRejection::RecoveryTerminalBufferAbsent,
        OperationRecoveryRejection::RecoveryTerminalCapacity,
        OperationRecoveryRejection::RecoveryTerminalObservationAbsent,
        OperationRecoveryRejection::RecoveryTerminalOutput,
        OperationRecoveryRejection::UnexpectedRecoveryCipherKey,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::OperationRecovery(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::OperationRecovery(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
