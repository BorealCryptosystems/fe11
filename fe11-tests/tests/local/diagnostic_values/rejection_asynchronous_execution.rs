// SPDX-License-Identifier: Apache-2.0
//! Public AsynchronousExecutionRejection values retain identity through category conversion.
use fe11::{AsynchronousExecutionRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        AsynchronousExecutionRejection::CAsyncGetIDUnavailable,
        AsynchronousExecutionRejection::CAsyncJoinUnavailable,
        AsynchronousExecutionRejection::GcmMessageEncryptionDetachmentDeferred,
        AsynchronousExecutionRejection::AsynchronousIdentifierAlreadyRequested,
        AsynchronousExecutionRejection::AsynchronousInterfaceUnavailable,
        AsynchronousExecutionRejection::AsynchronousJoinAlreadyAttempted,
        AsynchronousExecutionRejection::AsynchronousJoinNotAttached,
        AsynchronousExecutionRejection::AsynchronousObjectHandles,
        AsynchronousExecutionRejection::AsynchronousRejoinFunctionsUnavailable,
        AsynchronousExecutionRejection::CaptureNativeStorageAbsent,
        AsynchronousExecutionRejection::ControlNotDetachable,
        AsynchronousExecutionRejection::DetachedCaptureCapacityAbsent,
        AsynchronousExecutionRejection::FailedJoinedFixedOutput,
        AsynchronousExecutionRejection::FailedJoinedOutput,
        AsynchronousExecutionRejection::ForeignOrConsumedRejoinTicket,
        AsynchronousExecutionRejection::GenericMessageAsynchronousModeUnavailable,
        AsynchronousExecutionRejection::JoinedAsynchronousOutputIdentity,
        AsynchronousExecutionRejection::JoinedFixedOutputAbsent,
        AsynchronousExecutionRejection::JoinedFixedOutputCapacity,
        AsynchronousExecutionRejection::JoinedFixedOutputLength,
        AsynchronousExecutionRejection::JoinedFixedResultShape,
        AsynchronousExecutionRejection::JoinedFixedResultSizeOrType,
        AsynchronousExecutionRejection::JoinedObjectResultShape,
        AsynchronousExecutionRejection::JoinedPreparedOwnerLayout,
        AsynchronousExecutionRejection::JoinedResultFunctionOrPhase,
        AsynchronousExecutionRejection::JoinedResultOutputKind,
        AsynchronousExecutionRejection::JoinedResultOutputShape,
        AsynchronousExecutionRejection::JoinedResultUnavailable,
        AsynchronousExecutionRejection::JoinedStateSizeResultShape,
        AsynchronousExecutionRejection::JoinedStorageAccounting,
        AsynchronousExecutionRejection::NativeAesAsynchronousModeUnavailable,
        AsynchronousExecutionRejection::OperationNotDetachable,
        AsynchronousExecutionRejection::OperationNotPending,
        AsynchronousExecutionRejection::RejoinAbsent,
        AsynchronousExecutionRejection::RejoinInspectionAbsent,
        AsynchronousExecutionRejection::RejoinOutputStorageAbsent,
        AsynchronousExecutionRejection::RejoinOwnerAdapterAbsent,
        AsynchronousExecutionRejection::RejoinPreparationAbsent,
        AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
        AsynchronousExecutionRejection::SignatureRecoveryAsynchronousModeUnavailable,
        AsynchronousExecutionRejection::StaleRejoinTicket,
        AsynchronousExecutionRejection::StateControlNotPending,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::AsynchronousExecution(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::AsynchronousExecution(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
