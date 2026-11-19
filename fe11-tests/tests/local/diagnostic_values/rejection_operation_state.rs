// SPDX-License-Identifier: Apache-2.0
//! Public OperationStateRejection values retain identity through category conversion.
use fe11::{Error, OperationStateRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        OperationStateRejection::CGetOperationStateUnavailable,
        OperationStateRejection::CGetSessionInfoUnavailable,
        OperationStateRejection::CancelledStateCapture,
        OperationStateRejection::CaptureSessionState,
        OperationStateRejection::DuplicateStateCompletion,
        OperationStateRejection::FinalStateCaptureRequired,
        OperationStateRejection::OperationStateCeiling,
        OperationStateRejection::OperationStateSession,
        OperationStateRejection::OperationStateSessionIdentity,
        OperationStateRejection::OperationStateSessionMismatch,
        OperationStateRejection::PreparatoryStateCaptureDetachmentDeferred,
        OperationStateRejection::RestorationInputAbsent,
        OperationStateRejection::RestorationInputLength,
        OperationStateRejection::RestorationInputStillNativeOwned,
        OperationStateRejection::RestorationStateAbsent,
        OperationStateRejection::RestorationStateNotRecoverable,
        OperationStateRejection::RestorationTransferFunction,
        OperationStateRejection::RestorationTransferPhase,
        OperationStateRejection::SessionInspectionIncomplete,
        OperationStateRejection::StateIoAbsent,
        OperationStateRejection::StateIoFailed,
        OperationStateRejection::StateIoNotActive,
        OperationStateRejection::StateAlreadyConsumed,
        OperationStateRejection::StateAsynchronousOutputIdentity,
        OperationStateRejection::StateAsynchronousVersion,
        OperationStateRejection::StateCaptureAbsent,
        OperationStateRejection::StateCaptureIncomplete,
        OperationStateRejection::StateCapturePreparationChanged,
        OperationStateRejection::StateOutputAbsent,
        OperationStateRejection::StateSizeDirection,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::OperationState(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::OperationState(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
