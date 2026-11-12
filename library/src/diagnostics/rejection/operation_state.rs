// SPDX-License-Identifier: Apache-2.0
//! OperationState causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation state.
#[doc = include_str!("../../../docs/diagnostics/rejection-operation_state.md")]
pub enum OperationStateRejection {
    /// C_GetOperationState unavailable. [Detection, owner and recovery](#cause-CGetOperationStateUnavailable).
    CGetOperationStateUnavailable,
    /// C_GetSessionInfo unavailable. [Detection, owner and recovery](#cause-CGetSessionInfoUnavailable).
    CGetSessionInfoUnavailable,
    /// Cancelled state capture. [Detection, owner and recovery](#cause-CancelledStateCapture).
    CancelledStateCapture,
    /// Capture session state. [Detection, owner and recovery](#cause-CaptureSessionState).
    CaptureSessionState,
    /// Duplicate state completion. [Detection, owner and recovery](#cause-DuplicateStateCompletion).
    DuplicateStateCompletion,
    /// Final state capture required. [Detection, owner and recovery](#cause-FinalStateCaptureRequired).
    FinalStateCaptureRequired,
    /// Operation state ceiling. [Detection, owner and recovery](#cause-OperationStateCeiling).
    OperationStateCeiling,
    /// Operation state session. [Detection, owner and recovery](#cause-OperationStateSession).
    OperationStateSession,
    /// Operation state session identity. [Detection, owner and recovery](#cause-OperationStateSessionIdentity).
    OperationStateSessionIdentity,
    /// Operation state session mismatch. [Detection, owner and recovery](#cause-OperationStateSessionMismatch).
    OperationStateSessionMismatch,
    /// Preparatory state capture detachment deferred. [Detection, owner and recovery](#cause-PreparatoryStateCaptureDetachmentDeferred).
    PreparatoryStateCaptureDetachmentDeferred,
    /// Restoration input absent. [Detection, owner and recovery](#cause-RestorationInputAbsent).
    RestorationInputAbsent,
    /// Restoration input length. [Detection, owner and recovery](#cause-RestorationInputLength).
    RestorationInputLength,
    /// Restoration input still native owned. [Detection, owner and recovery](#cause-RestorationInputStillNativeOwned).
    RestorationInputStillNativeOwned,
    /// Restoration state absent. [Detection, owner and recovery](#cause-RestorationStateAbsent).
    RestorationStateAbsent,
    /// Restoration state not recoverable. [Detection, owner and recovery](#cause-RestorationStateNotRecoverable).
    RestorationStateNotRecoverable,
    /// Restoration transfer function. [Detection, owner and recovery](#cause-RestorationTransferFunction).
    RestorationTransferFunction,
    /// Restoration transfer phase. [Detection, owner and recovery](#cause-RestorationTransferPhase).
    RestorationTransferPhase,
    /// Session inspection incomplete. [Detection, owner and recovery](#cause-SessionInspectionIncomplete).
    SessionInspectionIncomplete,
    /// State IO absent. [Detection, owner and recovery](#cause-StateIoAbsent).
    StateIoAbsent,
    /// State IO failed. [Detection, owner and recovery](#cause-StateIoFailed).
    StateIoFailed,
    /// State IO not active. [Detection, owner and recovery](#cause-StateIoNotActive).
    StateIoNotActive,
    /// State already consumed. [Detection, owner and recovery](#cause-StateAlreadyConsumed).
    StateAlreadyConsumed,
    /// State asynchronous output identity. [Detection, owner and recovery](#cause-StateAsynchronousOutputIdentity).
    StateAsynchronousOutputIdentity,
    /// State asynchronous version. [Detection, owner and recovery](#cause-StateAsynchronousVersion).
    StateAsynchronousVersion,
    /// State capture absent. [Detection, owner and recovery](#cause-StateCaptureAbsent).
    StateCaptureAbsent,
    /// State capture incomplete. [Detection, owner and recovery](#cause-StateCaptureIncomplete).
    StateCaptureIncomplete,
    /// State capture preparation changed. [Detection, owner and recovery](#cause-StateCapturePreparationChanged).
    StateCapturePreparationChanged,
    /// State output absent. [Detection, owner and recovery](#cause-StateOutputAbsent).
    StateOutputAbsent,
    /// State size direction. [Detection, owner and recovery](#cause-StateSizeDirection).
    StateSizeDirection,

}

impl std::fmt::Display for OperationStateRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::CGetOperationStateUnavailable => f.write_str("C_GetOperationState unavailable"),
            Self::CGetSessionInfoUnavailable => f.write_str("C_GetSessionInfo unavailable"),
            Self::CancelledStateCapture => f.write_str("cancelled state capture"),
            Self::CaptureSessionState => f.write_str("capture session state"),
            Self::DuplicateStateCompletion => f.write_str("duplicate state completion"),
            Self::FinalStateCaptureRequired => f.write_str("final state capture required"),
            Self::OperationStateCeiling => f.write_str("operation state ceiling"),
            Self::OperationStateSession => f.write_str("operation state session"),
            Self::OperationStateSessionIdentity => f.write_str("operation state session identity"),
            Self::OperationStateSessionMismatch => f.write_str("operation state session mismatch"),
            Self::PreparatoryStateCaptureDetachmentDeferred => {
                f.write_str("preparatory state capture detachment deferred")
            }
            Self::RestorationInputAbsent => f.write_str("restoration input absent"),
            Self::RestorationInputLength => f.write_str("restoration input length"),
            Self::RestorationInputStillNativeOwned => {
                f.write_str("restoration input still native owned")
            }
            Self::RestorationStateAbsent => f.write_str("restoration state absent"),
            Self::RestorationStateNotRecoverable => {
                f.write_str("restoration state not recoverable")
            }
            Self::RestorationTransferFunction => f.write_str("restoration transfer function"),
            Self::RestorationTransferPhase => f.write_str("restoration transfer phase"),
            Self::SessionInspectionIncomplete => f.write_str("session inspection incomplete"),
            Self::StateIoAbsent => f.write_str("state IO absent"),
            Self::StateIoFailed => f.write_str("state IO failed"),
            Self::StateIoNotActive => f.write_str("state IO not active"),
            Self::StateAlreadyConsumed => f.write_str("state already consumed"),
            Self::StateAsynchronousOutputIdentity => {
                f.write_str("state asynchronous output identity")
            }
            Self::StateAsynchronousVersion => f.write_str("state asynchronous version"),
            Self::StateCaptureAbsent => f.write_str("state capture absent"),
            Self::StateCaptureIncomplete => f.write_str("state capture incomplete"),
            Self::StateCapturePreparationChanged => {
                f.write_str("state capture preparation changed")
            }
            Self::StateOutputAbsent => f.write_str("state output absent"),
            Self::StateSizeDirection => f.write_str("state size direction"),
        }
    }
}
