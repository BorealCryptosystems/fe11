// SPDX-License-Identifier: Apache-2.0
//! AsynchronousExecution causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to asynchronous execution.
#[doc = include_str!("../../../docs/diagnostics/rejection-asynchronous_execution.md")]
pub enum AsynchronousExecutionRejection {
    /// C_AsyncGetID unavailable. [Detection, owner and recovery](#cause-CAsyncGetIDUnavailable).
    CAsyncGetIDUnavailable,
    /// C_AsyncJoin unavailable. [Detection, owner and recovery](#cause-CAsyncJoinUnavailable).
    CAsyncJoinUnavailable,
    /// GCM message encryption detachment deferred. [Detection, owner and recovery](#cause-GcmMessageEncryptionDetachmentDeferred).
    GcmMessageEncryptionDetachmentDeferred,
    /// Asynchronous identifier already requested. [Detection, owner and recovery](#cause-AsynchronousIdentifierAlreadyRequested).
    AsynchronousIdentifierAlreadyRequested,
    /// Asynchronous interface unavailable. [Detection, owner and recovery](#cause-AsynchronousInterfaceUnavailable).
    AsynchronousInterfaceUnavailable,
    /// Asynchronous join already attempted. [Detection, owner and recovery](#cause-AsynchronousJoinAlreadyAttempted).
    AsynchronousJoinAlreadyAttempted,
    /// Asynchronous join not attached. [Detection, owner and recovery](#cause-AsynchronousJoinNotAttached).
    AsynchronousJoinNotAttached,
    /// Asynchronous object handles. [Detection, owner and recovery](#cause-AsynchronousObjectHandles).
    AsynchronousObjectHandles,
    /// Asynchronous rejoin functions unavailable. [Detection, owner and recovery](#cause-AsynchronousRejoinFunctionsUnavailable).
    AsynchronousRejoinFunctionsUnavailable,
    /// Capture native storage absent. [Detection, owner and recovery](#cause-CaptureNativeStorageAbsent).
    CaptureNativeStorageAbsent,
    /// Control not detachable. [Detection, owner and recovery](#cause-ControlNotDetachable).
    ControlNotDetachable,
    /// Detached capture capacity absent. [Detection, owner and recovery](#cause-DetachedCaptureCapacityAbsent).
    DetachedCaptureCapacityAbsent,
    /// Failed joined fixed output. [Detection, owner and recovery](#cause-FailedJoinedFixedOutput).
    FailedJoinedFixedOutput,
    /// Failed joined output. [Detection, owner and recovery](#cause-FailedJoinedOutput).
    FailedJoinedOutput,
    /// Foreign or consumed rejoin ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedRejoinTicket).
    ForeignOrConsumedRejoinTicket,
    /// Generic message native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-GenericMessageAsynchronousModeUnavailable).
    GenericMessageAsynchronousModeUnavailable,
    /// Joined asynchronous output identity. [Detection, owner and recovery](#cause-JoinedAsynchronousOutputIdentity).
    JoinedAsynchronousOutputIdentity,
    /// Joined fixed output absent. [Detection, owner and recovery](#cause-JoinedFixedOutputAbsent).
    JoinedFixedOutputAbsent,
    /// Joined fixed output capacity. [Detection, owner and recovery](#cause-JoinedFixedOutputCapacity).
    JoinedFixedOutputCapacity,
    /// Joined fixed output length. [Detection, owner and recovery](#cause-JoinedFixedOutputLength).
    JoinedFixedOutputLength,
    /// Joined fixed result shape. [Detection, owner and recovery](#cause-JoinedFixedResultShape).
    JoinedFixedResultShape,
    /// Joined fixed result size or type. [Detection, owner and recovery](#cause-JoinedFixedResultSizeOrType).
    JoinedFixedResultSizeOrType,
    /// Joined object result shape. [Detection, owner and recovery](#cause-JoinedObjectResultShape).
    JoinedObjectResultShape,
    /// Joined prepared owner layout. [Detection, owner and recovery](#cause-JoinedPreparedOwnerLayout).
    JoinedPreparedOwnerLayout,
    /// Joined result function or phase. [Detection, owner and recovery](#cause-JoinedResultFunctionOrPhase).
    JoinedResultFunctionOrPhase,
    /// Joined result output kind. [Detection, owner and recovery](#cause-JoinedResultOutputKind).
    JoinedResultOutputKind,
    /// Joined result output shape. [Detection, owner and recovery](#cause-JoinedResultOutputShape).
    JoinedResultOutputShape,
    /// Joined result unavailable. [Detection, owner and recovery](#cause-JoinedResultUnavailable).
    JoinedResultUnavailable,
    /// Joined state size result shape. [Detection, owner and recovery](#cause-JoinedStateSizeResultShape).
    JoinedStateSizeResultShape,
    /// Joined storage accounting. [Detection, owner and recovery](#cause-JoinedStorageAccounting).
    JoinedStorageAccounting,
    /// Native AES native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-NativeAesAsynchronousModeUnavailable).
    NativeAesAsynchronousModeUnavailable,
    /// Operation not detachable. [Detection, owner and recovery](#cause-OperationNotDetachable).
    OperationNotDetachable,
    /// Operation not pending. [Detection, owner and recovery](#cause-OperationNotPending).
    OperationNotPending,
    /// Rejoin absent. [Detection, owner and recovery](#cause-RejoinAbsent).
    RejoinAbsent,
    /// Rejoin inspection absent. [Detection, owner and recovery](#cause-RejoinInspectionAbsent).
    RejoinInspectionAbsent,
    /// Rejoin output storage absent. [Detection, owner and recovery](#cause-RejoinOutputStorageAbsent).
    RejoinOutputStorageAbsent,
    /// Rejoin owner adapter absent. [Detection, owner and recovery](#cause-RejoinOwnerAdapterAbsent).
    RejoinOwnerAdapterAbsent,
    /// Rejoin preparation absent. [Detection, owner and recovery](#cause-RejoinPreparationAbsent).
    RejoinPreparationAbsent,
    /// Signature native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-SignatureAsynchronousModeUnavailable).
    SignatureAsynchronousModeUnavailable,
    /// Signature recovery native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-SignatureRecoveryAsynchronousModeUnavailable).
    SignatureRecoveryAsynchronousModeUnavailable,
    /// Stale rejoin ticket. [Detection, owner and recovery](#cause-StaleRejoinTicket).
    StaleRejoinTicket,
    /// State control not pending. [Detection, owner and recovery](#cause-StateControlNotPending).
    StateControlNotPending,

}

impl std::fmt::Display for AsynchronousExecutionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::CAsyncGetIDUnavailable => f.write_str("C_AsyncGetID unavailable"),
            Self::CAsyncJoinUnavailable => f.write_str("C_AsyncJoin unavailable"),
            Self::GcmMessageEncryptionDetachmentDeferred => {
                f.write_str("GCM message encryption detachment deferred")
            }
            Self::AsynchronousIdentifierAlreadyRequested => {
                f.write_str("asynchronous identifier already requested")
            }
            Self::AsynchronousInterfaceUnavailable => {
                f.write_str("asynchronous interface unavailable")
            }
            Self::AsynchronousJoinAlreadyAttempted => {
                f.write_str("asynchronous join already attempted")
            }
            Self::AsynchronousJoinNotAttached => f.write_str("asynchronous join not attached"),
            Self::AsynchronousObjectHandles => f.write_str("asynchronous object handles"),
            Self::AsynchronousRejoinFunctionsUnavailable => {
                f.write_str("asynchronous rejoin functions unavailable")
            }
            Self::CaptureNativeStorageAbsent => f.write_str("capture native storage absent"),
            Self::ControlNotDetachable => f.write_str("control not detachable"),
            Self::DetachedCaptureCapacityAbsent => f.write_str("detached capture capacity absent"),
            Self::FailedJoinedFixedOutput => f.write_str("failed joined fixed output"),
            Self::FailedJoinedOutput => f.write_str("failed joined output"),
            Self::ForeignOrConsumedRejoinTicket => f.write_str("foreign or consumed rejoin ticket"),
            Self::GenericMessageAsynchronousModeUnavailable => {
                f.write_str("generic message native asynchronous mode is unsupported")
            }
            Self::JoinedAsynchronousOutputIdentity => {
                f.write_str("joined asynchronous output identity")
            }
            Self::JoinedFixedOutputAbsent => f.write_str("joined fixed output absent"),
            Self::JoinedFixedOutputCapacity => f.write_str("joined fixed output capacity"),
            Self::JoinedFixedOutputLength => f.write_str("joined fixed output length"),
            Self::JoinedFixedResultShape => f.write_str("joined fixed result shape"),
            Self::JoinedFixedResultSizeOrType => f.write_str("joined fixed result size or type"),
            Self::JoinedObjectResultShape => f.write_str("joined object result shape"),
            Self::JoinedPreparedOwnerLayout => f.write_str("joined prepared owner layout"),
            Self::JoinedResultFunctionOrPhase => f.write_str("joined result function or phase"),
            Self::JoinedResultOutputKind => f.write_str("joined result output kind"),
            Self::JoinedResultOutputShape => f.write_str("joined result output shape"),
            Self::JoinedResultUnavailable => f.write_str("joined result unavailable"),
            Self::JoinedStateSizeResultShape => f.write_str("joined state size result shape"),
            Self::JoinedStorageAccounting => f.write_str("joined storage accounting"),
            Self::NativeAesAsynchronousModeUnavailable => {
                f.write_str("native AES native asynchronous mode is unsupported")
            }
            Self::OperationNotDetachable => f.write_str("operation not detachable"),
            Self::OperationNotPending => f.write_str("operation not pending"),
            Self::RejoinAbsent => f.write_str("rejoin absent"),
            Self::RejoinInspectionAbsent => f.write_str("rejoin inspection absent"),
            Self::RejoinOutputStorageAbsent => f.write_str("rejoin output storage absent"),
            Self::RejoinOwnerAdapterAbsent => f.write_str("rejoin owner adapter absent"),
            Self::RejoinPreparationAbsent => f.write_str("rejoin preparation absent"),
            Self::SignatureAsynchronousModeUnavailable => {
                f.write_str("signature native asynchronous mode is unsupported")
            }
            Self::SignatureRecoveryAsynchronousModeUnavailable => {
                f.write_str("signature recovery native asynchronous mode is unsupported")
            }
            Self::StaleRejoinTicket => f.write_str("stale rejoin ticket"),
            Self::StateControlNotPending => f.write_str("state control not pending"),
        }
    }
}
