// SPDX-License-Identifier: Apache-2.0
//! NativeMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native messages.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_messages.md")]
pub enum NativeMessagesRejection {
    /// Captured generic message requires destination binding. [Detection, owner and recovery](#cause-CapturedGenericMessageRequiresDestinationBinding).
    CapturedGenericMessageRequiresDestinationBinding,
    /// Changed generic message snapshot input. [Detection, owner and recovery](#cause-ChangedGenericMessageSnapshotInput).
    ChangedGenericMessageSnapshotInput,
    /// Foreign message preparation budget. [Detection, owner and recovery](#cause-ForeignMessagePreparationBudget).
    ForeignMessagePreparationBudget,
    /// Foreign or consumed generic message ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedGenericMessageTicket).
    ForeignOrConsumedGenericMessageTicket,
    /// Generic message continuation ticket unavailable. [Detection, owner and recovery](#cause-GenericMessageContinuationTicketUnavailable).
    GenericMessageContinuationTicketUnavailable,
    /// Generic message destination binding. [Detection, owner and recovery](#cause-GenericMessageDestinationBinding).
    GenericMessageDestinationBinding,
    /// Generic message diagnostic not used. [Detection, owner and recovery](#cause-GenericMessageDiagnosticNotUsed).
    GenericMessageDiagnosticNotUsed,
    /// Generic message facade incomplete. [Detection, owner and recovery](#cause-GenericMessageFacadeIncomplete).
    GenericMessageFacadeIncomplete,
    /// Generic message initialization binding. [Detection, owner and recovery](#cause-GenericMessageInitializationBinding).
    GenericMessageInitializationBinding,
    /// Generic message input boundary not established. [Detection, owner and recovery](#cause-GenericMessageInputBoundaryNotEstablished).
    GenericMessageInputBoundaryNotEstablished,
    /// Generic message input boundary unavailable. [Detection, owner and recovery](#cause-GenericMessageInputBoundaryUnavailable).
    GenericMessageInputBoundaryUnavailable,
    /// Generic message input mutation. [Detection, owner and recovery](#cause-GenericMessageInputMutation).
    GenericMessageInputMutation,
    /// Generic message is not waiting for output. [Detection, owner and recovery](#cause-GenericMessageIsNotWaitingForOutput).
    GenericMessageIsNotWaitingForOutput,
    /// Generic message not at a capturable boundary. [Detection, owner and recovery](#cause-GenericMessageNotAtACapturableBoundary).
    GenericMessageNotAtACapturableBoundary,
    /// Generic message output row absent. [Detection, owner and recovery](#cause-GenericMessageOutputRowAbsent).
    GenericMessageOutputRowAbsent,
    /// Generic message owner accounting. [Detection, owner and recovery](#cause-GenericMessageOwnerAccounting).
    GenericMessageOwnerAccounting,
    /// Generic message owner shape. [Detection, owner and recovery](#cause-GenericMessageOwnerShape).
    GenericMessageOwnerShape,
    /// Generic message parameter declaration mismatch. [Detection, owner and recovery](#cause-GenericMessageParameterDeclarationMismatch).
    GenericMessageParameterDeclarationMismatch,
    /// Generic message prepared output width. [Detection, owner and recovery](#cause-GenericMessagePreparedOutputWidth).
    GenericMessagePreparedOutputWidth,
    /// Generic message reconstruction. [Detection, owner and recovery](#cause-GenericMessageReconstruction).
    GenericMessageReconstruction,
    /// Generic message requires explicit cleanup. [Detection, owner and recovery](#cause-GenericMessageRequiresExplicitCleanup).
    GenericMessageRequiresExplicitCleanup,
    /// Generic message result absent. [Detection, owner and recovery](#cause-GenericMessageResultAbsent).
    GenericMessageResultAbsent,
    /// Generic message result not available. [Detection, owner and recovery](#cause-GenericMessageResultNotAvailable).
    GenericMessageResultNotAvailable,
    /// Generic message result shape. [Detection, owner and recovery](#cause-GenericMessageResultShape).
    GenericMessageResultShape,
    /// Generic message retained input mutation. [Detection, owner and recovery](#cause-GenericMessageRetainedInputMutation).
    GenericMessageRetainedInputMutation,
    /// Generic message signing output absent. [Detection, owner and recovery](#cause-GenericMessageSigningOutputAbsent).
    GenericMessageSigningOutputAbsent,
    /// Generic message snapshot shape. [Detection, owner and recovery](#cause-GenericMessageSnapshotShape).
    GenericMessageSnapshotShape,
    /// Generic message start accounting. [Detection, owner and recovery](#cause-GenericMessageStartAccounting).
    GenericMessageStartAccounting,
    /// Generic message stream is not awaiting input. [Detection, owner and recovery](#cause-GenericMessageStreamIsNotAwaitingInput).
    GenericMessageStreamIsNotAwaitingInput,
    /// Generic message submission accounting. [Detection, owner and recovery](#cause-GenericMessageSubmissionAccounting).
    GenericMessageSubmissionAccounting,
    /// Generic message submission route. [Detection, owner and recovery](#cause-GenericMessageSubmissionRoute).
    GenericMessageSubmissionRoute,
    /// Generic message terminal operands. [Detection, owner and recovery](#cause-GenericMessageTerminalOperands).
    GenericMessageTerminalOperands,
    /// Generic message ticket already transferred. [Detection, owner and recovery](#cause-GenericMessageTicketAlreadyTransferred).
    GenericMessageTicketAlreadyTransferred,
    /// Generic message ticket required. [Detection, owner and recovery](#cause-GenericMessageTicketRequired).
    GenericMessageTicketRequired,
    /// Generic result accounting. [Detection, owner and recovery](#cause-GenericResultAccounting).
    GenericResultAccounting,
    /// Message native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-MessageAsynchronousModeUnavailable).
    MessageAsynchronousModeUnavailable,
    /// Message output already submitted. [Detection, owner and recovery](#cause-MessageOutputAlreadySubmitted).
    MessageOutputAlreadySubmitted,
    /// Message parameter mechanism mismatch. [Detection, owner and recovery](#cause-MessageParameterMechanismMismatch).
    MessageParameterMechanismMismatch,
    /// Message part count overflow. [Detection, owner and recovery](#cause-MessagePartCountOverflow).
    MessagePartCountOverflow,
    /// Message primary binding absent. [Detection, owner and recovery](#cause-MessagePrimaryBindingAbsent).
    MessagePrimaryBindingAbsent,
    /// Message signature not completed. [Detection, owner and recovery](#cause-MessageSignatureNotCompleted).
    MessageSignatureNotCompleted,
    /// Message signature output offset. [Detection, owner and recovery](#cause-MessageSignatureOutputOffset).
    MessageSignatureOutputOffset,
    /// Message signature result extent. [Detection, owner and recovery](#cause-MessageSignatureResultExtent).
    MessageSignatureResultExtent,
    /// Message write requires its declared writer. [Detection, owner and recovery](#cause-MessageWriteRequiresItsDeclaredWriter).
    MessageWriteRequiresItsDeclaredWriter,
    /// Revoked message auxiliary key. [Detection, owner and recovery](#cause-RevokedMessageAuxiliaryKey).
    RevokedMessageAuxiliaryKey,
    /// Stale generic message ticket. [Detection, owner and recovery](#cause-StaleGenericMessageTicket).
    StaleGenericMessageTicket,
}

impl std::fmt::Display for NativeMessagesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapturedGenericMessageRequiresDestinationBinding => {
                f.write_str("captured generic message requires destination binding")
            }
            Self::ChangedGenericMessageSnapshotInput => {
                f.write_str("changed generic message snapshot input")
            }
            Self::ForeignMessagePreparationBudget => {
                f.write_str("foreign message preparation budget")
            }
            Self::ForeignOrConsumedGenericMessageTicket => {
                f.write_str("foreign or consumed generic message ticket")
            }
            Self::GenericMessageContinuationTicketUnavailable => {
                f.write_str("generic message continuation ticket unavailable")
            }
            Self::GenericMessageDestinationBinding => {
                f.write_str("generic message destination binding")
            }
            Self::GenericMessageDiagnosticNotUsed => {
                f.write_str("generic message diagnostic not used")
            }
            Self::GenericMessageFacadeIncomplete => {
                f.write_str("generic message facade incomplete")
            }
            Self::GenericMessageInitializationBinding => {
                f.write_str("generic message initialization binding")
            }
            Self::GenericMessageInputBoundaryNotEstablished => {
                f.write_str("generic message input boundary not established")
            }
            Self::GenericMessageInputBoundaryUnavailable => {
                f.write_str("generic message input boundary unavailable")
            }
            Self::GenericMessageInputMutation => f.write_str("generic message input mutation"),
            Self::GenericMessageIsNotWaitingForOutput => {
                f.write_str("generic message is not waiting for output")
            }
            Self::GenericMessageNotAtACapturableBoundary => {
                f.write_str("generic message not at a capturable boundary")
            }
            Self::GenericMessageOutputRowAbsent => f.write_str("generic message output row absent"),
            Self::GenericMessageOwnerAccounting => f.write_str("generic message owner accounting"),
            Self::GenericMessageOwnerShape => f.write_str("generic message owner shape"),
            Self::GenericMessageParameterDeclarationMismatch => {
                f.write_str("generic message parameter declaration mismatch")
            }
            Self::GenericMessagePreparedOutputWidth => {
                f.write_str("generic message prepared output width")
            }
            Self::GenericMessageReconstruction => f.write_str("generic message reconstruction"),
            Self::GenericMessageRequiresExplicitCleanup => {
                f.write_str("generic message requires explicit cleanup")
            }
            Self::GenericMessageResultAbsent => f.write_str("generic message result absent"),
            Self::GenericMessageResultNotAvailable => {
                f.write_str("generic message result not available")
            }
            Self::GenericMessageResultShape => f.write_str("generic message result shape"),
            Self::GenericMessageRetainedInputMutation => {
                f.write_str("generic message retained input mutation")
            }
            Self::GenericMessageSigningOutputAbsent => {
                f.write_str("generic message signing output absent")
            }
            Self::GenericMessageSnapshotShape => f.write_str("generic message snapshot shape"),
            Self::GenericMessageStartAccounting => f.write_str("generic message start accounting"),
            Self::GenericMessageStreamIsNotAwaitingInput => {
                f.write_str("generic message stream is not awaiting input")
            }
            Self::GenericMessageSubmissionAccounting => {
                f.write_str("generic message submission accounting")
            }
            Self::GenericMessageSubmissionRoute => f.write_str("generic message submission route"),
            Self::GenericMessageTerminalOperands => {
                f.write_str("generic message terminal operands")
            }
            Self::GenericMessageTicketAlreadyTransferred => {
                f.write_str("generic message ticket already transferred")
            }
            Self::GenericMessageTicketRequired => f.write_str("generic message ticket required"),
            Self::GenericResultAccounting => f.write_str("generic result accounting"),
            Self::MessageAsynchronousModeUnavailable => {
                f.write_str("message native asynchronous mode is unsupported")
            }
            Self::MessageOutputAlreadySubmitted => f.write_str("message output already submitted"),
            Self::MessageParameterMechanismMismatch => {
                f.write_str("message parameter mechanism mismatch")
            }
            Self::MessagePartCountOverflow => f.write_str("message part count overflow"),
            Self::MessagePrimaryBindingAbsent => f.write_str("message primary binding absent"),
            Self::MessageSignatureNotCompleted => f.write_str("message signature not completed"),
            Self::MessageSignatureOutputOffset => f.write_str("message signature output offset"),
            Self::MessageSignatureResultExtent => f.write_str("message signature result extent"),
            Self::MessageWriteRequiresItsDeclaredWriter => {
                f.write_str("message write requires its declared writer")
            }
            Self::RevokedMessageAuxiliaryKey => f.write_str("revoked message auxiliary key"),
            Self::StaleGenericMessageTicket => f.write_str("stale generic message ticket"),
        }
    }
}
