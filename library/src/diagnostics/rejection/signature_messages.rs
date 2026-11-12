// SPDX-License-Identifier: Apache-2.0
//! SignatureMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to signature messages.
#[doc = include_str!("../../../docs/diagnostics/rejection-signature_messages.md")]
pub enum SignatureMessagesRejection {
    /// MAC tag size. [Detection, owner and recovery](#cause-MacTagSize).
    MacTagSize,
    /// PSS checkpoint parameter identity. [Detection, owner and recovery](#cause-PssCheckpointParameterIdentity).
    PssCheckpointParameterIdentity,
    /// PSS message mechanism mismatch. [Detection, owner and recovery](#cause-PssMessageMechanismMismatch).
    PssMessageMechanismMismatch,
    /// PSS native parameter identity. [Detection, owner and recovery](#cause-PssNativeParameterIdentity).
    PssNativeParameterIdentity,
    /// PSS snapshot parameter identity. [Detection, owner and recovery](#cause-PssSnapshotParameterIdentity).
    PssSnapshotParameterIdentity,
    /// Buffered message has stream fragment. [Detection, owner and recovery](#cause-BufferedMessageHasStreamFragment).
    BufferedMessageHasStreamFragment,
    /// Consumed message ticket. [Detection, owner and recovery](#cause-ConsumedMessageTicket).
    ConsumedMessageTicket,
    /// Current message fragment absent. [Detection, owner and recovery](#cause-CurrentMessageFragmentAbsent).
    CurrentMessageFragmentAbsent,
    /// Duplicate message completion. [Detection, owner and recovery](#cause-DuplicateMessageCompletion).
    DuplicateMessageCompletion,
    /// Finish the current message before the parent process. [Detection, owner and recovery](#cause-FinishTheCurrentMessageBeforeTheParentProcess).
    FinishTheCurrentMessageBeforeTheParentProcess,
    /// Foreign operation lease admission. [Detection, owner and recovery](#cause-ForeignOperationLeaseAdmission).
    ForeignOperationLeaseAdmission,
    /// Foreign or consumed message signature ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedMessageSignatureTicket).
    ForeignOrConsumedMessageSignatureTicket,
    /// Message HMAC key required. [Detection, owner and recovery](#cause-MessageHmacKeyRequired).
    MessageHmacKeyRequired,
    /// Message allocation. [Detection, owner and recovery](#cause-MessageAllocation).
    MessageAllocation,
    /// Message already published. [Detection, owner and recovery](#cause-MessageAlreadyPublished).
    MessageAlreadyPublished,
    /// Message asynchronous result identity. [Detection, owner and recovery](#cause-MessageAsynchronousResultIdentity).
    MessageAsynchronousResultIdentity,
    /// Message byte overflow. [Detection, owner and recovery](#cause-MessageByteOverflow).
    MessageByteOverflow,
    /// Message count. [Detection, owner and recovery](#cause-MessageCount).
    MessageCount,
    /// Message failed; explicit cleanup required. [Detection, owner and recovery](#cause-MessageFailedExplicitCleanupRequired).
    MessageFailedExplicitCleanupRequired,
    /// Message functions unavailable. [Detection, owner and recovery](#cause-MessageFunctionsUnavailable).
    MessageFunctionsUnavailable,
    /// Message input ceiling. [Detection, owner and recovery](#cause-MessageInputCeiling).
    MessageInputCeiling,
    /// Message input storage overflow. [Detection, owner and recovery](#cause-MessageInputStorageOverflow).
    MessageInputStorageOverflow,
    /// Message metadata overflow. [Detection, owner and recovery](#cause-MessageMetadataOverflow).
    MessageMetadataOverflow,
    /// Message native length width. [Detection, owner and recovery](#cause-MessageNativeLengthWidth).
    MessageNativeLengthWidth,
    /// Message native parameter identity. [Detection, owner and recovery](#cause-MessageNativeParameterIdentity).
    MessageNativeParameterIdentity,
    /// Message not active. [Detection, owner and recovery](#cause-MessageNotActive).
    MessageNotActive,
    /// Message not capturable. [Detection, owner and recovery](#cause-MessageNotCapturable).
    MessageNotCapturable,
    /// Message not complete. [Detection, owner and recovery](#cause-MessageNotComplete).
    MessageNotComplete,
    /// Message operation not joinable. [Detection, owner and recovery](#cause-MessageOperationNotJoinable).
    MessageOperationNotJoinable,
    /// Message operation storage size. [Detection, owner and recovery](#cause-MessageOperationStorageSize).
    MessageOperationStorageSize,
    /// Message output call absent. [Detection, owner and recovery](#cause-MessageOutputCallAbsent).
    MessageOutputCallAbsent,
    /// Message part overflow. [Detection, owner and recovery](#cause-MessagePartOverflow).
    MessagePartOverflow,
    /// Message prepared output width. [Detection, owner and recovery](#cause-MessagePreparedOutputWidth).
    MessagePreparedOutputWidth,
    /// Message report count overflow. [Detection, owner and recovery](#cause-MessageReportCountOverflow).
    MessageReportCountOverflow,
    /// Message result metadata. [Detection, owner and recovery](#cause-MessageResultMetadata).
    MessageResultMetadata,
    /// Message result withheld after failure. [Detection, owner and recovery](#cause-MessageResultWithheldAfterFailure).
    MessageResultWithheldAfterFailure,
    /// Message results absent. [Detection, owner and recovery](#cause-MessageResultsAbsent).
    MessageResultsAbsent,
    /// Message row count overflow. [Detection, owner and recovery](#cause-MessageRowCountOverflow).
    MessageRowCountOverflow,
    /// Message signature count. [Detection, owner and recovery](#cause-MessageSignatureCount).
    MessageSignatureCount,
    /// Message signature is not waiting for storage. [Detection, owner and recovery](#cause-MessageSignatureIsNotWaitingForStorage).
    MessageSignatureIsNotWaitingForStorage,
    /// Message signature storage absent. [Detection, owner and recovery](#cause-MessageSignatureStorageAbsent).
    MessageSignatureStorageAbsent,
    /// Message signature stream is not awaiting input. [Detection, owner and recovery](#cause-MessageSignatureStreamIsNotAwaitingInput).
    MessageSignatureStreamIsNotAwaitingInput,
    /// Message signature stream row shape. [Detection, owner and recovery](#cause-MessageSignatureStreamRowShape).
    MessageSignatureStreamRowShape,
    /// Message signature submission route. [Detection, owner and recovery](#cause-MessageSignatureSubmissionRoute).
    MessageSignatureSubmissionRoute,
    /// Message signature ticket required. [Detection, owner and recovery](#cause-MessageSignatureTicketRequired).
    MessageSignatureTicketRequired,
    /// Message signatures already published. [Detection, owner and recovery](#cause-MessageSignaturesAlreadyPublished).
    MessageSignaturesAlreadyPublished,
    /// Message snapshot accounting. [Detection, owner and recovery](#cause-MessageSnapshotAccounting).
    MessageSnapshotAccounting,
    /// Message snapshot row count. [Detection, owner and recovery](#cause-MessageSnapshotRowCount).
    MessageSnapshotRowCount,
    /// Message stream active row absent. [Detection, owner and recovery](#cause-MessageStreamActiveRowAbsent).
    MessageStreamActiveRowAbsent,
    /// Message stream capture phase. [Detection, owner and recovery](#cause-MessageStreamCapturePhase).
    MessageStreamCapturePhase,
    /// Message stream capture shape. [Detection, owner and recovery](#cause-MessageStreamCaptureShape).
    MessageStreamCaptureShape,
    /// Message stream fragment absent. [Detection, owner and recovery](#cause-MessageStreamFragmentAbsent).
    MessageStreamFragmentAbsent,
    /// Message stream reconstruction fragment. [Detection, owner and recovery](#cause-MessageStreamReconstructionFragment).
    MessageStreamReconstructionFragment,
    /// Message stream reconstruction size. [Detection, owner and recovery](#cause-MessageStreamReconstructionSize).
    MessageStreamReconstructionSize,
    /// Message stream repeated fragment. [Detection, owner and recovery](#cause-MessageStreamRepeatedFragment).
    MessageStreamRepeatedFragment,
    /// Message stream results absent. [Detection, owner and recovery](#cause-MessageStreamResultsAbsent).
    MessageStreamResultsAbsent,
    /// Message stream snapshot fragment. [Detection, owner and recovery](#cause-MessageStreamSnapshotFragment).
    MessageStreamSnapshotFragment,
    /// Message stream snapshot row. [Detection, owner and recovery](#cause-MessageStreamSnapshotRow).
    MessageStreamSnapshotRow,
    /// Message stream snapshot shape. [Detection, owner and recovery](#cause-MessageStreamSnapshotShape).
    MessageStreamSnapshotShape,
    /// Message vector allocation. [Detection, owner and recovery](#cause-MessageVectorAllocation).
    MessageVectorAllocation,
    /// Message vector storage overflow. [Detection, owner and recovery](#cause-MessageVectorStorageOverflow).
    MessageVectorStorageOverflow,
    /// Reconstruction expected signature. [Detection, owner and recovery](#cause-ReconstructionExpectedSignature).
    ReconstructionExpectedSignature,
    /// Reconstruction mechanism width. [Detection, owner and recovery](#cause-ReconstructionMechanismWidth).
    ReconstructionMechanismWidth,
    /// Reconstruction signature phase. [Detection, owner and recovery](#cause-ReconstructionSignaturePhase).
    ReconstructionSignaturePhase,
    /// Record PSS MGF absent. [Detection, owner and recovery](#cause-RecordPssMgfAbsent).
    RecordPssMgfAbsent,
    /// Record PSS MGF width. [Detection, owner and recovery](#cause-RecordPssMgfWidth).
    RecordPssMgfWidth,
    /// Record PSS hash absent. [Detection, owner and recovery](#cause-RecordPssHashAbsent).
    RecordPssHashAbsent,
    /// Record PSS hash width. [Detection, owner and recovery](#cause-RecordPssHashWidth).
    RecordPssHashWidth,
    /// Record PSS messages absent. [Detection, owner and recovery](#cause-RecordPssMessagesAbsent).
    RecordPssMessagesAbsent,
    /// Record PSS parameters. [Detection, owner and recovery](#cause-RecordPssParameters).
    RecordPssParameters,
    /// Record PSS profile. [Detection, owner and recovery](#cause-RecordPssProfile).
    RecordPssProfile,
    /// Record PSS salt absent. [Detection, owner and recovery](#cause-RecordPssSaltAbsent).
    RecordPssSaltAbsent,
    /// Record PSS salt width. [Detection, owner and recovery](#cause-RecordPssSaltWidth).
    RecordPssSaltWidth,
    /// Record mixed PSS parameters. [Detection, owner and recovery](#cause-RecordMixedPssParameters).
    RecordMixedPssParameters,
    /// Restoration authentication key required. [Detection, owner and recovery](#cause-RestorationAuthenticationKeyRequired).
    RestorationAuthenticationKeyRequired,
    /// Restore RSA reference role. [Detection, owner and recovery](#cause-RestoreRsaReferenceRole).
    RestoreRsaReferenceRole,
    /// Restore RSA size. [Detection, owner and recovery](#cause-RestoreRsaSize).
    RestoreRsaSize,
    /// Signature checkpoint shape. [Detection, owner and recovery](#cause-SignatureCheckpointShape).
    SignatureCheckpointShape,
    /// Signature checkpoint unavailable. [Detection, owner and recovery](#cause-SignatureCheckpointUnavailable).
    SignatureCheckpointUnavailable,
    /// Stale message signature ticket. [Detection, owner and recovery](#cause-StaleMessageSignatureTicket).
    StaleMessageSignatureTicket,
    /// Stale message ticket. [Detection, owner and recovery](#cause-StaleMessageTicket).
    StaleMessageTicket,
    /// Stream phase on buffered message. [Detection, owner and recovery](#cause-StreamPhaseOnBufferedMessage).
    StreamPhaseOnBufferedMessage,
    /// Unexpected restoration encryption key. [Detection, owner and recovery](#cause-UnexpectedRestorationEncryptionKey).
    UnexpectedRestorationEncryptionKey,


}

impl std::fmt::Display for SignatureMessagesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::MacTagSize => f.write_str("MAC tag size"),
            Self::PssCheckpointParameterIdentity => {
                f.write_str("PSS checkpoint parameter identity")
            }
            Self::PssMessageMechanismMismatch => f.write_str("PSS message mechanism mismatch"),
            Self::PssNativeParameterIdentity => f.write_str("PSS native parameter identity"),
            Self::PssSnapshotParameterIdentity => f.write_str("PSS snapshot parameter identity"),
            Self::BufferedMessageHasStreamFragment => {
                f.write_str("buffered message has stream fragment")
            }
            Self::ConsumedMessageTicket => f.write_str("consumed message ticket"),
            Self::CurrentMessageFragmentAbsent => f.write_str("current message fragment absent"),
            Self::DuplicateMessageCompletion => f.write_str("duplicate message completion"),
            Self::FinishTheCurrentMessageBeforeTheParentProcess => {
                f.write_str("finish the current message before the parent process")
            }
            Self::ForeignOperationLeaseAdmission => {
                f.write_str("foreign operation lease admission")
            }
            Self::ForeignOrConsumedMessageSignatureTicket => {
                f.write_str("foreign or consumed message signature ticket")
            }
            Self::MessageHmacKeyRequired => f.write_str("message HMAC key required"),
            Self::MessageAllocation => f.write_str("message allocation"),
            Self::MessageAlreadyPublished => f.write_str("message already published"),
            Self::MessageAsynchronousResultIdentity => {
                f.write_str("message asynchronous result identity")
            }
            Self::MessageByteOverflow => f.write_str("message byte overflow"),
            Self::MessageCount => f.write_str("message count"),
            Self::MessageFailedExplicitCleanupRequired => {
                f.write_str("message failed; explicit cleanup required")
            }
            Self::MessageFunctionsUnavailable => f.write_str("message functions unavailable"),
            Self::MessageInputCeiling => f.write_str("message input ceiling"),
            Self::MessageInputStorageOverflow => f.write_str("message input storage overflow"),
            Self::MessageMetadataOverflow => f.write_str("message metadata overflow"),
            Self::MessageNativeLengthWidth => f.write_str("message native length width"),
            Self::MessageNativeParameterIdentity => {
                f.write_str("message native parameter identity")
            }
            Self::MessageNotActive => f.write_str("message not active"),
            Self::MessageNotCapturable => f.write_str("message not capturable"),
            Self::MessageNotComplete => f.write_str("message not complete"),
            Self::MessageOperationNotJoinable => f.write_str("message operation not joinable"),
            Self::MessageOperationStorageSize => f.write_str("message operation storage size"),
            Self::MessageOutputCallAbsent => f.write_str("message output call absent"),
            Self::MessagePartOverflow => f.write_str("message part overflow"),
            Self::MessagePreparedOutputWidth => f.write_str("message prepared output width"),
            Self::MessageReportCountOverflow => f.write_str("message report count overflow"),
            Self::MessageResultMetadata => f.write_str("message result metadata"),
            Self::MessageResultWithheldAfterFailure => {
                f.write_str("message result withheld after failure")
            }
            Self::MessageResultsAbsent => f.write_str("message results absent"),
            Self::MessageRowCountOverflow => f.write_str("message row count overflow"),
            Self::MessageSignatureCount => f.write_str("message signature count"),
            Self::MessageSignatureIsNotWaitingForStorage => {
                f.write_str("message signature is not waiting for storage")
            }
            Self::MessageSignatureStorageAbsent => f.write_str("message signature storage absent"),
            Self::MessageSignatureStreamIsNotAwaitingInput => {
                f.write_str("message signature stream is not awaiting input")
            }
            Self::MessageSignatureStreamRowShape => {
                f.write_str("message signature stream row shape")
            }
            Self::MessageSignatureSubmissionRoute => {
                f.write_str("message signature submission route")
            }
            Self::MessageSignatureTicketRequired => {
                f.write_str("message signature ticket required")
            }
            Self::MessageSignaturesAlreadyPublished => {
                f.write_str("message signatures already published")
            }
            Self::MessageSnapshotAccounting => f.write_str("message snapshot accounting"),
            Self::MessageSnapshotRowCount => f.write_str("message snapshot row count"),
            Self::MessageStreamActiveRowAbsent => f.write_str("message stream active row absent"),
            Self::MessageStreamCapturePhase => f.write_str("message stream capture phase"),
            Self::MessageStreamCaptureShape => f.write_str("message stream capture shape"),
            Self::MessageStreamFragmentAbsent => f.write_str("message stream fragment absent"),
            Self::MessageStreamReconstructionFragment => {
                f.write_str("message stream reconstruction fragment")
            }
            Self::MessageStreamReconstructionSize => {
                f.write_str("message stream reconstruction size")
            }
            Self::MessageStreamRepeatedFragment => f.write_str("message stream repeated fragment"),
            Self::MessageStreamResultsAbsent => f.write_str("message stream results absent"),
            Self::MessageStreamSnapshotFragment => f.write_str("message stream snapshot fragment"),
            Self::MessageStreamSnapshotRow => f.write_str("message stream snapshot row"),
            Self::MessageStreamSnapshotShape => f.write_str("message stream snapshot shape"),
            Self::MessageVectorAllocation => f.write_str("message vector allocation"),
            Self::MessageVectorStorageOverflow => f.write_str("message vector storage overflow"),
            Self::ReconstructionExpectedSignature => {
                f.write_str("reconstruction expected signature")
            }
            Self::ReconstructionMechanismWidth => f.write_str("reconstruction mechanism width"),
            Self::ReconstructionSignaturePhase => f.write_str("reconstruction signature phase"),
            Self::RecordPssMgfAbsent => f.write_str("record PSS MGF absent"),
            Self::RecordPssMgfWidth => f.write_str("record PSS MGF width"),
            Self::RecordPssHashAbsent => f.write_str("record PSS hash absent"),
            Self::RecordPssHashWidth => f.write_str("record PSS hash width"),
            Self::RecordPssMessagesAbsent => f.write_str("record PSS messages absent"),
            Self::RecordPssParameters => f.write_str("record PSS parameters"),
            Self::RecordPssProfile => f.write_str("record PSS profile"),
            Self::RecordPssSaltAbsent => f.write_str("record PSS salt absent"),
            Self::RecordPssSaltWidth => f.write_str("record PSS salt width"),
            Self::RecordMixedPssParameters => f.write_str("record mixed PSS parameters"),
            Self::RestorationAuthenticationKeyRequired => {
                f.write_str("restoration authentication key required")
            }
            Self::RestoreRsaReferenceRole => f.write_str("restore RSA reference role"),
            Self::RestoreRsaSize => f.write_str("restore RSA size"),
            Self::SignatureCheckpointShape => f.write_str("signature checkpoint shape"),
            Self::SignatureCheckpointUnavailable => f.write_str("signature checkpoint unavailable"),
            Self::StaleMessageSignatureTicket => f.write_str("stale message signature ticket"),
            Self::StaleMessageTicket => f.write_str("stale message ticket"),
            Self::StreamPhaseOnBufferedMessage => f.write_str("stream phase on buffered message"),
            Self::UnexpectedRestorationEncryptionKey => {
                f.write_str("unexpected restoration encryption key")
            }
        }
    }
}
