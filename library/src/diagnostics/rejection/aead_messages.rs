// SPDX-License-Identifier: Apache-2.0
//! AeadMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to aead messages.
#[doc = include_str!("../../../docs/diagnostics/rejection-aead_messages.md")]
pub enum AeadMessagesRejection {
    /// AEAD Init descriptor mutation. [Detection, owner and recovery](#cause-AeadInitDescriptorMutation).
    AeadInitDescriptorMutation,
    /// AEAD Init has no parameters. [Detection, owner and recovery](#cause-AeadInitHasNoParameters).
    AeadInitHasNoParameters,
    /// AEAD Init seed absent. [Detection, owner and recovery](#cause-AeadInitSeedAbsent).
    AeadInitSeedAbsent,
    /// AEAD Init selection/representation. [Detection, owner and recovery](#cause-AeadInitSelectionRepresentation).
    AeadInitSelectionRepresentation,
    /// AEAD Init tag representation. [Detection, owner and recovery](#cause-AeadInitTagRepresentation).
    AeadInitTagRepresentation,
    /// AEAD caller-fed refusal. [Detection, owner and recovery](#cause-AeadCallerFedRefusal).
    AeadCallerFedRefusal,
    /// AEAD caller-fed stream required. [Detection, owner and recovery](#cause-AeadCallerFedStreamRequired).
    AeadCallerFedStreamRequired,
    /// AEAD capacity restore outputs. [Detection, owner and recovery](#cause-AeadCapacityRestoreOutputs).
    AeadCapacityRestoreOutputs,
    /// AEAD capacity restore prefix. [Detection, owner and recovery](#cause-AeadCapacityRestorePrefix).
    AeadCapacityRestorePrefix,
    /// AEAD capacity restore row. [Detection, owner and recovery](#cause-AeadCapacityRestoreRow).
    AeadCapacityRestoreRow,
    /// AEAD compatibility output length. [Detection, owner and recovery](#cause-AeadCompatibilityOutputLength).
    AeadCompatibilityOutputLength,
    /// AEAD diagnostic not used. [Detection, owner and recovery](#cause-AeadDiagnosticNotUsed).
    AeadDiagnosticNotUsed,
    /// AEAD final tag representation. [Detection, owner and recovery](#cause-AeadFinalTagRepresentation).
    AeadFinalTagRepresentation,
    /// AEAD fixed bits ABI width. [Detection, owner and recovery](#cause-AeadFixedBitsAbiWidth).
    AeadFixedBitsAbiWidth,
    /// AEAD input ceiling. [Detection, owner and recovery](#cause-AeadInputCeiling).
    AeadInputCeiling,
    /// AEAD input metadata overflow. [Detection, owner and recovery](#cause-AeadInputMetadataOverflow).
    AeadInputMetadataOverflow,
    /// AEAD input size overflow. [Detection, owner and recovery](#cause-AeadInputSizeOverflow).
    AeadInputSizeOverflow,
    /// AEAD invocation diagnostics already installed. [Detection, owner and recovery](#cause-AeadInvocationDiagnosticsAlreadyInstalled).
    AeadInvocationDiagnosticsAlreadyInstalled,
    /// AEAD is not waiting for storage. [Detection, owner and recovery](#cause-AeadIsNotWaitingForStorage).
    AeadIsNotWaitingForStorage,
    /// AEAD mechanism mutation. [Detection, owner and recovery](#cause-AeadMechanismMutation).
    AeadMechanismMutation,
    /// AEAD message Init input bytes mutation. [Detection, owner and recovery](#cause-AeadMessageInitInputBytesMutation).
    AeadMessageInitInputBytesMutation,
    /// AEAD message already published. [Detection, owner and recovery](#cause-AeadMessageAlreadyPublished).
    AeadMessageAlreadyPublished,
    /// AEAD message asynchronous output identity. [Detection, owner and recovery](#cause-AeadMessageAsynchronousOutputIdentity).
    AeadMessageAsynchronousOutputIdentity,
    /// AEAD message batch ceiling. [Detection, owner and recovery](#cause-AeadMessageBatchCeiling).
    AeadMessageBatchCeiling,
    /// AEAD message decrypt nonce mutation. [Detection, owner and recovery](#cause-AeadMessageDecryptNonceMutation).
    AeadMessageDecryptNonceMutation,
    /// AEAD message decrypt parameters. [Detection, owner and recovery](#cause-AeadMessageDecryptParameters).
    AeadMessageDecryptParameters,
    /// AEAD message failed; explicit cleanup required. [Detection, owner and recovery](#cause-AeadMessageFailedExplicitCleanupRequired).
    AeadMessageFailedExplicitCleanupRequired,
    /// AEAD message generated fixed bits mutation. [Detection, owner and recovery](#cause-AeadMessageGeneratedFixedBitsMutation).
    AeadMessageGeneratedFixedBitsMutation,
    /// AEAD message generated nonce changed. [Detection, owner and recovery](#cause-AeadMessageGeneratedNonceChanged).
    AeadMessageGeneratedNonceChanged,
    /// AEAD message generated nonce length. [Detection, owner and recovery](#cause-AeadMessageGeneratedNonceLength).
    AeadMessageGeneratedNonceLength,
    /// AEAD message input overflow. [Detection, owner and recovery](#cause-AeadMessageInputOverflow).
    AeadMessageInputOverflow,
    /// AEAD message key reference/selection. [Detection, owner and recovery](#cause-AeadMessageKeyReferenceSelection).
    AeadMessageKeyReferenceSelection,
    /// AEAD message length overflow. [Detection, owner and recovery](#cause-AeadMessageLengthOverflow).
    AeadMessageLengthOverflow,
    /// AEAD message mechanism. [Detection, owner and recovery](#cause-AeadMessageMechanism).
    AeadMessageMechanism,
    /// AEAD message message checkpoint unavailable. [Detection, owner and recovery](#cause-AeadMessageMessageCheckpointUnavailable).
    AeadMessageMessageCheckpointUnavailable,
    /// AEAD message message count. [Detection, owner and recovery](#cause-AeadMessageMessageCount).
    AeadMessageMessageCount,
    /// AEAD message message functions unavailable. [Detection, owner and recovery](#cause-AeadMessageMessageFunctionsUnavailable).
    AeadMessageMessageFunctionsUnavailable,
    /// AEAD message native tag mutation. [Detection, owner and recovery](#cause-AeadMessageNativeTagMutation).
    AeadMessageNativeTagMutation,
    /// AEAD message not active. [Detection, owner and recovery](#cause-AeadMessageNotActive).
    AeadMessageNotActive,
    /// AEAD message not capturable. [Detection, owner and recovery](#cause-AeadMessageNotCapturable).
    AeadMessageNotCapturable,
    /// AEAD message not complete. [Detection, owner and recovery](#cause-AeadMessageNotComplete).
    AeadMessageNotComplete,
    /// AEAD message operation not joinable. [Detection, owner and recovery](#cause-AeadMessageOperationNotJoinable).
    AeadMessageOperationNotJoinable,
    /// AEAD message output progression. [Detection, owner and recovery](#cause-AeadMessageOutputProgression).
    AeadMessageOutputProgression,
    /// AEAD message output shape. [Detection, owner and recovery](#cause-AeadMessageOutputShape).
    AeadMessageOutputShape,
    /// AEAD message outputs absent. [Detection, owner and recovery](#cause-AeadMessageOutputsAbsent).
    AeadMessageOutputsAbsent,
    /// AEAD message part overflow. [Detection, owner and recovery](#cause-AeadMessagePartOverflow).
    AeadMessagePartOverflow,
    /// AEAD message provided nonce mutation. [Detection, owner and recovery](#cause-AeadMessageProvidedNonceMutation).
    AeadMessageProvidedNonceMutation,
    /// AEAD message result withheld after failure. [Detection, owner and recovery](#cause-AeadMessageResultWithheldAfterFailure).
    AeadMessageResultWithheldAfterFailure,
    /// AEAD message selection/tag representation. [Detection, owner and recovery](#cause-AeadMessageSelectionTagRepresentation).
    AeadMessageSelectionTagRepresentation,
    /// AEAD message ticket unavailable. [Detection, owner and recovery](#cause-AeadMessageTicketUnavailable).
    AeadMessageTicketUnavailable,
    /// AEAD message unexpected generated nonce. [Detection, owner and recovery](#cause-AeadMessageUnexpectedGeneratedNonce).
    AeadMessageUnexpectedGeneratedNonce,
    /// AEAD native length width. [Detection, owner and recovery](#cause-AeadNativeLengthWidth).
    AeadNativeLengthWidth,
    /// AEAD native parameter identity. [Detection, owner and recovery](#cause-AeadNativeParameterIdentity).
    AeadNativeParameterIdentity,
    /// AEAD output already published. [Detection, owner and recovery](#cause-AeadOutputAlreadyPublished).
    AeadOutputAlreadyPublished,
    /// AEAD output call absent. [Detection, owner and recovery](#cause-AeadOutputCallAbsent).
    AeadOutputCallAbsent,
    /// AEAD output capacity overflow. [Detection, owner and recovery](#cause-AeadOutputCapacityOverflow).
    AeadOutputCapacityOverflow,
    /// AEAD output still referenced by pending call. [Detection, owner and recovery](#cause-AeadOutputStillReferencedByPendingCall).
    AeadOutputStillReferencedByPendingCall,
    /// AEAD outputs absent. [Detection, owner and recovery](#cause-AeadOutputsAbsent).
    AeadOutputsAbsent,
    /// AEAD prepared message index. [Detection, owner and recovery](#cause-AeadPreparedMessageIndex).
    AeadPreparedMessageIndex,
    /// AEAD prepared output width. [Detection, owner and recovery](#cause-AeadPreparedOutputWidth).
    AeadPreparedOutputWidth,
    /// AEAD queued fragment count. [Detection, owner and recovery](#cause-AeadQueuedFragmentCount).
    AeadQueuedFragmentCount,
    /// AEAD queued fragment width. [Detection, owner and recovery](#cause-AeadQueuedFragmentWidth).
    AeadQueuedFragmentWidth,
    /// AEAD queued input transition. [Detection, owner and recovery](#cause-AeadQueuedInputTransition).
    AeadQueuedInputTransition,
    /// AEAD queued row absent. [Detection, owner and recovery](#cause-AeadQueuedRowAbsent).
    AeadQueuedRowAbsent,
    /// AEAD recorded fixed bits. [Detection, owner and recovery](#cause-AeadRecordedFixedBits).
    AeadRecordedFixedBits,
    /// AEAD recorded generator. [Detection, owner and recovery](#cause-AeadRecordedGenerator).
    AeadRecordedGenerator,
    /// AEAD recorded initial nonce. [Detection, owner and recovery](#cause-AeadRecordedInitialNonce).
    AeadRecordedInitialNonce,
    /// AEAD refusal phase. [Detection, owner and recovery](#cause-AeadRefusalPhase).
    AeadRefusalPhase,
    /// AEAD report count overflow. [Detection, owner and recovery](#cause-AeadReportCountOverflow).
    AeadReportCountOverflow,
    /// AEAD result metadata overflow. [Detection, owner and recovery](#cause-AeadResultMetadataOverflow).
    AeadResultMetadataOverflow,
    /// AEAD retained output range. [Detection, owner and recovery](#cause-AeadRetainedOutputRange).
    AeadRetainedOutputRange,
    /// AEAD retirement allocation. [Detection, owner and recovery](#cause-AeadRetirementAllocation).
    AeadRetirementAllocation,
    /// AEAD retirement metadata overflow. [Detection, owner and recovery](#cause-AeadRetirementMetadataOverflow).
    AeadRetirementMetadataOverflow,
    /// AEAD retirement pool absent. [Detection, owner and recovery](#cause-AeadRetirementPoolAbsent).
    AeadRetirementPoolAbsent,
    /// AEAD retirement slot absent. [Detection, owner and recovery](#cause-AeadRetirementSlotAbsent).
    AeadRetirementSlotAbsent,
    /// AEAD retirement storage overflow. [Detection, owner and recovery](#cause-AeadRetirementStorageOverflow).
    AeadRetirementStorageOverflow,
    /// AEAD returned input not retired. [Detection, owner and recovery](#cause-AeadReturnedInputNotRetired).
    AeadReturnedInputNotRetired,
    /// AEAD returned storage not retired. [Detection, owner and recovery](#cause-AeadReturnedStorageNotRetired).
    AeadReturnedStorageNotRetired,
    /// AEAD row count overflow. [Detection, owner and recovery](#cause-AeadRowCountOverflow).
    AeadRowCountOverflow,
    /// AEAD shared Init descriptor mutation. [Detection, owner and recovery](#cause-AeadSharedInitDescriptorMutation).
    AeadSharedInitDescriptorMutation,
    /// AEAD snapshot Init index. [Detection, owner and recovery](#cause-AeadSnapshotInitIndex).
    AeadSnapshotInitIndex,
    /// AEAD snapshot accounting. [Detection, owner and recovery](#cause-AeadSnapshotAccounting).
    AeadSnapshotAccounting,
    /// AEAD snapshot allocation. [Detection, owner and recovery](#cause-AeadSnapshotAllocation).
    AeadSnapshotAllocation,
    /// AEAD snapshot shape changed. [Detection, owner and recovery](#cause-AeadSnapshotShapeChanged).
    AeadSnapshotShapeChanged,
    /// AEAD snapshot tag shape changed. [Detection, owner and recovery](#cause-AeadSnapshotTagShapeChanged).
    AeadSnapshotTagShapeChanged,
    /// AEAD storage already bound. [Detection, owner and recovery](#cause-AeadStorageAlreadyBound).
    AeadStorageAlreadyBound,
    /// AEAD storage not bound. [Detection, owner and recovery](#cause-AeadStorageNotBound).
    AeadStorageNotBound,
    /// AEAD storage overflow. [Detection, owner and recovery](#cause-AeadStorageOverflow).
    AeadStorageOverflow,
    /// AEAD storage shape changed. [Detection, owner and recovery](#cause-AeadStorageShapeChanged).
    AeadStorageShapeChanged,
    /// AEAD stream Init capture pending. [Detection, owner and recovery](#cause-AeadStreamInitCapturePending).
    AeadStreamInitCapturePending,
    /// AEAD stream checkpoint boundary. [Detection, owner and recovery](#cause-AeadStreamCheckpointBoundary).
    AeadStreamCheckpointBoundary,
    /// AEAD stream fragment absent. [Detection, owner and recovery](#cause-AeadStreamFragmentAbsent).
    AeadStreamFragmentAbsent,
    /// AEAD stream is not awaiting input. [Detection, owner and recovery](#cause-AeadStreamIsNotAwaitingInput).
    AeadStreamIsNotAwaitingInput,
    /// AEAD stream reconstruction. [Detection, owner and recovery](#cause-AeadStreamReconstruction).
    AeadStreamReconstruction,
    /// AEAD stream refusal phase. [Detection, owner and recovery](#cause-AeadStreamRefusalPhase).
    AeadStreamRefusalPhase,
    /// AEAD stream row shape. [Detection, owner and recovery](#cause-AeadStreamRowShape).
    AeadStreamRowShape,
    /// AEAD stream snapshot shape changed. [Detection, owner and recovery](#cause-AeadStreamSnapshotShapeChanged).
    AeadStreamSnapshotShapeChanged,
    /// AEAD submission route. [Detection, owner and recovery](#cause-AeadSubmissionRoute).
    AeadSubmissionRoute,
    /// AEAD table allocation. [Detection, owner and recovery](#cause-AeadTableAllocation).
    AeadTableAllocation,
    /// AEAD table size overflow. [Detection, owner and recovery](#cause-AeadTableSizeOverflow).
    AeadTableSizeOverflow,
    /// AEAD ticket already transferred. [Detection, owner and recovery](#cause-AeadTicketAlreadyTransferred).
    AeadTicketAlreadyTransferred,
    /// CCM MAC length. [Detection, owner and recovery](#cause-CcmMacLength).
    CcmMacLength,
    /// CCM generator ABI width. [Detection, owner and recovery](#cause-CcmGeneratorAbiWidth).
    CcmGeneratorAbiWidth,
    /// CCM recorded MAC alignment. [Detection, owner and recovery](#cause-CcmRecordedMacAlignment).
    CcmRecordedMacAlignment,
    /// CCM retained selection accounting. [Detection, owner and recovery](#cause-CcmRetainedSelectionAccounting).
    CcmRetainedSelectionAccounting,
    /// Message result exceeds admitted capacity. [Detection, owner and recovery](#cause-MessageResultExceedsAdmittedCapacity).
    MessageResultExceedsAdmittedCapacity,
    /// Message result length overflow. [Detection, owner and recovery](#cause-MessageResultLengthOverflow).
    MessageResultLengthOverflow,
    /// Caller-fed AEAD stream required. [Detection, owner and recovery](#cause-CallerFedAeadStreamRequired).
    CallerFedAeadStreamRequired,
    /// Checkpoint GCM result range. [Detection, owner and recovery](#cause-CheckpointGcmResultRange).
    CheckpointGcmResultRange,
    /// Checkpoint generated nonce unknown. [Detection, owner and recovery](#cause-CheckpointGeneratedNonceUnknown).
    CheckpointGeneratedNonceUnknown,
    /// Consumed AEAD message ticket. [Detection, owner and recovery](#cause-ConsumedAeadMessageTicket).
    ConsumedAeadMessageTicket,
    /// Declared GCM Init descriptor mutation. [Detection, owner and recovery](#cause-DeclaredGcmInitDescriptorMutation).
    DeclaredGcmInitDescriptorMutation,
    /// Declared GCM Init dispatch. [Detection, owner and recovery](#cause-DeclaredGcmInitDispatch).
    DeclaredGcmInitDispatch,
    /// Declared GCM native key reference. [Detection, owner and recovery](#cause-DeclaredGcmNativeKeyReference).
    DeclaredGcmNativeKeyReference,
    /// Declared GCM result ownership. [Detection, owner and recovery](#cause-DeclaredGcmResultOwnership).
    DeclaredGcmResultOwnership,
    /// Declared Init has no standard seed. [Detection, owner and recovery](#cause-DeclaredInitHasNoStandardSeed).
    DeclaredInitHasNoStandardSeed,
    /// Decryption tag absent. [Detection, owner and recovery](#cause-DecryptionTagAbsent).
    DecryptionTagAbsent,
    /// Duplicate GCM completion. [Detection, owner and recovery](#cause-DuplicateGcmCompletion).
    DuplicateGcmCompletion,
    /// Empty AEAD message sequence. [Detection, owner and recovery](#cause-EmptyAeadMessageSequence).
    EmptyAeadMessageSequence,
    /// Empty stream AEAD sequence. [Detection, owner and recovery](#cause-EmptyStreamAeadSequence).
    EmptyStreamAeadSequence,
    /// Finish AEAD message before its parent. [Detection, owner and recovery](#cause-FinishAeadMessageBeforeItsParent).
    FinishAeadMessageBeforeItsParent,
    /// Foreign GCM message declaration. [Detection, owner and recovery](#cause-ForeignGcmMessageDeclaration).
    ForeignGcmMessageDeclaration,
    /// Foreign or consumed AEAD stream ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedAeadStreamTicket).
    ForeignOrConsumedAeadStreamTicket,
    /// Foreign or consumed AEAD ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedAeadTicket).
    ForeignOrConsumedAeadTicket,
    /// Message extension mechanism ABI width. [Detection, owner and recovery](#cause-MessageExtensionMechanismAbiWidth).
    MessageExtensionMechanismAbiWidth,
    /// Message interface unavailable. [Detection, owner and recovery](#cause-MessageInterfaceUnavailable).
    MessageInterfaceUnavailable,
    /// Mixed AEAD message mechanisms. [Detection, owner and recovery](#cause-MixedAeadMessageMechanisms).
    MixedAeadMessageMechanisms,
    /// Mixed AEAD message selections. [Detection, owner and recovery](#cause-MixedAeadMessageSelections).
    MixedAeadMessageSelections,
    /// Queued AEAD capacity call. [Detection, owner and recovery](#cause-QueuedAeadCapacityCall).
    QueuedAeadCapacityCall,
    /// Reconstruction AAD. [Detection, owner and recovery](#cause-ReconstructionAad).
    ReconstructionAad,
    /// Reconstruction GCM phase. [Detection, owner and recovery](#cause-ReconstructionGcmPhase).
    ReconstructionGcmPhase,
    /// Reconstruction MAC. [Detection, owner and recovery](#cause-ReconstructionMac).
    ReconstructionMac,
    /// Reconstruction nonce width. [Detection, owner and recovery](#cause-ReconstructionNonceWidth).
    ReconstructionNonceWidth,
    /// Reconstruction tag. [Detection, owner and recovery](#cause-ReconstructionTag).
    ReconstructionTag,
    /// Reconstruction tag width. [Detection, owner and recovery](#cause-ReconstructionTagWidth).
    ReconstructionTagWidth,
    /// Record GCM Init layout changed within sequence. [Detection, owner and recovery](#cause-RecordGcmInitLayoutChangedWithinSequence).
    RecordGcmInitLayoutChangedWithinSequence,
    /// Recovery requires AEAD message decryption. [Detection, owner and recovery](#cause-RecoveryRequiresAeadMessageDecryption).
    RecoveryRequiresAeadMessageDecryption,
    /// Single AEAD request count. [Detection, owner and recovery](#cause-SingleAeadRequestCount).
    SingleAeadRequestCount,
    /// Single Message result count. [Detection, owner and recovery](#cause-SingleMessageResultCount).
    SingleMessageResultCount,
    /// Stale AEAD message owner. [Detection, owner and recovery](#cause-StaleAeadMessageOwner).
    StaleAeadMessageOwner,
    /// Stale AEAD stream ticket. [Detection, owner and recovery](#cause-StaleAeadStreamTicket).
    StaleAeadStreamTicket,
    /// Stale AEAD ticket. [Detection, owner and recovery](#cause-StaleAeadTicket).
    StaleAeadTicket,
    /// Stream AEAD MessageInit has no parameters. [Detection, owner and recovery](#cause-StreamAeadMessageinitHasNoParameters).
    StreamAeadMessageinitHasNoParameters,
    /// Stream AEAD initial nonce absent. [Detection, owner and recovery](#cause-StreamAeadInitialNonceAbsent).
    StreamAeadInitialNonceAbsent,
    /// Stream AEAD record scalar selection. [Detection, owner and recovery](#cause-StreamAeadRecordScalarSelection).
    StreamAeadRecordScalarSelection,
    /// Synchronous Message facade requires synchronous session. [Detection, owner and recovery](#cause-SynchronousMessageFacadeRequiresSynchronousSession).
    SynchronousMessageFacadeRequiresSynchronousSession,
    /// Synchronous Message sequence did not complete. [Detection, owner and recovery](#cause-SynchronousMessageSequenceDidNotComplete).
    SynchronousMessageSequenceDidNotComplete,
    /// Unexpected restoration authentication key. [Detection, owner and recovery](#cause-UnexpectedRestorationAuthenticationKey).
    UnexpectedRestorationAuthenticationKey,
    /// Validation report length. [Detection, owner and recovery](#cause-ValidationReportLength).
    ValidationReportLength,


}

impl std::fmt::Display for AeadMessagesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AeadInitDescriptorMutation => f.write_str("AEAD Init descriptor mutation"),
            Self::AeadInitHasNoParameters => f.write_str("AEAD Init has no parameters"),
            Self::AeadInitSeedAbsent => f.write_str("AEAD Init seed absent"),
            Self::AeadInitSelectionRepresentation => {
                f.write_str("AEAD Init selection/representation")
            }
            Self::AeadInitTagRepresentation => f.write_str("AEAD Init tag representation"),
            Self::AeadCallerFedRefusal => f.write_str("AEAD caller-fed refusal"),
            Self::AeadCallerFedStreamRequired => f.write_str("AEAD caller-fed stream required"),
            Self::AeadCapacityRestoreOutputs => f.write_str("AEAD capacity restore outputs"),
            Self::AeadCapacityRestorePrefix => f.write_str("AEAD capacity restore prefix"),
            Self::AeadCapacityRestoreRow => f.write_str("AEAD capacity restore row"),
            Self::AeadCompatibilityOutputLength => f.write_str("AEAD compatibility output length"),
            Self::AeadDiagnosticNotUsed => f.write_str("AEAD diagnostic not used"),
            Self::AeadFinalTagRepresentation => f.write_str("AEAD final tag representation"),
            Self::AeadFixedBitsAbiWidth => f.write_str("AEAD fixed bits ABI width"),
            Self::AeadInputCeiling => f.write_str("AEAD input ceiling"),
            Self::AeadInputMetadataOverflow => f.write_str("AEAD input metadata overflow"),
            Self::AeadInputSizeOverflow => f.write_str("AEAD input size overflow"),
            Self::AeadInvocationDiagnosticsAlreadyInstalled => {
                f.write_str("AEAD invocation diagnostics already installed")
            }
            Self::AeadIsNotWaitingForStorage => f.write_str("AEAD is not waiting for storage"),
            Self::AeadMechanismMutation => f.write_str("AEAD mechanism mutation"),
            Self::AeadMessageInitInputBytesMutation => {
                f.write_str("AEAD message Init input bytes mutation")
            }
            Self::AeadMessageAlreadyPublished => f.write_str("AEAD message already published"),
            Self::AeadMessageAsynchronousOutputIdentity => {
                f.write_str("AEAD message asynchronous output identity")
            }
            Self::AeadMessageBatchCeiling => f.write_str("AEAD message batch ceiling"),
            Self::AeadMessageDecryptNonceMutation => {
                f.write_str("AEAD message decrypt nonce mutation")
            }
            Self::AeadMessageDecryptParameters => f.write_str("AEAD message decrypt parameters"),
            Self::AeadMessageFailedExplicitCleanupRequired => {
                f.write_str("AEAD message failed; explicit cleanup required")
            }
            Self::AeadMessageGeneratedFixedBitsMutation => {
                f.write_str("AEAD message generated fixed bits mutation")
            }
            Self::AeadMessageGeneratedNonceChanged => {
                f.write_str("AEAD message generated nonce changed")
            }
            Self::AeadMessageGeneratedNonceLength => {
                f.write_str("AEAD message generated nonce length")
            }
            Self::AeadMessageInputOverflow => f.write_str("AEAD message input overflow"),
            Self::AeadMessageKeyReferenceSelection => {
                f.write_str("AEAD message key reference/selection")
            }
            Self::AeadMessageLengthOverflow => f.write_str("AEAD message length overflow"),
            Self::AeadMessageMechanism => f.write_str("AEAD message mechanism"),
            Self::AeadMessageMessageCheckpointUnavailable => {
                f.write_str("AEAD message message checkpoint unavailable")
            }
            Self::AeadMessageMessageCount => f.write_str("AEAD message message count"),
            Self::AeadMessageMessageFunctionsUnavailable => {
                f.write_str("AEAD message message functions unavailable")
            }
            Self::AeadMessageNativeTagMutation => f.write_str("AEAD message native tag mutation"),
            Self::AeadMessageNotActive => f.write_str("AEAD message not active"),
            Self::AeadMessageNotCapturable => f.write_str("AEAD message not capturable"),
            Self::AeadMessageNotComplete => f.write_str("AEAD message not complete"),
            Self::AeadMessageOperationNotJoinable => {
                f.write_str("AEAD message operation not joinable")
            }
            Self::AeadMessageOutputProgression => f.write_str("AEAD message output progression"),
            Self::AeadMessageOutputShape => f.write_str("AEAD message output shape"),
            Self::AeadMessageOutputsAbsent => f.write_str("AEAD message outputs absent"),
            Self::AeadMessagePartOverflow => f.write_str("AEAD message part overflow"),
            Self::AeadMessageProvidedNonceMutation => {
                f.write_str("AEAD message provided nonce mutation")
            }
            Self::AeadMessageResultWithheldAfterFailure => {
                f.write_str("AEAD message result withheld after failure")
            }
            Self::AeadMessageSelectionTagRepresentation => {
                f.write_str("AEAD message selection/tag representation")
            }
            Self::AeadMessageTicketUnavailable => f.write_str("AEAD message ticket unavailable"),
            Self::AeadMessageUnexpectedGeneratedNonce => {
                f.write_str("AEAD message unexpected generated nonce")
            }
            Self::AeadNativeLengthWidth => f.write_str("AEAD native length width"),
            Self::AeadNativeParameterIdentity => f.write_str("AEAD native parameter identity"),
            Self::AeadOutputAlreadyPublished => f.write_str("AEAD output already published"),
            Self::AeadOutputCallAbsent => f.write_str("AEAD output call absent"),
            Self::AeadOutputCapacityOverflow => f.write_str("AEAD output capacity overflow"),
            Self::AeadOutputStillReferencedByPendingCall => {
                f.write_str("AEAD output still referenced by pending call")
            }
            Self::AeadOutputsAbsent => f.write_str("AEAD outputs absent"),
            Self::AeadPreparedMessageIndex => f.write_str("AEAD prepared message index"),
            Self::AeadPreparedOutputWidth => f.write_str("AEAD prepared output width"),
            Self::AeadQueuedFragmentCount => f.write_str("AEAD queued fragment count"),
            Self::AeadQueuedFragmentWidth => f.write_str("AEAD queued fragment width"),
            Self::AeadQueuedInputTransition => f.write_str("AEAD queued input transition"),
            Self::AeadQueuedRowAbsent => f.write_str("AEAD queued row absent"),
            Self::AeadRecordedFixedBits => f.write_str("AEAD recorded fixed bits"),
            Self::AeadRecordedGenerator => f.write_str("AEAD recorded generator"),
            Self::AeadRecordedInitialNonce => f.write_str("AEAD recorded initial nonce"),
            Self::AeadRefusalPhase => f.write_str("AEAD refusal phase"),
            Self::AeadReportCountOverflow => f.write_str("AEAD report count overflow"),
            Self::AeadResultMetadataOverflow => f.write_str("AEAD result metadata overflow"),
            Self::AeadRetainedOutputRange => f.write_str("AEAD retained output range"),
            Self::AeadRetirementAllocation => f.write_str("AEAD retirement allocation"),
            Self::AeadRetirementMetadataOverflow => {
                f.write_str("AEAD retirement metadata overflow")
            }
            Self::AeadRetirementPoolAbsent => f.write_str("AEAD retirement pool absent"),
            Self::AeadRetirementSlotAbsent => f.write_str("AEAD retirement slot absent"),
            Self::AeadRetirementStorageOverflow => f.write_str("AEAD retirement storage overflow"),
            Self::AeadReturnedInputNotRetired => f.write_str("AEAD returned input not retired"),
            Self::AeadReturnedStorageNotRetired => f.write_str("AEAD returned storage not retired"),
            Self::AeadRowCountOverflow => f.write_str("AEAD row count overflow"),
            Self::AeadSharedInitDescriptorMutation => {
                f.write_str("AEAD shared Init descriptor mutation")
            }
            Self::AeadSnapshotInitIndex => f.write_str("AEAD snapshot Init index"),
            Self::AeadSnapshotAccounting => f.write_str("AEAD snapshot accounting"),
            Self::AeadSnapshotAllocation => f.write_str("AEAD snapshot allocation"),
            Self::AeadSnapshotShapeChanged => f.write_str("AEAD snapshot shape changed"),
            Self::AeadSnapshotTagShapeChanged => f.write_str("AEAD snapshot tag shape changed"),
            Self::AeadStorageAlreadyBound => f.write_str("AEAD storage already bound"),
            Self::AeadStorageNotBound => f.write_str("AEAD storage not bound"),
            Self::AeadStorageOverflow => f.write_str("AEAD storage overflow"),
            Self::AeadStorageShapeChanged => f.write_str("AEAD storage shape changed"),
            Self::AeadStreamInitCapturePending => f.write_str("AEAD stream Init capture pending"),
            Self::AeadStreamCheckpointBoundary => f.write_str("AEAD stream checkpoint boundary"),
            Self::AeadStreamFragmentAbsent => f.write_str("AEAD stream fragment absent"),
            Self::AeadStreamIsNotAwaitingInput => f.write_str("AEAD stream is not awaiting input"),
            Self::AeadStreamReconstruction => f.write_str("AEAD stream reconstruction"),
            Self::AeadStreamRefusalPhase => f.write_str("AEAD stream refusal phase"),
            Self::AeadStreamRowShape => f.write_str("AEAD stream row shape"),
            Self::AeadStreamSnapshotShapeChanged => {
                f.write_str("AEAD stream snapshot shape changed")
            }
            Self::AeadSubmissionRoute => f.write_str("AEAD submission route"),
            Self::AeadTableAllocation => f.write_str("AEAD table allocation"),
            Self::AeadTableSizeOverflow => f.write_str("AEAD table size overflow"),
            Self::AeadTicketAlreadyTransferred => f.write_str("AEAD ticket already transferred"),
            Self::CcmMacLength => f.write_str("CCM MAC length"),
            Self::CcmGeneratorAbiWidth => f.write_str("CCM generator ABI width"),
            Self::CcmRecordedMacAlignment => f.write_str("CCM recorded MAC alignment"),
            Self::CcmRetainedSelectionAccounting => {
                f.write_str("CCM retained selection accounting")
            }
            Self::MessageResultExceedsAdmittedCapacity => {
                f.write_str("Message result exceeds admitted capacity")
            }
            Self::MessageResultLengthOverflow => f.write_str("Message result length overflow"),
            Self::CallerFedAeadStreamRequired => f.write_str("caller-fed AEAD stream required"),
            Self::CheckpointGcmResultRange => f.write_str("checkpoint GCM result range"),
            Self::CheckpointGeneratedNonceUnknown => {
                f.write_str("checkpoint generated nonce unknown")
            }
            Self::ConsumedAeadMessageTicket => f.write_str("consumed AEAD message ticket"),
            Self::DeclaredGcmInitDescriptorMutation => {
                f.write_str("declared GCM Init descriptor mutation")
            }
            Self::DeclaredGcmInitDispatch => f.write_str("declared GCM Init dispatch"),
            Self::DeclaredGcmNativeKeyReference => f.write_str("declared GCM native key reference"),
            Self::DeclaredGcmResultOwnership => f.write_str("declared GCM result ownership"),
            Self::DeclaredInitHasNoStandardSeed => {
                f.write_str("declared Init has no standard seed")
            }
            Self::DecryptionTagAbsent => f.write_str("decryption tag absent"),
            Self::DuplicateGcmCompletion => f.write_str("duplicate GCM completion"),
            Self::EmptyAeadMessageSequence => f.write_str("empty AEAD message sequence"),
            Self::EmptyStreamAeadSequence => f.write_str("empty stream AEAD sequence"),
            Self::FinishAeadMessageBeforeItsParent => {
                f.write_str("finish AEAD message before its parent")
            }
            Self::ForeignGcmMessageDeclaration => f.write_str("foreign GCM message declaration"),
            Self::ForeignOrConsumedAeadStreamTicket => {
                f.write_str("foreign or consumed AEAD stream ticket")
            }
            Self::ForeignOrConsumedAeadTicket => f.write_str("foreign or consumed AEAD ticket"),
            Self::MessageExtensionMechanismAbiWidth => {
                f.write_str("message extension mechanism ABI width")
            }
            Self::MessageInterfaceUnavailable => f.write_str("message interface unavailable"),
            Self::MixedAeadMessageMechanisms => f.write_str("mixed AEAD message mechanisms"),
            Self::MixedAeadMessageSelections => f.write_str("mixed AEAD message selections"),
            Self::QueuedAeadCapacityCall => f.write_str("queued AEAD capacity call"),
            Self::ReconstructionAad => f.write_str("reconstruction AAD"),
            Self::ReconstructionGcmPhase => f.write_str("reconstruction GCM phase"),
            Self::ReconstructionMac => f.write_str("reconstruction MAC"),
            Self::ReconstructionNonceWidth => f.write_str("reconstruction nonce width"),
            Self::ReconstructionTag => f.write_str("reconstruction tag"),
            Self::ReconstructionTagWidth => f.write_str("reconstruction tag width"),
            Self::RecordGcmInitLayoutChangedWithinSequence => {
                f.write_str("record GCM Init layout changed within sequence")
            }
            Self::RecoveryRequiresAeadMessageDecryption => {
                f.write_str("recovery requires AEAD message decryption")
            }
            Self::SingleAeadRequestCount => f.write_str("single AEAD request count"),
            Self::SingleMessageResultCount => f.write_str("single Message result count"),
            Self::StaleAeadMessageOwner => f.write_str("stale AEAD message owner"),
            Self::StaleAeadStreamTicket => f.write_str("stale AEAD stream ticket"),
            Self::StaleAeadTicket => f.write_str("stale AEAD ticket"),
            Self::StreamAeadMessageinitHasNoParameters => {
                f.write_str("stream AEAD MessageInit has no parameters")
            }
            Self::StreamAeadInitialNonceAbsent => f.write_str("stream AEAD initial nonce absent"),
            Self::StreamAeadRecordScalarSelection => {
                f.write_str("stream AEAD record scalar selection")
            }
            Self::SynchronousMessageFacadeRequiresSynchronousSession => {
                f.write_str("synchronous Message facade requires synchronous session")
            }
            Self::SynchronousMessageSequenceDidNotComplete => {
                f.write_str("synchronous Message sequence did not complete")
            }
            Self::UnexpectedRestorationAuthenticationKey => {
                f.write_str("unexpected restoration authentication key")
            }
            Self::ValidationReportLength => f.write_str("validation report length"),
        }
    }
}
