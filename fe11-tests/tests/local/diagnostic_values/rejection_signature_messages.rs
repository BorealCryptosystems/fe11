// SPDX-License-Identifier: Apache-2.0
//! Public SignatureMessagesRejection values retain identity through category conversion.
use fe11::{Error, RejectionReason, SignatureMessagesRejection};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        SignatureMessagesRejection::MacTagSize,
        SignatureMessagesRejection::PssCheckpointParameterIdentity,
        SignatureMessagesRejection::PssMessageMechanismMismatch,
        SignatureMessagesRejection::PssNativeParameterIdentity,
        SignatureMessagesRejection::PssSnapshotParameterIdentity,
        SignatureMessagesRejection::BufferedMessageHasStreamFragment,
        SignatureMessagesRejection::ConsumedMessageTicket,
        SignatureMessagesRejection::CurrentMessageFragmentAbsent,
        SignatureMessagesRejection::DuplicateMessageCompletion,
        SignatureMessagesRejection::FinishTheCurrentMessageBeforeTheParentProcess,
        SignatureMessagesRejection::ForeignOperationLeaseAdmission,
        SignatureMessagesRejection::ForeignOrConsumedMessageSignatureTicket,
        SignatureMessagesRejection::MessageHmacKeyRequired,
        SignatureMessagesRejection::MessageAllocation,
        SignatureMessagesRejection::MessageAlreadyPublished,
        SignatureMessagesRejection::MessageAsynchronousResultIdentity,
        SignatureMessagesRejection::MessageByteOverflow,
        SignatureMessagesRejection::MessageCount,
        SignatureMessagesRejection::MessageFailedExplicitCleanupRequired,
        SignatureMessagesRejection::MessageFunctionsUnavailable,
        SignatureMessagesRejection::MessageInputCeiling,
        SignatureMessagesRejection::MessageInputStorageOverflow,
        SignatureMessagesRejection::MessageMetadataOverflow,
        SignatureMessagesRejection::MessageNativeLengthWidth,
        SignatureMessagesRejection::MessageNativeParameterIdentity,
        SignatureMessagesRejection::MessageNotActive,
        SignatureMessagesRejection::MessageNotCapturable,
        SignatureMessagesRejection::MessageNotComplete,
        SignatureMessagesRejection::MessageOperationNotJoinable,
        SignatureMessagesRejection::MessageOperationStorageSize,
        SignatureMessagesRejection::MessageOutputCallAbsent,
        SignatureMessagesRejection::MessagePartOverflow,
        SignatureMessagesRejection::MessagePreparedOutputWidth,
        SignatureMessagesRejection::MessageReportCountOverflow,
        SignatureMessagesRejection::MessageResultMetadata,
        SignatureMessagesRejection::MessageResultWithheldAfterFailure,
        SignatureMessagesRejection::MessageResultsAbsent,
        SignatureMessagesRejection::MessageRowCountOverflow,
        SignatureMessagesRejection::MessageSignatureCount,
        SignatureMessagesRejection::MessageSignatureIsNotWaitingForStorage,
        SignatureMessagesRejection::MessageSignatureStorageAbsent,
        SignatureMessagesRejection::MessageSignatureStreamIsNotAwaitingInput,
        SignatureMessagesRejection::MessageSignatureStreamRowShape,
        SignatureMessagesRejection::MessageSignatureSubmissionRoute,
        SignatureMessagesRejection::MessageSignatureTicketRequired,
        SignatureMessagesRejection::MessageSignaturesAlreadyPublished,
        SignatureMessagesRejection::MessageSnapshotAccounting,
        SignatureMessagesRejection::MessageSnapshotRowCount,
        SignatureMessagesRejection::MessageStreamActiveRowAbsent,
        SignatureMessagesRejection::MessageStreamCapturePhase,
        SignatureMessagesRejection::MessageStreamCaptureShape,
        SignatureMessagesRejection::MessageStreamFragmentAbsent,
        SignatureMessagesRejection::MessageStreamReconstructionFragment,
        SignatureMessagesRejection::MessageStreamReconstructionSize,
        SignatureMessagesRejection::MessageStreamRepeatedFragment,
        SignatureMessagesRejection::MessageStreamResultsAbsent,
        SignatureMessagesRejection::MessageStreamSnapshotFragment,
        SignatureMessagesRejection::MessageStreamSnapshotRow,
        SignatureMessagesRejection::MessageStreamSnapshotShape,
        SignatureMessagesRejection::MessageVectorAllocation,
        SignatureMessagesRejection::MessageVectorStorageOverflow,
        SignatureMessagesRejection::ReconstructionExpectedSignature,
        SignatureMessagesRejection::ReconstructionMechanismWidth,
        SignatureMessagesRejection::ReconstructionSignaturePhase,
        SignatureMessagesRejection::RecordPssMgfAbsent,
        SignatureMessagesRejection::RecordPssMgfWidth,
        SignatureMessagesRejection::RecordPssHashAbsent,
        SignatureMessagesRejection::RecordPssHashWidth,
        SignatureMessagesRejection::RecordPssMessagesAbsent,
        SignatureMessagesRejection::RecordPssParameters,
        SignatureMessagesRejection::RecordPssProfile,
        SignatureMessagesRejection::RecordPssSaltAbsent,
        SignatureMessagesRejection::RecordPssSaltWidth,
        SignatureMessagesRejection::RecordMixedPssParameters,
        SignatureMessagesRejection::RestorationAuthenticationKeyRequired,
        SignatureMessagesRejection::RestoreRsaReferenceRole,
        SignatureMessagesRejection::RestoreRsaSize,
        SignatureMessagesRejection::SignatureCheckpointShape,
        SignatureMessagesRejection::SignatureCheckpointUnavailable,
        SignatureMessagesRejection::StaleMessageSignatureTicket,
        SignatureMessagesRejection::StaleMessageTicket,
        SignatureMessagesRejection::StreamPhaseOnBufferedMessage,
        SignatureMessagesRejection::UnexpectedRestorationEncryptionKey,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::SignatureMessages(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::SignatureMessages(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
