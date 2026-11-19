// SPDX-License-Identifier: Apache-2.0
//! Public OperationRecordRejection values retain identity through category conversion.
use fe11::{Error, OperationRecordRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        OperationRecordRejection::AesRequiresPhaseSpecificTerminalValidation,
        OperationRecordRejection::AsynchronousFunctionIdentity,
        OperationRecordRejection::CipherExtensionKeyEffects,
        OperationRecordRejection::CipherExtensionProvenance,
        OperationRecordRejection::DigestExtensionProvenance,
        OperationRecordRejection::DigestOutputCapacityWidth,
        OperationRecordRejection::FailedAesOwnerHasNoTerminalResult,
        OperationRecordRejection::FailedRecoveryMustNotContainATerminalResult,
        OperationRecordRejection::InvalidTerminalPlaintextDisclosure,
        OperationRecordRejection::ReconstructionRequiresEncodedGraph,
        OperationRecordRejection::RecordByteCeiling,
        OperationRecordRejection::RecordByteLength,
        OperationRecordRejection::RecordCipherOptionsTag,
        OperationRecordRejection::RecordClassWidth,
        OperationRecordRejection::RecordContextMismatch,
        OperationRecordRejection::RecordCount,
        OperationRecordRejection::RecordFunctionCode,
        OperationRecordRejection::RecordGeneratedByteLength,
        OperationRecordRejection::RecordIdentityWidth,
        OperationRecordRejection::RecordIntegerWidth,
        OperationRecordRejection::RecordKeyRole,
        OperationRecordRejection::RecordKeyRoleOrder,
        OperationRecordRejection::RecordKeyTypeWidth,
        OperationRecordRejection::RecordKind,
        OperationRecordRejection::RecordLength,
        OperationRecordRejection::RecordLimits,
        OperationRecordRejection::RecordObservationWidth,
        OperationRecordRejection::RecordOption,
        OperationRecordRejection::RecordOptionalIntegerTag,
        OperationRecordRejection::RecordPayloadLength,
        OperationRecordRejection::RecordPhaseCode,
        OperationRecordRejection::RecordReadOverflow,
        OperationRecordRejection::RecordSessionState,
        OperationRecordRejection::RecordSessionWidth,
        OperationRecordRejection::RecordSizeChanged,
        OperationRecordRejection::RecordTrailingBytes,
        OperationRecordRejection::RecordValidationFunction,
        OperationRecordRejection::RecordValidationIndex,
        OperationRecordRejection::RecordValidationMode,
        OperationRecordRejection::RecordValidationWidth,
        OperationRecordRejection::RecordVersion,
        OperationRecordRejection::RecordWriteRange,
        OperationRecordRejection::SignatureContinuationObservation,
        OperationRecordRejection::SignatureContinuationPosition,
        OperationRecordRejection::SignatureKeyEffect,
        OperationRecordRejection::SignatureLayoutProvenance,
        OperationRecordRejection::SignatureMechanismWidth,
        OperationRecordRejection::SignatureOutputQuery,
        OperationRecordRejection::SignatureRecordKind,
        OperationRecordRejection::SignatureRecordOperands,
        OperationRecordRejection::SignatureRecordParametersAbsent,
        OperationRecordRejection::SignatureRecordPhase,
        OperationRecordRejection::SignatureRecordRepresentation,
        OperationRecordRejection::SignatureRecordSections,
        OperationRecordRejection::SignatureRecordWidth,
        OperationRecordRejection::SignatureRetainedSizingResponse,
        OperationRecordRejection::SignatureReturnedLengthWidth,
        OperationRecordRejection::SignatureTerminalInputOpen,
        OperationRecordRejection::SignatureTerminalSizingContinuation,
        OperationRecordRejection::SingleSignatureReadyPhase,
        OperationRecordRejection::SingleSignatureSubmissionCounters,
        OperationRecordRejection::SingleSignatureUpdatePhase,
        OperationRecordRejection::TerminalAeadCapacityContinuation,
        OperationRecordRejection::TerminalCipherCorrelation,
        OperationRecordRejection::TerminalCipherObservationAbsent,
        OperationRecordRejection::TerminalCipherResultLength,
        OperationRecordRejection::TerminalClassicBatch,
        OperationRecordRejection::TerminalCompletedFunction,
        OperationRecordRejection::TerminalEmptyResult,
        OperationRecordRejection::TerminalInputLength,
        OperationRecordRejection::TerminalMessageCorrelation,
        OperationRecordRejection::TerminalMessageObservationAbsent,
        OperationRecordRejection::TerminalMessageOutputContinuation,
        OperationRecordRejection::TerminalMessageProgression,
        OperationRecordRejection::TerminalNoncontiguousProcessedPrefix,
        OperationRecordRejection::TerminalProcessedPrefix,
        OperationRecordRejection::TerminalReportCapacity,
        OperationRecordRejection::TerminalResultDisposition,
        OperationRecordRejection::TerminalUnexpectedObservation,
        OperationRecordRejection::TerminalUnfinishedResult,
        OperationRecordRejection::TruncatedRecord,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::OperationRecord(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::OperationRecord(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
