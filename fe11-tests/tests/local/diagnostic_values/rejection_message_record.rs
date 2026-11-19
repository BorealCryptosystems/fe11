// SPDX-License-Identifier: Apache-2.0
//! Public MessageRecordRejection values retain identity through category conversion.
use fe11::{Error, MessageRecordRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        MessageRecordRejection::AeadInitSeed,
        MessageRecordRejection::AeadBatchOutputContinuation,
        MessageRecordRejection::AeadBatchOutputPrepared,
        MessageRecordRejection::AeadBatchRecordAssociation,
        MessageRecordRejection::AeadCapacityContinuationAssociation,
        MessageRecordRejection::AeadCapacityContinuationPhase,
        MessageRecordRejection::AeadCapacityPrefixExceedsStorage,
        MessageRecordRejection::AeadCapacityRowAbsent,
        MessageRecordRejection::AeadDeclaredInputAbsent,
        MessageRecordRejection::AeadDeclaredInputIndex,
        MessageRecordRejection::AeadDeclaredInputRowCount,
        MessageRecordRejection::AeadDeclaredInputWidth,
        MessageRecordRejection::AeadDeclaredRetainedInputAssociation,
        MessageRecordRejection::AeadPreparedOutput,
        MessageRecordRejection::AeadPreviousOutputWidth,
        MessageRecordRejection::AeadRequiredOutputWidth,
        MessageRecordRejection::AeadRetainedInputOverflow,
        MessageRecordRejection::AeadStreamArchiveRepresentation,
        MessageRecordRejection::CipherExtensionParameters,
        MessageRecordRejection::DigestExtensionParameters,
        MessageRecordRejection::DigestOutputStorage,
        MessageRecordRejection::GenericMessageBeginPresence,
        MessageRecordRejection::GenericMessageArchiveRepresentation,
        MessageRecordRejection::GenericMessageBodyOnAnotherFamily,
        MessageRecordRejection::GenericMessageCapacityPrepared,
        MessageRecordRejection::GenericMessageDeclarationPresence,
        MessageRecordRejection::GenericMessageImportDeclarationMismatch,
        MessageRecordRejection::GenericMessageInvalidVerdict,
        MessageRecordRejection::GenericMessageKeyEffect,
        MessageRecordRejection::GenericMessageLayoutProvenance,
        MessageRecordRejection::GenericMessageRefusal,
        MessageRecordRejection::GenericMessageWriterDeclaration,
        MessageRecordRejection::ImportRequiresADestinationAbiDeclaration,
        MessageRecordRejection::ImportedCallableGraphRequiresAnAssertedAbi,
        MessageRecordRejection::MessageOutputContinuation,
        MessageRecordRejection::MessageOutputContinuationAssociation,
        MessageRecordRejection::MessageOutputContinuationPhase,
        MessageRecordRejection::MessageOutputContinuationRowAbsent,
        MessageRecordRejection::MessageOutputPrepared,
        MessageRecordRejection::MessagePreviousOutputWidth,
        MessageRecordRejection::MessageRefusalCodeWidth,
        MessageRecordRejection::MessageRefusalCount,
        MessageRecordRejection::MessageRefusalDisposition,
        MessageRecordRejection::MessageRefusalPresence,
        MessageRecordRejection::MessageRefusalRepresentation,
        MessageRecordRejection::MessageRefusalRowAbsent,
        MessageRecordRejection::MessageRepresentationOnAnotherFamily,
        MessageRecordRejection::MessageRequiredOutputWidth,
        MessageRecordRejection::MessageStreamParent,
        MessageRecordRejection::RecordInitLayoutWithoutAeadParameters,
        MessageRecordRejection::RecordAggregateFragments,
        MessageRecordRejection::RecordChangedFixedInitScalars,
        MessageRecordRejection::RecordCompletedNonceAbsent,
        MessageRecordRejection::RecordFinishedMessageIncomplete,
        MessageRecordRejection::RecordFragmentCount,
        MessageRecordRejection::RecordFragmentIndex,
        MessageRecordRejection::RecordMessageInitLayout,
        MessageRecordRejection::RecordMessageCount,
        MessageRecordRejection::RecordMessageOrder,
        MessageRecordRejection::RecordMessageProgression,
        MessageRecordRejection::RecordMessageRoute,
        MessageRecordRejection::RecordMessageState,
        MessageRecordRejection::RecordMessageStreamAssociation,
        MessageRecordRejection::RecordMessageStreamBoundary,
        MessageRecordRejection::RecordMessageStreamDisposition,
        MessageRecordRejection::RecordMessageStreamInvalidResult,
        MessageRecordRejection::RecordMessageStreamObservationAbsent,
        MessageRecordRejection::RecordMessageStreamObservationAssociation,
        MessageRecordRejection::RecordMessageStreamOutputCounter,
        MessageRecordRejection::RecordMessageStreamOutputPhase,
        MessageRecordRejection::RecordMessageStreamProgress,
        MessageRecordRejection::RecordMessageStreamReportCapacity,
        MessageRecordRejection::RecordMessageStreamRoute,
        MessageRecordRejection::RecordMessageStreamRow,
        MessageRecordRejection::RecordMessageStreamRowAbsent,
        MessageRecordRejection::RecordMessageStreamSignatureResult,
        MessageRecordRejection::RecordMessageStreamSubmissionWidth,
        MessageRecordRejection::RecordMessageStreamUnexpectedObservation,
        MessageRecordRejection::RecordMessageStreamVerificationInput,
        MessageRecordRejection::RecordMessageWidth,
        MessageRecordRejection::RecordMixedMessageInitLayouts,
        MessageRecordRejection::RecordNonceOrigin,
        MessageRecordRejection::RecordPlannedMessageProgressed,
        MessageRecordRejection::RecordResidualRange,
        MessageRecordRejection::RecordSizeConversion,
        MessageRecordRejection::SignatureRecordParameters,
        MessageRecordRejection::TerminalMessageStreamReportAbsent,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::MessageRecord(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::MessageRecord(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
