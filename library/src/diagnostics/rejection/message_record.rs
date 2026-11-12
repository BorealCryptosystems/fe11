// SPDX-License-Identifier: Apache-2.0
//! MessageRecord causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to message record.
#[doc = include_str!("../../../docs/diagnostics/rejection-message_record.md")]
pub enum MessageRecordRejection {
    /// AEAD Init seed. [Detection, owner and recovery](#cause-AeadInitSeed).
    AeadInitSeed,
    /// AEAD batch output continuation. [Detection, owner and recovery](#cause-AeadBatchOutputContinuation).
    AeadBatchOutputContinuation,
    /// AEAD batch output prepared. [Detection, owner and recovery](#cause-AeadBatchOutputPrepared).
    AeadBatchOutputPrepared,
    /// AEAD batch record association. [Detection, owner and recovery](#cause-AeadBatchRecordAssociation).
    AeadBatchRecordAssociation,
    /// AEAD capacity continuation association. [Detection, owner and recovery](#cause-AeadCapacityContinuationAssociation).
    AeadCapacityContinuationAssociation,
    /// AEAD capacity continuation phase. [Detection, owner and recovery](#cause-AeadCapacityContinuationPhase).
    AeadCapacityContinuationPhase,
    /// AEAD capacity prefix exceeds storage. [Detection, owner and recovery](#cause-AeadCapacityPrefixExceedsStorage).
    AeadCapacityPrefixExceedsStorage,
    /// AEAD capacity row absent. [Detection, owner and recovery](#cause-AeadCapacityRowAbsent).
    AeadCapacityRowAbsent,
    /// AEAD declared input absent. [Detection, owner and recovery](#cause-AeadDeclaredInputAbsent).
    AeadDeclaredInputAbsent,
    /// AEAD declared input index. [Detection, owner and recovery](#cause-AeadDeclaredInputIndex).
    AeadDeclaredInputIndex,
    /// AEAD declared input row count. [Detection, owner and recovery](#cause-AeadDeclaredInputRowCount).
    AeadDeclaredInputRowCount,
    /// AEAD declared input width. [Detection, owner and recovery](#cause-AeadDeclaredInputWidth).
    AeadDeclaredInputWidth,
    /// AEAD declared/retained input association. [Detection, owner and recovery](#cause-AeadDeclaredRetainedInputAssociation).
    AeadDeclaredRetainedInputAssociation,
    /// AEAD prepared output. [Detection, owner and recovery](#cause-AeadPreparedOutput).
    AeadPreparedOutput,
    /// AEAD previous output width. [Detection, owner and recovery](#cause-AeadPreviousOutputWidth).
    AeadPreviousOutputWidth,
    /// AEAD required output width. [Detection, owner and recovery](#cause-AeadRequiredOutputWidth).
    AeadRequiredOutputWidth,
    /// AEAD retained input overflow. [Detection, owner and recovery](#cause-AeadRetainedInputOverflow).
    AeadRetainedInputOverflow,
    /// AEAD stream archive representation. [Detection, owner and recovery](#cause-AeadStreamArchiveRepresentation).
    AeadStreamArchiveRepresentation,
    /// Cipher extension parameters. [Detection, owner and recovery](#cause-CipherExtensionParameters).
    CipherExtensionParameters,
    /// Digest extension parameters. [Detection, owner and recovery](#cause-DigestExtensionParameters).
    DigestExtensionParameters,
    /// Digest output storage. [Detection, owner and recovery](#cause-DigestOutputStorage).
    DigestOutputStorage,
    /// Generic message Begin presence. [Detection, owner and recovery](#cause-GenericMessageBeginPresence).
    GenericMessageBeginPresence,
    /// Generic message archive representation. [Detection, owner and recovery](#cause-GenericMessageArchiveRepresentation).
    GenericMessageArchiveRepresentation,
    /// Generic message body on another family. [Detection, owner and recovery](#cause-GenericMessageBodyOnAnotherFamily).
    GenericMessageBodyOnAnotherFamily,
    /// Generic message capacity prepared. [Detection, owner and recovery](#cause-GenericMessageCapacityPrepared).
    GenericMessageCapacityPrepared,
    /// Generic message declaration presence. [Detection, owner and recovery](#cause-GenericMessageDeclarationPresence).
    GenericMessageDeclarationPresence,
    /// Generic message import declaration mismatch. [Detection, owner and recovery](#cause-GenericMessageImportDeclarationMismatch).
    GenericMessageImportDeclarationMismatch,
    /// Generic message invalid verdict. [Detection, owner and recovery](#cause-GenericMessageInvalidVerdict).
    GenericMessageInvalidVerdict,
    /// Generic message key effect. [Detection, owner and recovery](#cause-GenericMessageKeyEffect).
    GenericMessageKeyEffect,
    /// Generic message layout provenance. [Detection, owner and recovery](#cause-GenericMessageLayoutProvenance).
    GenericMessageLayoutProvenance,
    /// Generic message refusal. [Detection, owner and recovery](#cause-GenericMessageRefusal).
    GenericMessageRefusal,
    /// Generic message writer declaration. [Detection, owner and recovery](#cause-GenericMessageWriterDeclaration).
    GenericMessageWriterDeclaration,
    /// Import requires a destination ABI declaration. [Detection, owner and recovery](#cause-ImportRequiresADestinationAbiDeclaration).
    ImportRequiresADestinationAbiDeclaration,
    /// Imported callable graph requires an asserted ABI. [Detection, owner and recovery](#cause-ImportedCallableGraphRequiresAnAssertedAbi).
    ImportedCallableGraphRequiresAnAssertedAbi,
    /// Message output continuation. [Detection, owner and recovery](#cause-MessageOutputContinuation).
    MessageOutputContinuation,
    /// Message output continuation association. [Detection, owner and recovery](#cause-MessageOutputContinuationAssociation).
    MessageOutputContinuationAssociation,
    /// Message output continuation phase. [Detection, owner and recovery](#cause-MessageOutputContinuationPhase).
    MessageOutputContinuationPhase,
    /// Message output continuation row absent. [Detection, owner and recovery](#cause-MessageOutputContinuationRowAbsent).
    MessageOutputContinuationRowAbsent,
    /// Message output prepared. [Detection, owner and recovery](#cause-MessageOutputPrepared).
    MessageOutputPrepared,
    /// Message previous output width. [Detection, owner and recovery](#cause-MessagePreviousOutputWidth).
    MessagePreviousOutputWidth,
    /// Message refusal code width. [Detection, owner and recovery](#cause-MessageRefusalCodeWidth).
    MessageRefusalCodeWidth,
    /// Message refusal count. [Detection, owner and recovery](#cause-MessageRefusalCount).
    MessageRefusalCount,
    /// Message refusal disposition. [Detection, owner and recovery](#cause-MessageRefusalDisposition).
    MessageRefusalDisposition,
    /// Message refusal presence. [Detection, owner and recovery](#cause-MessageRefusalPresence).
    MessageRefusalPresence,
    /// Message refusal representation. [Detection, owner and recovery](#cause-MessageRefusalRepresentation).
    MessageRefusalRepresentation,
    /// Message refusal row absent. [Detection, owner and recovery](#cause-MessageRefusalRowAbsent).
    MessageRefusalRowAbsent,
    /// Message representation on another family. [Detection, owner and recovery](#cause-MessageRepresentationOnAnotherFamily).
    MessageRepresentationOnAnotherFamily,
    /// Message required output width. [Detection, owner and recovery](#cause-MessageRequiredOutputWidth).
    MessageRequiredOutputWidth,
    /// Message stream parent. [Detection, owner and recovery](#cause-MessageStreamParent).
    MessageStreamParent,
    /// Record Init layout without AEAD parameters. [Detection, owner and recovery](#cause-RecordInitLayoutWithoutAeadParameters).
    RecordInitLayoutWithoutAeadParameters,
    /// Record aggregate fragments. [Detection, owner and recovery](#cause-RecordAggregateFragments).
    RecordAggregateFragments,
    /// Record changed fixed Init scalars. [Detection, owner and recovery](#cause-RecordChangedFixedInitScalars).
    RecordChangedFixedInitScalars,
    /// Record completed nonce absent. [Detection, owner and recovery](#cause-RecordCompletedNonceAbsent).
    RecordCompletedNonceAbsent,
    /// Record finished message incomplete. [Detection, owner and recovery](#cause-RecordFinishedMessageIncomplete).
    RecordFinishedMessageIncomplete,
    /// Record fragment count. [Detection, owner and recovery](#cause-RecordFragmentCount).
    RecordFragmentCount,
    /// Record fragment index. [Detection, owner and recovery](#cause-RecordFragmentIndex).
    RecordFragmentIndex,
    /// Record message Init layout. [Detection, owner and recovery](#cause-RecordMessageInitLayout).
    RecordMessageInitLayout,
    /// Record message count. [Detection, owner and recovery](#cause-RecordMessageCount).
    RecordMessageCount,
    /// Record message order. [Detection, owner and recovery](#cause-RecordMessageOrder).
    RecordMessageOrder,
    /// Record message progression. [Detection, owner and recovery](#cause-RecordMessageProgression).
    RecordMessageProgression,
    /// Record message route. [Detection, owner and recovery](#cause-RecordMessageRoute).
    RecordMessageRoute,
    /// Record message state. [Detection, owner and recovery](#cause-RecordMessageState).
    RecordMessageState,
    /// Record message stream association. [Detection, owner and recovery](#cause-RecordMessageStreamAssociation).
    RecordMessageStreamAssociation,
    /// Record message stream boundary. [Detection, owner and recovery](#cause-RecordMessageStreamBoundary).
    RecordMessageStreamBoundary,
    /// Record message stream disposition. [Detection, owner and recovery](#cause-RecordMessageStreamDisposition).
    RecordMessageStreamDisposition,
    /// Record message stream invalid result. [Detection, owner and recovery](#cause-RecordMessageStreamInvalidResult).
    RecordMessageStreamInvalidResult,
    /// Record message stream observation absent. [Detection, owner and recovery](#cause-RecordMessageStreamObservationAbsent).
    RecordMessageStreamObservationAbsent,
    /// Record message stream observation association. [Detection, owner and recovery](#cause-RecordMessageStreamObservationAssociation).
    RecordMessageStreamObservationAssociation,
    /// Record message stream output counter. [Detection, owner and recovery](#cause-RecordMessageStreamOutputCounter).
    RecordMessageStreamOutputCounter,
    /// Record message stream output phase. [Detection, owner and recovery](#cause-RecordMessageStreamOutputPhase).
    RecordMessageStreamOutputPhase,
    /// Record message stream progress. [Detection, owner and recovery](#cause-RecordMessageStreamProgress).
    RecordMessageStreamProgress,
    /// Record message stream report capacity. [Detection, owner and recovery](#cause-RecordMessageStreamReportCapacity).
    RecordMessageStreamReportCapacity,
    /// Record message stream route. [Detection, owner and recovery](#cause-RecordMessageStreamRoute).
    RecordMessageStreamRoute,
    /// Record message stream row. [Detection, owner and recovery](#cause-RecordMessageStreamRow).
    RecordMessageStreamRow,
    /// Record message stream row absent. [Detection, owner and recovery](#cause-RecordMessageStreamRowAbsent).
    RecordMessageStreamRowAbsent,
    /// Record message stream signature result. [Detection, owner and recovery](#cause-RecordMessageStreamSignatureResult).
    RecordMessageStreamSignatureResult,
    /// Record message stream submission width. [Detection, owner and recovery](#cause-RecordMessageStreamSubmissionWidth).
    RecordMessageStreamSubmissionWidth,
    /// Record message stream unexpected observation. [Detection, owner and recovery](#cause-RecordMessageStreamUnexpectedObservation).
    RecordMessageStreamUnexpectedObservation,
    /// Record message stream verification input. [Detection, owner and recovery](#cause-RecordMessageStreamVerificationInput).
    RecordMessageStreamVerificationInput,
    /// Record message width. [Detection, owner and recovery](#cause-RecordMessageWidth).
    RecordMessageWidth,
    /// Record mixed message Init layouts. [Detection, owner and recovery](#cause-RecordMixedMessageInitLayouts).
    RecordMixedMessageInitLayouts,
    /// Record nonce origin. [Detection, owner and recovery](#cause-RecordNonceOrigin).
    RecordNonceOrigin,
    /// Record planned message progressed. [Detection, owner and recovery](#cause-RecordPlannedMessageProgressed).
    RecordPlannedMessageProgressed,
    /// Record residual range. [Detection, owner and recovery](#cause-RecordResidualRange).
    RecordResidualRange,
    /// Record size conversion. [Detection, owner and recovery](#cause-RecordSizeConversion).
    RecordSizeConversion,
    /// Signature record parameters. [Detection, owner and recovery](#cause-SignatureRecordParameters).
    SignatureRecordParameters,
    /// Terminal message stream report absent. [Detection, owner and recovery](#cause-TerminalMessageStreamReportAbsent).
    TerminalMessageStreamReportAbsent,
}

impl std::fmt::Display for MessageRecordRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadInitSeed => f.write_str("AEAD Init seed"),
            Self::AeadBatchOutputContinuation => f.write_str("AEAD batch output continuation"),
            Self::AeadBatchOutputPrepared => f.write_str("AEAD batch output prepared"),
            Self::AeadBatchRecordAssociation => f.write_str("AEAD batch record association"),
            Self::AeadCapacityContinuationAssociation => {
                f.write_str("AEAD capacity continuation association")
            }
            Self::AeadCapacityContinuationPhase => f.write_str("AEAD capacity continuation phase"),
            Self::AeadCapacityPrefixExceedsStorage => {
                f.write_str("AEAD capacity prefix exceeds storage")
            }
            Self::AeadCapacityRowAbsent => f.write_str("AEAD capacity row absent"),
            Self::AeadDeclaredInputAbsent => f.write_str("AEAD declared input absent"),
            Self::AeadDeclaredInputIndex => f.write_str("AEAD declared input index"),
            Self::AeadDeclaredInputRowCount => f.write_str("AEAD declared input row count"),
            Self::AeadDeclaredInputWidth => f.write_str("AEAD declared input width"),
            Self::AeadDeclaredRetainedInputAssociation => {
                f.write_str("AEAD declared/retained input association")
            }
            Self::AeadPreparedOutput => f.write_str("AEAD prepared output"),
            Self::AeadPreviousOutputWidth => f.write_str("AEAD previous output width"),
            Self::AeadRequiredOutputWidth => f.write_str("AEAD required output width"),
            Self::AeadRetainedInputOverflow => f.write_str("AEAD retained input overflow"),
            Self::AeadStreamArchiveRepresentation => {
                f.write_str("AEAD stream archive representation")
            }
            Self::CipherExtensionParameters => f.write_str("cipher extension parameters"),
            Self::DigestExtensionParameters => f.write_str("digest extension parameters"),
            Self::DigestOutputStorage => f.write_str("digest output storage"),
            Self::GenericMessageBeginPresence => f.write_str("generic message Begin presence"),
            Self::GenericMessageArchiveRepresentation => {
                f.write_str("generic message archive representation")
            }
            Self::GenericMessageBodyOnAnotherFamily => {
                f.write_str("generic message body on another family")
            }
            Self::GenericMessageCapacityPrepared => {
                f.write_str("generic message capacity prepared")
            }
            Self::GenericMessageDeclarationPresence => {
                f.write_str("generic message declaration presence")
            }
            Self::GenericMessageImportDeclarationMismatch => {
                f.write_str("generic message import declaration mismatch")
            }
            Self::GenericMessageInvalidVerdict => f.write_str("generic message invalid verdict"),
            Self::GenericMessageKeyEffect => f.write_str("generic message key effect"),
            Self::GenericMessageLayoutProvenance => {
                f.write_str("generic message layout provenance")
            }
            Self::GenericMessageRefusal => f.write_str("generic message refusal"),
            Self::GenericMessageWriterDeclaration => {
                f.write_str("generic message writer declaration")
            }
            Self::ImportRequiresADestinationAbiDeclaration => {
                f.write_str("import requires a destination ABI declaration")
            }
            Self::ImportedCallableGraphRequiresAnAssertedAbi => {
                f.write_str("imported callable graph requires an asserted ABI")
            }
            Self::MessageOutputContinuation => f.write_str("message output continuation"),
            Self::MessageOutputContinuationAssociation => {
                f.write_str("message output continuation association")
            }
            Self::MessageOutputContinuationPhase => {
                f.write_str("message output continuation phase")
            }
            Self::MessageOutputContinuationRowAbsent => {
                f.write_str("message output continuation row absent")
            }
            Self::MessageOutputPrepared => f.write_str("message output prepared"),
            Self::MessagePreviousOutputWidth => f.write_str("message previous output width"),
            Self::MessageRefusalCodeWidth => f.write_str("message refusal code width"),
            Self::MessageRefusalCount => f.write_str("message refusal count"),
            Self::MessageRefusalDisposition => f.write_str("message refusal disposition"),
            Self::MessageRefusalPresence => f.write_str("message refusal presence"),
            Self::MessageRefusalRepresentation => f.write_str("message refusal representation"),
            Self::MessageRefusalRowAbsent => f.write_str("message refusal row absent"),
            Self::MessageRepresentationOnAnotherFamily => {
                f.write_str("message representation on another family")
            }
            Self::MessageRequiredOutputWidth => f.write_str("message required output width"),
            Self::MessageStreamParent => f.write_str("message stream parent"),
            Self::RecordInitLayoutWithoutAeadParameters => {
                f.write_str("record Init layout without AEAD parameters")
            }
            Self::RecordAggregateFragments => f.write_str("record aggregate fragments"),
            Self::RecordChangedFixedInitScalars => f.write_str("record changed fixed Init scalars"),
            Self::RecordCompletedNonceAbsent => f.write_str("record completed nonce absent"),
            Self::RecordFinishedMessageIncomplete => {
                f.write_str("record finished message incomplete")
            }
            Self::RecordFragmentCount => f.write_str("record fragment count"),
            Self::RecordFragmentIndex => f.write_str("record fragment index"),
            Self::RecordMessageInitLayout => f.write_str("record message Init layout"),
            Self::RecordMessageCount => f.write_str("record message count"),
            Self::RecordMessageOrder => f.write_str("record message order"),
            Self::RecordMessageProgression => f.write_str("record message progression"),
            Self::RecordMessageRoute => f.write_str("record message route"),
            Self::RecordMessageState => f.write_str("record message state"),
            Self::RecordMessageStreamAssociation => {
                f.write_str("record message stream association")
            }
            Self::RecordMessageStreamBoundary => f.write_str("record message stream boundary"),
            Self::RecordMessageStreamDisposition => {
                f.write_str("record message stream disposition")
            }
            Self::RecordMessageStreamInvalidResult => {
                f.write_str("record message stream invalid result")
            }
            Self::RecordMessageStreamObservationAbsent => {
                f.write_str("record message stream observation absent")
            }
            Self::RecordMessageStreamObservationAssociation => {
                f.write_str("record message stream observation association")
            }
            Self::RecordMessageStreamOutputCounter => {
                f.write_str("record message stream output counter")
            }
            Self::RecordMessageStreamOutputPhase => {
                f.write_str("record message stream output phase")
            }
            Self::RecordMessageStreamProgress => f.write_str("record message stream progress"),
            Self::RecordMessageStreamReportCapacity => {
                f.write_str("record message stream report capacity")
            }
            Self::RecordMessageStreamRoute => f.write_str("record message stream route"),
            Self::RecordMessageStreamRow => f.write_str("record message stream row"),
            Self::RecordMessageStreamRowAbsent => f.write_str("record message stream row absent"),
            Self::RecordMessageStreamSignatureResult => {
                f.write_str("record message stream signature result")
            }
            Self::RecordMessageStreamSubmissionWidth => {
                f.write_str("record message stream submission width")
            }
            Self::RecordMessageStreamUnexpectedObservation => {
                f.write_str("record message stream unexpected observation")
            }
            Self::RecordMessageStreamVerificationInput => {
                f.write_str("record message stream verification input")
            }
            Self::RecordMessageWidth => f.write_str("record message width"),
            Self::RecordMixedMessageInitLayouts => f.write_str("record mixed message Init layouts"),
            Self::RecordNonceOrigin => f.write_str("record nonce origin"),
            Self::RecordPlannedMessageProgressed => {
                f.write_str("record planned message progressed")
            }
            Self::RecordResidualRange => f.write_str("record residual range"),
            Self::RecordSizeConversion => f.write_str("record size conversion"),
            Self::SignatureRecordParameters => f.write_str("signature record parameters"),
            Self::TerminalMessageStreamReportAbsent => {
                f.write_str("terminal message stream report absent")
            }
        }
    }
}
