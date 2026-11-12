// SPDX-License-Identifier: Apache-2.0
//! CheckpointFormat causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to checkpoint format.
#[doc = include_str!("../../../docs/diagnostics/rejection-checkpoint_format.md")]
pub enum CheckpointFormatRejection {
    /// Caller-fed AEAD native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-CallerFedAeadAsynchronousModeUnavailable).
    CallerFedAeadAsynchronousModeUnavailable,
    /// Checkpoint symmetric profile. [Detection, owner and recovery](#cause-CheckpointSymmetricProfile).
    CheckpointSymmetricProfile,
    /// Cipher graph on another record family. [Detection, owner and recovery](#cause-CipherGraphOnAnotherRecordFamily).
    CipherGraphOnAnotherRecordFamily,
    /// Cipher options on another record family. [Detection, owner and recovery](#cause-CipherOptionsOnAnotherRecordFamily).
    CipherOptionsOnAnotherRecordFamily,
    /// Detached active message absent. [Detection, owner and recovery](#cause-DetachedActiveMessageAbsent).
    DetachedActiveMessageAbsent,
    /// Detached cryptographic family. [Detection, owner and recovery](#cause-DetachedCryptographicFamily).
    DetachedCryptographicFamily,
    /// Detached input length. [Detection, owner and recovery](#cause-DetachedInputLength).
    DetachedInputLength,
    /// Detached message absent. [Detection, owner and recovery](#cause-DetachedMessageAbsent).
    DetachedMessageAbsent,
    /// Detached output capacity. [Detection, owner and recovery](#cause-DetachedOutputCapacity).
    DetachedOutputCapacity,
    /// Detached output ceiling. [Detection, owner and recovery](#cause-DetachedOutputCeiling).
    DetachedOutputCeiling,
    /// Detached output progression. [Detection, owner and recovery](#cause-DetachedOutputProgression).
    DetachedOutputProgression,
    /// Digest OID on a non-digest record. [Detection, owner and recovery](#cause-DigestOidOnANonDigestRecord).
    DigestOidOnANonDigestRecord,
    /// Digest extension on another family. [Detection, owner and recovery](#cause-DigestExtensionOnAnotherFamily).
    DigestExtensionOnAnotherFamily,
    /// Digest output on another family. [Detection, owner and recovery](#cause-DigestOutputOnAnotherFamily).
    DigestOutputOnAnotherFamily,
    /// Digest output storage absent. [Detection, owner and recovery](#cause-DigestOutputStorageAbsent).
    DigestOutputStorageAbsent,
    /// Digest output storage limit. [Detection, owner and recovery](#cause-DigestOutputStorageLimit).
    DigestOutputStorageLimit,
    /// Digest output wait is not a retained terminal. [Detection, owner and recovery](#cause-DigestOutputWaitIsNotARetainedTerminal).
    DigestOutputWaitIsNotARetainedTerminal,
    /// Digest parameters on another record family. [Detection, owner and recovery](#cause-DigestParametersOnAnotherRecordFamily).
    DigestParametersOnAnotherRecordFamily,
    /// Native block-cipher native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-NativeBlockCipherAsynchronousModeUnavailable).
    NativeBlockCipherAsynchronousModeUnavailable,
    /// Native signature validation dispatch. [Detection, owner and recovery](#cause-NativeSignatureValidationDispatch).
    NativeSignatureValidationDispatch,
    /// Record AEAD output. [Detection, owner and recovery](#cause-RecordAeadOutput).
    RecordAeadOutput,
    /// Record AEAD parameter selection. [Detection, owner and recovery](#cause-RecordAeadParameterSelection).
    RecordAeadParameterSelection,
    /// Record AES profile. [Detection, owner and recovery](#cause-RecordAesProfile).
    RecordAesProfile,
    /// Record CCM MAC alignment. [Detection, owner and recovery](#cause-RecordCcmMacAlignment).
    RecordCcmMacAlignment,
    /// Record CCM fixed bits. [Detection, owner and recovery](#cause-RecordCcmFixedBits).
    RecordCcmFixedBits,
    /// Record CCM generator. [Detection, owner and recovery](#cause-RecordCcmGenerator).
    RecordCcmGenerator,
    /// Record CCM initial nonce. [Detection, owner and recovery](#cause-RecordCcmInitialNonce).
    RecordCcmInitialNonce,
    /// Record CTR counter width absent. [Detection, owner and recovery](#cause-RecordCtrCounterWidthAbsent).
    RecordCtrCounterWidthAbsent,
    /// Record IV fixed bits absent. [Detection, owner and recovery](#cause-RecordIvFixedBitsAbsent).
    RecordIvFixedBitsAbsent,
    /// Record IV generator absent. [Detection, owner and recovery](#cause-RecordIvGeneratorAbsent).
    RecordIvGeneratorAbsent,
    /// Record Init layout for a non-AEAD message family. [Detection, owner and recovery](#cause-RecordInitLayoutForANonAeadMessageFamily).
    RecordInitLayoutForANonAeadMessageFamily,
    /// Record MAC key. [Detection, owner and recovery](#cause-RecordMacKey).
    RecordMacKey,
    /// Record MAC profile. [Detection, owner and recovery](#cause-RecordMacProfile).
    RecordMacProfile,
    /// Record RSA profile. [Detection, owner and recovery](#cause-RecordRsaProfile).
    RecordRsaProfile,
    /// Record active message phase. [Detection, owner and recovery](#cause-RecordActiveMessagePhase).
    RecordActiveMessagePhase,
    /// Record batch final phase. [Detection, owner and recovery](#cause-RecordBatchFinalPhase).
    RecordBatchFinalPhase,
    /// Record buffered message input state. [Detection, owner and recovery](#cause-RecordBufferedMessageInputState).
    RecordBufferedMessageInputState,
    /// Record carried message unfinished. [Detection, owner and recovery](#cause-RecordCarriedMessageUnfinished).
    RecordCarriedMessageUnfinished,
    /// Record carried prefix. [Detection, owner and recovery](#cause-RecordCarriedPrefix).
    RecordCarriedPrefix,
    /// Record carried prefix width. [Detection, owner and recovery](#cause-RecordCarriedPrefixWidth).
    RecordCarriedPrefixWidth,
    /// Record cipher init progression. [Detection, owner and recovery](#cause-RecordCipherInitProgression).
    RecordCipherInitProgression,
    /// Record cipher mechanism. [Detection, owner and recovery](#cause-RecordCipherMechanism).
    RecordCipherMechanism,
    /// Record cipher nonce. [Detection, owner and recovery](#cause-RecordCipherNonce).
    RecordCipherNonce,
    /// Record cipher observation association. [Detection, owner and recovery](#cause-RecordCipherObservationAssociation).
    RecordCipherObservationAssociation,
    /// Record cipher parameters. [Detection, owner and recovery](#cause-RecordCipherParameters).
    RecordCipherParameters,
    /// Record classic batch. [Detection, owner and recovery](#cause-RecordClassicBatch).
    RecordClassicBatch,
    /// Record consumed length. [Detection, owner and recovery](#cause-RecordConsumedLength).
    RecordConsumedLength,
    /// Record counter width on non-CTR operation. [Detection, owner and recovery](#cause-RecordCounterWidthOnNonCtrOperation).
    RecordCounterWidthOnNonCtrOperation,
    /// Record descriptor flags. [Detection, owner and recovery](#cause-RecordDescriptorFlags).
    RecordDescriptorFlags,
    /// Record digest parameters. [Detection, owner and recovery](#cause-RecordDigestParameters).
    RecordDigestParameters,
    /// Record digest phase. [Detection, owner and recovery](#cause-RecordDigestPhase).
    RecordDigestPhase,
    /// Record dual MAC class. [Detection, owner and recovery](#cause-RecordDualMacClass).
    RecordDualMacClass,
    /// Record dual active state. [Detection, owner and recovery](#cause-RecordDualActiveState).
    RecordDualActiveState,
    /// Record dual capacity. [Detection, owner and recovery](#cause-RecordDualCapacity).
    RecordDualCapacity,
    /// Record dual phase. [Detection, owner and recovery](#cause-RecordDualPhase).
    RecordDualPhase,
    /// Record empty operation. [Detection, owner and recovery](#cause-RecordEmptyOperation).
    RecordEmptyOperation,
    /// Record expected MAC. [Detection, owner and recovery](#cause-RecordExpectedMac).
    RecordExpectedMac,
    /// Record final progression. [Detection, owner and recovery](#cause-RecordFinalProgression).
    RecordFinalProgression,
    /// Record finalized cipher length. [Detection, owner and recovery](#cause-RecordFinalizedCipherLength).
    RecordFinalizedCipherLength,
    /// Record inactive classic operation. [Detection, owner and recovery](#cause-RecordInactiveClassicOperation).
    RecordInactiveClassicOperation,
    /// Record initial IV absent. [Detection, owner and recovery](#cause-RecordInitialIvAbsent).
    RecordInitialIvAbsent,
    /// Record initial progression. [Detection, owner and recovery](#cause-RecordInitialProgression).
    RecordInitialProgression,
    /// Record input length. [Detection, owner and recovery](#cause-RecordInputLength).
    RecordInputLength,
    /// Record message byte counter. [Detection, owner and recovery](#cause-RecordMessageByteCounter).
    RecordMessageByteCounter,
    /// Record message observation association. [Detection, owner and recovery](#cause-RecordMessageObservationAssociation).
    RecordMessageObservationAssociation,
    /// Record message output counter. [Detection, owner and recovery](#cause-RecordMessageOutputCounter).
    RecordMessageOutputCounter,
    /// Record message phase. [Detection, owner and recovery](#cause-RecordMessagePhase).
    RecordMessagePhase,
    /// Record message progress mismatch. [Detection, owner and recovery](#cause-RecordMessageProgressMismatch).
    RecordMessageProgressMismatch,
    /// Record message submission counter. [Detection, owner and recovery](#cause-RecordMessageSubmissionCounter).
    RecordMessageSubmissionCounter,
    /// Record message submission width. [Detection, owner and recovery](#cause-RecordMessageSubmissionWidth).
    RecordMessageSubmissionWidth,
    /// Record missing cipher observation. [Detection, owner and recovery](#cause-RecordMissingCipherObservation).
    RecordMissingCipherObservation,
    /// Record missing message observation. [Detection, owner and recovery](#cause-RecordMissingMessageObservation).
    RecordMissingMessageObservation,
    /// Record mixed routes. [Detection, owner and recovery](#cause-RecordMixedRoutes).
    RecordMixedRoutes,
    /// Record native AEAD key profile. [Detection, owner and recovery](#cause-RecordNativeAeadKeyProfile).
    RecordNativeAeadKeyProfile,
    /// Record non-AEAD nonce selection. [Detection, owner and recovery](#cause-RecordNonAeadNonceSelection).
    RecordNonAeadNonceSelection,
    /// Record operation family. [Detection, owner and recovery](#cause-RecordOperationFamily).
    RecordOperationFamily,
    /// Record output precedes input. [Detection, owner and recovery](#cause-RecordOutputPrecedesInput).
    RecordOutputPrecedesInput,
    /// Record premature dual authentication. [Detection, owner and recovery](#cause-RecordPrematureDualAuthentication).
    RecordPrematureDualAuthentication,
    /// Record premature signature. [Detection, owner and recovery](#cause-RecordPrematureSignature).
    RecordPrematureSignature,
    /// Record profile key roles. [Detection, owner and recovery](#cause-RecordProfileKeyRoles).
    RecordProfileKeyRoles,
    /// Record required validation absent. [Detection, owner and recovery](#cause-RecordRequiredValidationAbsent).
    RecordRequiredValidationAbsent,
    /// Record retained message submission. [Detection, owner and recovery](#cause-RecordRetainedMessageSubmission).
    RecordRetainedMessageSubmission,
    /// Record signature association. [Detection, owner and recovery](#cause-RecordSignatureAssociation).
    RecordSignatureAssociation,
    /// Record signature capacity. [Detection, owner and recovery](#cause-RecordSignatureCapacity).
    RecordSignatureCapacity,
    /// Record signature parameter family. [Detection, owner and recovery](#cause-RecordSignatureParameterFamily).
    RecordSignatureParameterFamily,
    /// Record signature parameters. [Detection, owner and recovery](#cause-RecordSignatureParameters).
    RecordSignatureParameters,
    /// Record signature result. [Detection, owner and recovery](#cause-RecordSignatureResult).
    RecordSignatureResult,
    /// Record single digest progression. [Detection, owner and recovery](#cause-RecordSingleDigestProgression).
    RecordSingleDigestProgression,
    /// Record single message progress. [Detection, owner and recovery](#cause-RecordSingleMessageProgress).
    RecordSingleMessageProgress,
    /// Record stream AEAD key profile. [Detection, owner and recovery](#cause-RecordStreamAeadKeyProfile).
    RecordStreamAeadKeyProfile,
    /// Record stream AEAD nonce. [Detection, owner and recovery](#cause-RecordStreamAeadNonce).
    RecordStreamAeadNonce,
    /// Record stream AEAD parameters. [Detection, owner and recovery](#cause-RecordStreamAeadParameters).
    RecordStreamAeadParameters,
    /// Record token IV direction. [Detection, owner and recovery](#cause-RecordTokenIvDirection).
    RecordTokenIvDirection,
    /// Record unexpected residual. [Detection, owner and recovery](#cause-RecordUnexpectedResidual).
    RecordUnexpectedResidual,
    /// Record unexpected validation observation. [Detection, owner and recovery](#cause-RecordUnexpectedValidationObservation).
    RecordUnexpectedValidationObservation,
    /// Record update progression. [Detection, owner and recovery](#cause-RecordUpdateProgression).
    RecordUpdateProgression,
    /// Record validation capacity. [Detection, owner and recovery](#cause-RecordValidationCapacity).
    RecordValidationCapacity,
    /// Record validation owner capacity. [Detection, owner and recovery](#cause-RecordValidationOwnerCapacity).
    RecordValidationOwnerCapacity,
    /// Record validation request. [Detection, owner and recovery](#cause-RecordValidationRequest).
    RecordValidationRequest,
    /// Recovery cannot retain a native capacity call. [Detection, owner and recovery](#cause-RecoveryCannotRetainANativeCapacityCall).
    RecoveryCannotRetainANativeCapacityCall,
    /// Recovery family or output continuation. [Detection, owner and recovery](#cause-RecoveryFamilyOrOutputContinuation).
    RecoveryFamilyOrOutputContinuation,
    /// Recovery mixed routes. [Detection, owner and recovery](#cause-RecoveryMixedRoutes).
    RecoveryMixedRoutes,
    /// Recovery unauthenticated progression. [Detection, owner and recovery](#cause-RecoveryUnauthenticatedProgression).
    RecoveryUnauthenticatedProgression,
    /// Saved record kind. [Detection, owner and recovery](#cause-SavedRecordKind).
    SavedRecordKind,
    /// Signature parameters on another family. [Detection, owner and recovery](#cause-SignatureParametersOnAnotherFamily).
    SignatureParametersOnAnotherFamily,
}

impl std::fmt::Display for CheckpointFormatRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CallerFedAeadAsynchronousModeUnavailable => {
                f.write_str("caller-fed AEAD native asynchronous mode is unsupported")
            }
            Self::CheckpointSymmetricProfile => f.write_str("checkpoint symmetric profile"),
            Self::CipherGraphOnAnotherRecordFamily => {
                f.write_str("cipher graph on another record family")
            }
            Self::CipherOptionsOnAnotherRecordFamily => {
                f.write_str("cipher options on another record family")
            }
            Self::DetachedActiveMessageAbsent => f.write_str("detached active message absent"),
            Self::DetachedCryptographicFamily => f.write_str("detached cryptographic family"),
            Self::DetachedInputLength => f.write_str("detached input length"),
            Self::DetachedMessageAbsent => f.write_str("detached message absent"),
            Self::DetachedOutputCapacity => f.write_str("detached output capacity"),
            Self::DetachedOutputCeiling => f.write_str("detached output ceiling"),
            Self::DetachedOutputProgression => f.write_str("detached output progression"),
            Self::DigestOidOnANonDigestRecord => f.write_str("digest OID on a non-digest record"),
            Self::DigestExtensionOnAnotherFamily => {
                f.write_str("digest extension on another family")
            }
            Self::DigestOutputOnAnotherFamily => f.write_str("digest output on another family"),
            Self::DigestOutputStorageAbsent => f.write_str("digest output storage absent"),
            Self::DigestOutputStorageLimit => f.write_str("digest output storage limit"),
            Self::DigestOutputWaitIsNotARetainedTerminal => {
                f.write_str("digest output wait is not a retained terminal")
            }
            Self::DigestParametersOnAnotherRecordFamily => {
                f.write_str("digest parameters on another record family")
            }
            Self::NativeBlockCipherAsynchronousModeUnavailable => {
                f.write_str("native block-cipher native asynchronous mode is unsupported")
            }
            Self::NativeSignatureValidationDispatch => {
                f.write_str("native signature validation dispatch")
            }
            Self::RecordAeadOutput => f.write_str("record AEAD output"),
            Self::RecordAeadParameterSelection => f.write_str("record AEAD parameter selection"),
            Self::RecordAesProfile => f.write_str("record AES profile"),
            Self::RecordCcmMacAlignment => f.write_str("record CCM MAC alignment"),
            Self::RecordCcmFixedBits => f.write_str("record CCM fixed bits"),
            Self::RecordCcmGenerator => f.write_str("record CCM generator"),
            Self::RecordCcmInitialNonce => f.write_str("record CCM initial nonce"),
            Self::RecordCtrCounterWidthAbsent => f.write_str("record CTR counter width absent"),
            Self::RecordIvFixedBitsAbsent => f.write_str("record IV fixed bits absent"),
            Self::RecordIvGeneratorAbsent => f.write_str("record IV generator absent"),
            Self::RecordInitLayoutForANonAeadMessageFamily => {
                f.write_str("record Init layout for a non-AEAD message family")
            }
            Self::RecordMacKey => f.write_str("record MAC key"),
            Self::RecordMacProfile => f.write_str("record MAC profile"),
            Self::RecordRsaProfile => f.write_str("record RSA profile"),
            Self::RecordActiveMessagePhase => f.write_str("record active message phase"),
            Self::RecordBatchFinalPhase => f.write_str("record batch final phase"),
            Self::RecordBufferedMessageInputState => {
                f.write_str("record buffered message input state")
            }
            Self::RecordCarriedMessageUnfinished => {
                f.write_str("record carried message unfinished")
            }
            Self::RecordCarriedPrefix => f.write_str("record carried prefix"),
            Self::RecordCarriedPrefixWidth => f.write_str("record carried prefix width"),
            Self::RecordCipherInitProgression => f.write_str("record cipher init progression"),
            Self::RecordCipherMechanism => f.write_str("record cipher mechanism"),
            Self::RecordCipherNonce => f.write_str("record cipher nonce"),
            Self::RecordCipherObservationAssociation => {
                f.write_str("record cipher observation association")
            }
            Self::RecordCipherParameters => f.write_str("record cipher parameters"),
            Self::RecordClassicBatch => f.write_str("record classic batch"),
            Self::RecordConsumedLength => f.write_str("record consumed length"),
            Self::RecordCounterWidthOnNonCtrOperation => {
                f.write_str("record counter width on non-CTR operation")
            }
            Self::RecordDescriptorFlags => f.write_str("record descriptor flags"),
            Self::RecordDigestParameters => f.write_str("record digest parameters"),
            Self::RecordDigestPhase => f.write_str("record digest phase"),
            Self::RecordDualMacClass => f.write_str("record dual MAC class"),
            Self::RecordDualActiveState => f.write_str("record dual active state"),
            Self::RecordDualCapacity => f.write_str("record dual capacity"),
            Self::RecordDualPhase => f.write_str("record dual phase"),
            Self::RecordEmptyOperation => f.write_str("record empty operation"),
            Self::RecordExpectedMac => f.write_str("record expected MAC"),
            Self::RecordFinalProgression => f.write_str("record final progression"),
            Self::RecordFinalizedCipherLength => f.write_str("record finalized cipher length"),
            Self::RecordInactiveClassicOperation => {
                f.write_str("record inactive classic operation")
            }
            Self::RecordInitialIvAbsent => f.write_str("record initial IV absent"),
            Self::RecordInitialProgression => f.write_str("record initial progression"),
            Self::RecordInputLength => f.write_str("record input length"),
            Self::RecordMessageByteCounter => f.write_str("record message byte counter"),
            Self::RecordMessageObservationAssociation => {
                f.write_str("record message observation association")
            }
            Self::RecordMessageOutputCounter => f.write_str("record message output counter"),
            Self::RecordMessagePhase => f.write_str("record message phase"),
            Self::RecordMessageProgressMismatch => f.write_str("record message progress mismatch"),
            Self::RecordMessageSubmissionCounter => {
                f.write_str("record message submission counter")
            }
            Self::RecordMessageSubmissionWidth => f.write_str("record message submission width"),
            Self::RecordMissingCipherObservation => {
                f.write_str("record missing cipher observation")
            }
            Self::RecordMissingMessageObservation => {
                f.write_str("record missing message observation")
            }
            Self::RecordMixedRoutes => f.write_str("record mixed routes"),
            Self::RecordNativeAeadKeyProfile => f.write_str("record native AEAD key profile"),
            Self::RecordNonAeadNonceSelection => f.write_str("record non-AEAD nonce selection"),
            Self::RecordOperationFamily => f.write_str("record operation family"),
            Self::RecordOutputPrecedesInput => f.write_str("record output precedes input"),
            Self::RecordPrematureDualAuthentication => {
                f.write_str("record premature dual authentication")
            }
            Self::RecordPrematureSignature => f.write_str("record premature signature"),
            Self::RecordProfileKeyRoles => f.write_str("record profile key roles"),
            Self::RecordRequiredValidationAbsent => {
                f.write_str("record required validation absent")
            }
            Self::RecordRetainedMessageSubmission => {
                f.write_str("record retained message submission")
            }
            Self::RecordSignatureAssociation => f.write_str("record signature association"),
            Self::RecordSignatureCapacity => f.write_str("record signature capacity"),
            Self::RecordSignatureParameterFamily => {
                f.write_str("record signature parameter family")
            }
            Self::RecordSignatureParameters => f.write_str("record signature parameters"),
            Self::RecordSignatureResult => f.write_str("record signature result"),
            Self::RecordSingleDigestProgression => f.write_str("record single digest progression"),
            Self::RecordSingleMessageProgress => f.write_str("record single message progress"),
            Self::RecordStreamAeadKeyProfile => f.write_str("record stream AEAD key profile"),
            Self::RecordStreamAeadNonce => f.write_str("record stream AEAD nonce"),
            Self::RecordStreamAeadParameters => f.write_str("record stream AEAD parameters"),
            Self::RecordTokenIvDirection => f.write_str("record token IV direction"),
            Self::RecordUnexpectedResidual => f.write_str("record unexpected residual"),
            Self::RecordUnexpectedValidationObservation => {
                f.write_str("record unexpected validation observation")
            }
            Self::RecordUpdateProgression => f.write_str("record update progression"),
            Self::RecordValidationCapacity => f.write_str("record validation capacity"),
            Self::RecordValidationOwnerCapacity => f.write_str("record validation owner capacity"),
            Self::RecordValidationRequest => f.write_str("record validation request"),
            Self::RecoveryCannotRetainANativeCapacityCall => {
                f.write_str("recovery cannot retain a native capacity call")
            }
            Self::RecoveryFamilyOrOutputContinuation => {
                f.write_str("recovery family or output continuation")
            }
            Self::RecoveryMixedRoutes => f.write_str("recovery mixed routes"),
            Self::RecoveryUnauthenticatedProgression => {
                f.write_str("recovery unauthenticated progression")
            }
            Self::SavedRecordKind => f.write_str("saved record kind"),
            Self::SignatureParametersOnAnotherFamily => {
                f.write_str("signature parameters on another family")
            }
        }
    }
}
