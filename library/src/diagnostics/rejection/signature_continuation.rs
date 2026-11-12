// SPDX-License-Identifier: Apache-2.0
//! SignatureContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to signature continuation.
#[doc = include_str!("../../../docs/diagnostics/rejection-signature_continuation.md")]
pub enum SignatureContinuationRejection {
    /// No native signature call is available in this operation phase. [Detection, owner and recovery](#cause-SignatureNotActive).
    SignatureNotActive,
    /// Changed signature snapshot input. [Detection, owner and recovery](#cause-ChangedSignatureSnapshotInput).
    ChangedSignatureSnapshotInput,
    /// Cipher authentication role absent. [Detection, owner and recovery](#cause-CipherAuthenticationRoleAbsent).
    CipherAuthenticationRoleAbsent,
    /// Cipher writer declaration absent. [Detection, owner and recovery](#cause-CipherWriterDeclarationAbsent).
    CipherWriterDeclarationAbsent,
    /// Classic signature facade route. [Detection, owner and recovery](#cause-ClassicSignatureFacadeRoute).
    ClassicSignatureFacadeRoute,
    /// Competing Init owner absent. [Detection, owner and recovery](#cause-CompetingInitOwnerAbsent).
    CompetingInitOwnerAbsent,
    /// Competing signature Init outcome uncertain. [Detection, owner and recovery](#cause-CompetingSignatureInitOutcomeUncertain).
    CompetingSignatureInitOutcomeUncertain,
    /// Conflicting Init returned no error. [Detection, owner and recovery](#cause-ConflictingInitReturnedNoError).
    ConflictingInitReturnedNoError,
    /// Consumed signature ticket. [Detection, owner and recovery](#cause-ConsumedSignatureTicket).
    ConsumedSignatureTicket,
    /// Explicit signature declaration mismatch. [Detection, owner and recovery](#cause-ExplicitSignatureDeclarationMismatch).
    ExplicitSignatureDeclarationMismatch,
    /// Foreign cipher destination. [Detection, owner and recovery](#cause-ForeignCipherDestination).
    ForeignCipherDestination,
    /// Foreign signature destination. [Detection, owner and recovery](#cause-ForeignSignatureDestination).
    ForeignSignatureDestination,
    /// Native cipher writer destination required. [Detection, owner and recovery](#cause-NativeCipherWriterDestinationRequired).
    NativeCipherWriterDestinationRequired,
    /// Native destination permissions absent. [Detection, owner and recovery](#cause-NativeDestinationPermissionsAbsent).
    NativeDestinationPermissionsAbsent,
    /// Native destination storage not prepared. [Detection, owner and recovery](#cause-NativeDestinationStorageNotPrepared).
    NativeDestinationStorageNotPrepared,
    /// Native signature destination required. [Detection, owner and recovery](#cause-NativeSignatureDestinationRequired).
    NativeSignatureDestinationRequired,
    /// Native transfer storage absent. [Detection, owner and recovery](#cause-NativeTransferStorageAbsent).
    NativeTransferStorageAbsent,
    /// Revoked signature destination. [Detection, owner and recovery](#cause-RevokedSignatureDestination).
    RevokedSignatureDestination,
    /// Revoked signature key. [Detection, owner and recovery](#cause-RevokedSignatureKey).
    RevokedSignatureKey,
    /// Signature Update did not establish input boundary. [Detection, owner and recovery](#cause-SignatureUpdateDidNotEstablishInputBoundary).
    SignatureUpdateDidNotEstablishInputBoundary,
    /// Signature continuation route. [Detection, owner and recovery](#cause-SignatureContinuationRoute).
    SignatureContinuationRoute,
    /// Signature continuation ticket unavailable. [Detection, owner and recovery](#cause-SignatureContinuationTicketUnavailable).
    SignatureContinuationTicketUnavailable,
    /// Signature destination binding absent. [Detection, owner and recovery](#cause-SignatureDestinationBindingAbsent).
    SignatureDestinationBindingAbsent,
    /// Signature destination declaration changed. [Detection, owner and recovery](#cause-SignatureDestinationDeclarationChanged).
    SignatureDestinationDeclarationChanged,
    /// Signature destination representation changed. [Detection, owner and recovery](#cause-SignatureDestinationRepresentationChanged).
    SignatureDestinationRepresentationChanged,
    /// Signature facade incomplete. [Detection, owner and recovery](#cause-SignatureFacadeIncomplete).
    SignatureFacadeIncomplete,
    /// Signature finish operands. [Detection, owner and recovery](#cause-SignatureFinishOperands).
    SignatureFinishOperands,
    /// Signature has no cipher key role. [Detection, owner and recovery](#cause-SignatureHasNoCipherKeyRole).
    SignatureHasNoCipherKeyRole,
    /// Signature import declaration mismatch. [Detection, owner and recovery](#cause-SignatureImportDeclarationMismatch).
    SignatureImportDeclarationMismatch,
    /// Signature initial operands. [Detection, owner and recovery](#cause-SignatureInitialOperands).
    SignatureInitialOperands,
    /// Signature input absent. [Detection, owner and recovery](#cause-SignatureInputAbsent).
    SignatureInputAbsent,
    /// Signature input accounting. [Detection, owner and recovery](#cause-SignatureInputAccounting).
    SignatureInputAccounting,
    /// Signature input boundary unavailable. [Detection, owner and recovery](#cause-SignatureInputBoundaryUnavailable).
    SignatureInputBoundaryUnavailable,
    /// Signature is not waiting for storage. [Detection, owner and recovery](#cause-SignatureIsNotWaitingForStorage).
    SignatureIsNotWaitingForStorage,
    /// Signature length width. [Detection, owner and recovery](#cause-SignatureLengthWidth).
    SignatureLengthWidth,
    /// Signature native input mutation. [Detection, owner and recovery](#cause-SignatureNativeInputMutation).
    SignatureNativeInputMutation,
    /// Signature native length width. [Detection, owner and recovery](#cause-SignatureNativeLengthWidth).
    SignatureNativeLengthWidth,
    /// Signature native termination uncertain. [Detection, owner and recovery](#cause-SignatureNativeTerminationUncertain).
    SignatureNativeTerminationUncertain,
    /// Signature not at a capturable boundary. [Detection, owner and recovery](#cause-SignatureNotAtACapturableBoundary).
    SignatureNotAtACapturableBoundary,
    /// Signature operation accounting. [Detection, owner and recovery](#cause-SignatureOperationAccounting).
    SignatureOperationAccounting,
    /// Signature output alignment. [Detection, owner and recovery](#cause-SignatureOutputAlignment).
    SignatureOutputAlignment,
    /// Signature output alignment accounting. [Detection, owner and recovery](#cause-SignatureOutputAlignmentAccounting).
    SignatureOutputAlignmentAccounting,
    /// Signature output capacity. [Detection, owner and recovery](#cause-SignatureOutputCapacity).
    SignatureOutputCapacity,
    /// Signature output ceiling. [Detection, owner and recovery](#cause-SignatureOutputCeiling).
    SignatureOutputCeiling,
    /// Signature phase not serializable. [Detection, owner and recovery](#cause-SignaturePhaseNotSerializable).
    SignaturePhaseNotSerializable,
    /// Signature prepared output width. [Detection, owner and recovery](#cause-SignaturePreparedOutputWidth).
    SignaturePreparedOutputWidth,
    /// Signature reconstruction accounting. [Detection, owner and recovery](#cause-SignatureReconstructionAccounting).
    SignatureReconstructionAccounting,
    /// Signature result already published. [Detection, owner and recovery](#cause-SignatureResultAlreadyPublished).
    SignatureResultAlreadyPublished,
    /// Signature result incomplete. [Detection, owner and recovery](#cause-SignatureResultIncomplete).
    SignatureResultIncomplete,
    /// Signature revocation accounting. [Detection, owner and recovery](#cause-SignatureRevocationAccounting).
    SignatureRevocationAccounting,
    /// Signature roles not prepared. [Detection, owner and recovery](#cause-SignatureRolesNotPrepared).
    SignatureRolesNotPrepared,
    /// Signature snapshot accounting. [Detection, owner and recovery](#cause-SignatureSnapshotAccounting).
    SignatureSnapshotAccounting,
    /// Signature snapshot shape changed. [Detection, owner and recovery](#cause-SignatureSnapshotShapeChanged).
    SignatureSnapshotShapeChanged,
    /// Signature stream extension route. [Detection, owner and recovery](#cause-SignatureStreamExtensionRoute).
    SignatureStreamExtensionRoute,
    /// Single signature extension route. [Detection, owner and recovery](#cause-SingleSignatureExtensionRoute).
    SingleSignatureExtensionRoute,
    /// Uncopied signature snapshot. [Detection, owner and recovery](#cause-UncopiedSignatureSnapshot).
    UncopiedSignatureSnapshot,
    /// Unsubmitted signature binding cannot be duplicated. [Detection, owner and recovery](#cause-UnsubmittedSignatureBindingCannotBeDuplicated).
    UnsubmittedSignatureBindingCannotBeDuplicated,
    /// Verification signature not supplied. [Detection, owner and recovery](#cause-VerificationSignatureNotSupplied).
    VerificationSignatureNotSupplied,
}

impl std::fmt::Display for SignatureContinuationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureNotActive => f.write_str("signature operation is not active"),
            Self::ChangedSignatureSnapshotInput => f.write_str("changed signature snapshot input"),
            Self::CipherAuthenticationRoleAbsent => {
                f.write_str("cipher authentication role absent")
            }
            Self::CipherWriterDeclarationAbsent => f.write_str("cipher writer declaration absent"),
            Self::ClassicSignatureFacadeRoute => f.write_str("classic signature facade route"),
            Self::CompetingInitOwnerAbsent => f.write_str("competing Init owner absent"),
            Self::CompetingSignatureInitOutcomeUncertain => {
                f.write_str("competing signature Init outcome uncertain")
            }
            Self::ConflictingInitReturnedNoError => {
                f.write_str("conflicting Init returned no error")
            }
            Self::ConsumedSignatureTicket => f.write_str("consumed signature ticket"),
            Self::ExplicitSignatureDeclarationMismatch => {
                f.write_str("explicit signature declaration mismatch")
            }
            Self::ForeignCipherDestination => f.write_str("foreign cipher destination"),
            Self::ForeignSignatureDestination => f.write_str("foreign signature destination"),
            Self::NativeCipherWriterDestinationRequired => {
                f.write_str("native cipher writer destination required")
            }
            Self::NativeDestinationPermissionsAbsent => {
                f.write_str("native destination permissions absent")
            }
            Self::NativeDestinationStorageNotPrepared => {
                f.write_str("native destination storage not prepared")
            }
            Self::NativeSignatureDestinationRequired => {
                f.write_str("native signature destination required")
            }
            Self::NativeTransferStorageAbsent => f.write_str("native transfer storage absent"),
            Self::RevokedSignatureDestination => f.write_str("revoked signature destination"),
            Self::RevokedSignatureKey => f.write_str("revoked signature key"),
            Self::SignatureUpdateDidNotEstablishInputBoundary => {
                f.write_str("signature Update did not establish input boundary")
            }
            Self::SignatureContinuationRoute => f.write_str("signature continuation route"),
            Self::SignatureContinuationTicketUnavailable => {
                f.write_str("signature continuation ticket unavailable")
            }
            Self::SignatureDestinationBindingAbsent => {
                f.write_str("signature destination binding absent")
            }
            Self::SignatureDestinationDeclarationChanged => {
                f.write_str("signature destination declaration changed")
            }
            Self::SignatureDestinationRepresentationChanged => {
                f.write_str("signature destination representation changed")
            }
            Self::SignatureFacadeIncomplete => f.write_str("signature facade incomplete"),
            Self::SignatureFinishOperands => f.write_str("signature finish operands"),
            Self::SignatureHasNoCipherKeyRole => f.write_str("signature has no cipher key role"),
            Self::SignatureImportDeclarationMismatch => {
                f.write_str("signature import declaration mismatch")
            }
            Self::SignatureInitialOperands => f.write_str("signature initial operands"),
            Self::SignatureInputAbsent => f.write_str("signature input absent"),
            Self::SignatureInputAccounting => f.write_str("signature input accounting"),
            Self::SignatureInputBoundaryUnavailable => {
                f.write_str("signature input boundary unavailable")
            }
            Self::SignatureIsNotWaitingForStorage => {
                f.write_str("signature is not waiting for storage")
            }
            Self::SignatureLengthWidth => f.write_str("signature length width"),
            Self::SignatureNativeInputMutation => f.write_str("signature native input mutation"),
            Self::SignatureNativeLengthWidth => f.write_str("signature native length width"),
            Self::SignatureNativeTerminationUncertain => {
                f.write_str("signature native termination uncertain")
            }
            Self::SignatureNotAtACapturableBoundary => {
                f.write_str("signature not at a capturable boundary")
            }
            Self::SignatureOperationAccounting => f.write_str("signature operation accounting"),
            Self::SignatureOutputAlignment => f.write_str("signature output alignment"),
            Self::SignatureOutputAlignmentAccounting => {
                f.write_str("signature output alignment accounting")
            }
            Self::SignatureOutputCapacity => f.write_str("signature output capacity"),
            Self::SignatureOutputCeiling => f.write_str("signature output ceiling"),
            Self::SignaturePhaseNotSerializable => f.write_str("signature phase not serializable"),
            Self::SignaturePreparedOutputWidth => f.write_str("signature prepared output width"),
            Self::SignatureReconstructionAccounting => {
                f.write_str("signature reconstruction accounting")
            }
            Self::SignatureResultAlreadyPublished => {
                f.write_str("signature result already published")
            }
            Self::SignatureResultIncomplete => f.write_str("signature result incomplete"),
            Self::SignatureRevocationAccounting => f.write_str("signature revocation accounting"),
            Self::SignatureRolesNotPrepared => f.write_str("signature roles not prepared"),
            Self::SignatureSnapshotAccounting => f.write_str("signature snapshot accounting"),
            Self::SignatureSnapshotShapeChanged => f.write_str("signature snapshot shape changed"),
            Self::SignatureStreamExtensionRoute => f.write_str("signature stream extension route"),
            Self::SingleSignatureExtensionRoute => f.write_str("single signature extension route"),
            Self::UncopiedSignatureSnapshot => f.write_str("uncopied signature snapshot"),
            Self::UnsubmittedSignatureBindingCannotBeDuplicated => {
                f.write_str("unsubmitted signature binding cannot be duplicated")
            }
            Self::VerificationSignatureNotSupplied => {
                f.write_str("verification signature not supplied")
            }
        }
    }
}
