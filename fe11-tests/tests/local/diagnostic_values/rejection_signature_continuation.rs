// SPDX-License-Identifier: Apache-2.0
//! Public SignatureContinuationRejection values retain identity through category conversion.
use fe11::{Error, RejectionReason, SignatureContinuationRejection};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        SignatureContinuationRejection::SignatureNotActive,
        SignatureContinuationRejection::ChangedSignatureSnapshotInput,
        SignatureContinuationRejection::CipherAuthenticationRoleAbsent,
        SignatureContinuationRejection::CipherWriterDeclarationAbsent,
        SignatureContinuationRejection::ClassicSignatureFacadeRoute,
        SignatureContinuationRejection::CompetingInitOwnerAbsent,
        SignatureContinuationRejection::CompetingSignatureInitOutcomeUncertain,
        SignatureContinuationRejection::ConflictingInitReturnedNoError,
        SignatureContinuationRejection::ConsumedSignatureTicket,
        SignatureContinuationRejection::ExplicitSignatureDeclarationMismatch,
        SignatureContinuationRejection::ForeignCipherDestination,
        SignatureContinuationRejection::ForeignSignatureDestination,
        SignatureContinuationRejection::NativeCipherWriterDestinationRequired,
        SignatureContinuationRejection::NativeDestinationPermissionsAbsent,
        SignatureContinuationRejection::NativeDestinationStorageNotPrepared,
        SignatureContinuationRejection::NativeSignatureDestinationRequired,
        SignatureContinuationRejection::NativeTransferStorageAbsent,
        SignatureContinuationRejection::RevokedSignatureDestination,
        SignatureContinuationRejection::RevokedSignatureKey,
        SignatureContinuationRejection::SignatureUpdateDidNotEstablishInputBoundary,
        SignatureContinuationRejection::SignatureContinuationRoute,
        SignatureContinuationRejection::SignatureContinuationTicketUnavailable,
        SignatureContinuationRejection::SignatureDestinationBindingAbsent,
        SignatureContinuationRejection::SignatureDestinationDeclarationChanged,
        SignatureContinuationRejection::SignatureDestinationRepresentationChanged,
        SignatureContinuationRejection::SignatureFacadeIncomplete,
        SignatureContinuationRejection::SignatureFinishOperands,
        SignatureContinuationRejection::SignatureHasNoCipherKeyRole,
        SignatureContinuationRejection::SignatureImportDeclarationMismatch,
        SignatureContinuationRejection::SignatureInitialOperands,
        SignatureContinuationRejection::SignatureInputAbsent,
        SignatureContinuationRejection::SignatureInputAccounting,
        SignatureContinuationRejection::SignatureInputBoundaryUnavailable,
        SignatureContinuationRejection::SignatureIsNotWaitingForStorage,
        SignatureContinuationRejection::SignatureLengthWidth,
        SignatureContinuationRejection::SignatureNativeInputMutation,
        SignatureContinuationRejection::SignatureNativeLengthWidth,
        SignatureContinuationRejection::SignatureNativeTerminationUncertain,
        SignatureContinuationRejection::SignatureNotAtACapturableBoundary,
        SignatureContinuationRejection::SignatureOperationAccounting,
        SignatureContinuationRejection::SignatureOutputAlignment,
        SignatureContinuationRejection::SignatureOutputAlignmentAccounting,
        SignatureContinuationRejection::SignatureOutputCapacity,
        SignatureContinuationRejection::SignatureOutputCeiling,
        SignatureContinuationRejection::SignaturePhaseNotSerializable,
        SignatureContinuationRejection::SignaturePreparedOutputWidth,
        SignatureContinuationRejection::SignatureReconstructionAccounting,
        SignatureContinuationRejection::SignatureResultAlreadyPublished,
        SignatureContinuationRejection::SignatureResultIncomplete,
        SignatureContinuationRejection::SignatureRevocationAccounting,
        SignatureContinuationRejection::SignatureRolesNotPrepared,
        SignatureContinuationRejection::SignatureSnapshotAccounting,
        SignatureContinuationRejection::SignatureSnapshotShapeChanged,
        SignatureContinuationRejection::SignatureStreamExtensionRoute,
        SignatureContinuationRejection::SingleSignatureExtensionRoute,
        SignatureContinuationRejection::UncopiedSignatureSnapshot,
        SignatureContinuationRejection::UnsubmittedSignatureBindingCannotBeDuplicated,
        SignatureContinuationRejection::VerificationSignatureNotSupplied,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::SignatureContinuation(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::SignatureContinuation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
