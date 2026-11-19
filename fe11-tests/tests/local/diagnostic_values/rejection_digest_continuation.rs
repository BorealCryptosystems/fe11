// SPDX-License-Identifier: Apache-2.0
//! Public DigestContinuationRejection values retain identity through category conversion.
use fe11::{DigestContinuationRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        DigestContinuationRejection::AdvancedInputAllocation,
        DigestContinuationRejection::AsynchronousResultIdentity,
        DigestContinuationRejection::AsynchronousResultVersion,
        DigestContinuationRejection::CallerDrivenDigestRequiresASynchronousSession,
        DigestContinuationRejection::CallerDrivenDigestResultOwner,
        DigestContinuationRejection::ConsumedDigestTicket,
        DigestContinuationRejection::DeclarationOnATypedDigest,
        DigestContinuationRejection::DeclarationWithoutDigestExtension,
        DigestContinuationRejection::DigestOidAccounting,
        DigestContinuationRejection::DigestOidSelection,
        DigestContinuationRejection::DigestContinuationTicketUnavailable,
        DigestContinuationRejection::DigestDeclarationFamily,
        DigestContinuationRejection::DigestDestinationDeclarationAbsentOrUnexpected,
        DigestContinuationRejection::DigestDestinationDeclarationMismatch,
        DigestContinuationRejection::DigestExtensionAsynchronousModeOrInitReplayIsUnavailable,
        DigestContinuationRejection::DigestExtensionGraphSelection,
        DigestContinuationRejection::DigestExtensionNotCapturable,
        DigestContinuationRejection::DigestExtensionParametersAbsent,
        DigestContinuationRejection::DigestExtensionSelection,
        DigestContinuationRejection::DigestExtensionSnapshotAccounting,
        DigestContinuationRejection::DigestExtensionSnapshotChanged,
        DigestContinuationRejection::DigestExtensionSnapshotTrailingBytes,
        DigestContinuationRejection::DigestFacadeObserverChanged,
        DigestContinuationRejection::DigestFacadeOwnerChanged,
        DigestContinuationRejection::DigestFunctionsUnavailable,
        DigestContinuationRejection::DigestGraphAccounting,
        DigestContinuationRejection::DigestHasNoContextAuthenticationRole,
        DigestContinuationRejection::DigestImportRequiresADestinationAbiDeclaration,
        DigestContinuationRejection::DigestInjectionStorageSize,
        DigestContinuationRejection::DigestInputCompletionUnproven,
        DigestContinuationRejection::DigestInputFunctionUnavailable,
        DigestContinuationRejection::DigestInputPhase,
        DigestContinuationRejection::DigestInputPreparation,
        DigestContinuationRejection::DigestInputRetirementCount,
        DigestContinuationRejection::DigestInputSize,
        DigestContinuationRejection::DigestMechanismWidth,
        DigestContinuationRejection::DigestNativeParameterIdentity,
        DigestContinuationRejection::DigestOperationNotJoinable,
        DigestContinuationRejection::DigestOperationStorageSize,
        DigestContinuationRejection::DigestOutputCapacity,
        DigestContinuationRejection::DigestOutputDescriptorAbsent,
        DigestContinuationRejection::DigestOutputIsNotAwaitingStorage,
        DigestContinuationRejection::DigestOutputWaitingPhase,
        DigestContinuationRejection::DigestPendingOutputOwner,
        DigestContinuationRejection::DigestReaderRetirementOccupied,
        DigestContinuationRejection::DigestReconstructionAccounting,
        DigestContinuationRejection::DigestReplacementStorage,
        DigestContinuationRejection::DigestRequiredCapacityWidth,
        DigestContinuationRejection::DigestResultContractMismatch,
        DigestContinuationRejection::DigestRetirementAccounting,
        DigestContinuationRejection::DigestSnapshotMetadataAccounting,
        DigestContinuationRejection::DigestSnapshotPartCount,
        DigestContinuationRejection::DigestSnapshotStorageAccounting,
        DigestContinuationRejection::DigestStorageSize,
        DigestContinuationRejection::DuplicateOperationCompletion,
        DigestContinuationRejection::ExtensionDigestAsynchronousModeUnavailable,
        DigestContinuationRejection::ExtensionDigestFacadeIncomplete,
        DigestContinuationRejection::ExtensionDigestFacadeRoute,
        DigestContinuationRejection::ExtensionDigestRequiresParameterOutputOwner,
        DigestContinuationRejection::ExtensionDigestResultOwner,
        DigestContinuationRejection::NativeDigestInputChanged,
        DigestContinuationRejection::NativeDigestResultOwner,
        DigestContinuationRejection::OperationFailedExplicitCleanupRequired,
        DigestContinuationRejection::OperationMetadataLength,
        DigestContinuationRejection::OperationNotActive,
        DigestContinuationRejection::ReconstructionDigestMessageAbsent,
        DigestContinuationRejection::ReconstructionDigestPhase,
        DigestContinuationRejection::RecordDigestMechanism,
        DigestContinuationRejection::RecordDigestParameterMechanism,
        DigestContinuationRejection::RecordDigestParameterWidth,
        DigestContinuationRejection::RecordDigestProfile,
        DigestContinuationRejection::RecordDigestWidth,
        DigestContinuationRejection::RecordNativeDigestMechanism,
        DigestContinuationRejection::RecordParameterizedDigestProfile,
        DigestContinuationRejection::SingleDigestInputCount,
        DigestContinuationRejection::StaleDigestFacadeTicket,
        DigestContinuationRejection::UncopiedDigestSnapshot,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::DigestContinuation(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::DigestContinuation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
