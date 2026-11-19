// SPDX-License-Identifier: Apache-2.0
//! Public RestorationRejection values retain identity through category conversion.
use fe11::{Error, RejectionReason, RestorationRejection};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        RestorationRejection::CSetOperationStateUnavailable,
        RestorationRejection::BlockCipherDestinationReferenceProfile,
        RestorationRejection::CaptureRecordIsNotAnActiveCryptographicOperation,
        RestorationRejection::CheckpointDestinationRoles,
        RestorationRejection::DestinationContinuationAlreadyBound,
        RestorationRejection::DetachedContinuationAssociation,
        RestorationRejection::DetachedReconstructedCapacity,
        RestorationRejection::DetachedReconstructionOwner,
        RestorationRejection::DuplicateKeyCandidateAlreadyOccupied,
        RestorationRejection::ForeignOrConsumedReplacementTicket,
        RestorationRejection::ForeignOrConsumedRestorationTicket,
        RestorationRejection::GenericMessageArchiveBodyAbsent,
        RestorationRejection::GenericMessageDestinationPreparationRequired,
        RestorationRejection::GenericMessageReconstructionFamily,
        RestorationRejection::ReconstructionAuthenticationKey,
        RestorationRejection::ReconstructionCandidateAbsent,
        RestorationRejection::ReconstructionCipherKey,
        RestorationRejection::ReconstructionKeysAbsent,
        RestorationRejection::ReconstructionMetadata,
        RestorationRejection::ReconstructionOutputCapacity,
        RestorationRejection::ReconstructionStorageFamilyChanged,
        RestorationRejection::RecordDestinationKeyRoles,
        RestorationRejection::RecordKeyCandidateAlreadyOccupied,
        RestorationRejection::RecordMechanismWidth,
        RestorationRejection::RecordValidationAccounting,
        RestorationRejection::RecoveryDestinationKeyAbsent,
        RestorationRejection::RecoveryPreparationFamily,
        RestorationRejection::RecoveryValidationCapacity,
        RestorationRejection::RestorationInitializationAccounting,
        RestorationRejection::RestorationInitializationCapacity,
        RestorationRejection::RestorationInitializationOwnerMismatch,
        RestorationRejection::RestorationKeyStorageAccounting,
        RestorationRejection::RestorationPublicationStorageAbsent,
        RestorationRejection::RestorationStorageSize,
        RestorationRejection::RestorationTransferAbsent,
        RestorationRejection::RestorationTransferCeiling,
        RestorationRejection::RestorationTransferProvenanceAbsent,
        RestorationRejection::RestorationTransferUncertain,
        RestorationRejection::RestoreJoinedStorageAbsent,
        RestorationRejection::RestoreKeyMechanismPolicy,
        RestorationRejection::RestoreNativeStorageAbsent,
        RestorationRejection::RestoreSymmetricReferenceRequired,
        RestorationRejection::RestoreTransferDestinationKeyRoles,
        RestorationRejection::SavedStateConsumed,
        RestorationRejection::SavedStateContextMismatch,
        RestorationRejection::SavedStateModuleAbsent,
        RestorationRejection::SignatureMessageAbsent,
        RestorationRejection::SignatureParametersAbsent,
        RestorationRejection::StaleReplacementTicket,
        RestorationRejection::StaleRestorationTicket,
        RestorationRejection::TerminalAuthenticationAbsent,
        RestorationRejection::TerminalFamily,
        RestorationRejection::TerminalMessageAbsent,
        RestorationRejection::TerminalReportAbsent,
        RestorationRejection::TransferStorageAccounting,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::Restoration(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::Restoration(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
