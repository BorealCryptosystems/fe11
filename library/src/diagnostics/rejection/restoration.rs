// SPDX-License-Identifier: Apache-2.0
//! Restoration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to restoration.
#[doc = include_str!("../../../docs/diagnostics/rejection-restoration.md")]
pub enum RestorationRejection {
    /// C_SetOperationState unavailable. [Detection, owner and recovery](#cause-CSetOperationStateUnavailable).
    CSetOperationStateUnavailable,
    /// Block cipher destination reference profile. [Detection, owner and recovery](#cause-BlockCipherDestinationReferenceProfile).
    BlockCipherDestinationReferenceProfile,
    /// Capture record is not an active cryptographic operation. [Detection, owner and recovery](#cause-CaptureRecordIsNotAnActiveCryptographicOperation).
    CaptureRecordIsNotAnActiveCryptographicOperation,
    /// Checkpoint destination roles. [Detection, owner and recovery](#cause-CheckpointDestinationRoles).
    CheckpointDestinationRoles,
    /// Destination continuation already bound. [Detection, owner and recovery](#cause-DestinationContinuationAlreadyBound).
    DestinationContinuationAlreadyBound,
    /// Detached continuation association. [Detection, owner and recovery](#cause-DetachedContinuationAssociation).
    DetachedContinuationAssociation,
    /// Detached reconstructed capacity. [Detection, owner and recovery](#cause-DetachedReconstructedCapacity).
    DetachedReconstructedCapacity,
    /// Detached reconstruction owner. [Detection, owner and recovery](#cause-DetachedReconstructionOwner).
    DetachedReconstructionOwner,
    /// Duplicate key candidate already occupied. [Detection, owner and recovery](#cause-DuplicateKeyCandidateAlreadyOccupied).
    DuplicateKeyCandidateAlreadyOccupied,
    /// Foreign or consumed replacement ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedReplacementTicket).
    ForeignOrConsumedReplacementTicket,
    /// Foreign or consumed restoration ticket. [Detection, owner and recovery](#cause-ForeignOrConsumedRestorationTicket).
    ForeignOrConsumedRestorationTicket,
    /// Generic message archive body absent. [Detection, owner and recovery](#cause-GenericMessageArchiveBodyAbsent).
    GenericMessageArchiveBodyAbsent,
    /// Generic message destination preparation required. [Detection, owner and recovery](#cause-GenericMessageDestinationPreparationRequired).
    GenericMessageDestinationPreparationRequired,
    /// Generic message reconstruction family. [Detection, owner and recovery](#cause-GenericMessageReconstructionFamily).
    GenericMessageReconstructionFamily,
    /// Reconstruction authentication key. [Detection, owner and recovery](#cause-ReconstructionAuthenticationKey).
    ReconstructionAuthenticationKey,
    /// Reconstruction candidate absent. [Detection, owner and recovery](#cause-ReconstructionCandidateAbsent).
    ReconstructionCandidateAbsent,
    /// Reconstruction cipher key. [Detection, owner and recovery](#cause-ReconstructionCipherKey).
    ReconstructionCipherKey,
    /// Reconstruction keys absent. [Detection, owner and recovery](#cause-ReconstructionKeysAbsent).
    ReconstructionKeysAbsent,
    /// Reconstruction metadata. [Detection, owner and recovery](#cause-ReconstructionMetadata).
    ReconstructionMetadata,
    /// Reconstruction output capacity. [Detection, owner and recovery](#cause-ReconstructionOutputCapacity).
    ReconstructionOutputCapacity,
    /// Reconstruction storage family changed. [Detection, owner and recovery](#cause-ReconstructionStorageFamilyChanged).
    ReconstructionStorageFamilyChanged,
    /// Record destination key roles. [Detection, owner and recovery](#cause-RecordDestinationKeyRoles).
    RecordDestinationKeyRoles,
    /// Record key candidate already occupied. [Detection, owner and recovery](#cause-RecordKeyCandidateAlreadyOccupied).
    RecordKeyCandidateAlreadyOccupied,
    /// Record mechanism width. [Detection, owner and recovery](#cause-RecordMechanismWidth).
    RecordMechanismWidth,
    /// Record validation accounting. [Detection, owner and recovery](#cause-RecordValidationAccounting).
    RecordValidationAccounting,
    /// Recovery destination key absent. [Detection, owner and recovery](#cause-RecoveryDestinationKeyAbsent).
    RecoveryDestinationKeyAbsent,
    /// Recovery preparation family. [Detection, owner and recovery](#cause-RecoveryPreparationFamily).
    RecoveryPreparationFamily,
    /// Recovery validation capacity. [Detection, owner and recovery](#cause-RecoveryValidationCapacity).
    RecoveryValidationCapacity,
    /// Restoration initialization accounting. [Detection, owner and recovery](#cause-RestorationInitializationAccounting).
    RestorationInitializationAccounting,
    /// Restoration initialization capacity. [Detection, owner and recovery](#cause-RestorationInitializationCapacity).
    RestorationInitializationCapacity,
    /// Restoration initialization owner mismatch. [Detection, owner and recovery](#cause-RestorationInitializationOwnerMismatch).
    RestorationInitializationOwnerMismatch,
    /// Restoration key storage accounting. [Detection, owner and recovery](#cause-RestorationKeyStorageAccounting).
    RestorationKeyStorageAccounting,
    /// Restoration publication storage absent. [Detection, owner and recovery](#cause-RestorationPublicationStorageAbsent).
    RestorationPublicationStorageAbsent,
    /// Restoration storage size. [Detection, owner and recovery](#cause-RestorationStorageSize).
    RestorationStorageSize,
    /// Restoration transfer absent. [Detection, owner and recovery](#cause-RestorationTransferAbsent).
    RestorationTransferAbsent,
    /// Restoration transfer ceiling. [Detection, owner and recovery](#cause-RestorationTransferCeiling).
    RestorationTransferCeiling,
    /// Restoration transfer provenance absent. [Detection, owner and recovery](#cause-RestorationTransferProvenanceAbsent).
    RestorationTransferProvenanceAbsent,
    /// Restoration transfer uncertain. [Detection, owner and recovery](#cause-RestorationTransferUncertain).
    RestorationTransferUncertain,
    /// Restore joined storage absent. [Detection, owner and recovery](#cause-RestoreJoinedStorageAbsent).
    RestoreJoinedStorageAbsent,
    /// Restore key mechanism policy. [Detection, owner and recovery](#cause-RestoreKeyMechanismPolicy).
    RestoreKeyMechanismPolicy,
    /// Restore native storage absent. [Detection, owner and recovery](#cause-RestoreNativeStorageAbsent).
    RestoreNativeStorageAbsent,
    /// Restore symmetric reference required. [Detection, owner and recovery](#cause-RestoreSymmetricReferenceRequired).
    RestoreSymmetricReferenceRequired,
    /// Restore transfer destination key roles. [Detection, owner and recovery](#cause-RestoreTransferDestinationKeyRoles).
    RestoreTransferDestinationKeyRoles,
    /// Saved state consumed. [Detection, owner and recovery](#cause-SavedStateConsumed).
    SavedStateConsumed,
    /// Saved state context mismatch. [Detection, owner and recovery](#cause-SavedStateContextMismatch).
    SavedStateContextMismatch,
    /// Saved state module absent. [Detection, owner and recovery](#cause-SavedStateModuleAbsent).
    SavedStateModuleAbsent,
    /// Signature message absent. [Detection, owner and recovery](#cause-SignatureMessageAbsent).
    SignatureMessageAbsent,
    /// Signature parameters absent. [Detection, owner and recovery](#cause-SignatureParametersAbsent).
    SignatureParametersAbsent,
    /// Stale replacement ticket. [Detection, owner and recovery](#cause-StaleReplacementTicket).
    StaleReplacementTicket,
    /// Stale restoration ticket. [Detection, owner and recovery](#cause-StaleRestorationTicket).
    StaleRestorationTicket,
    /// Terminal authentication absent. [Detection, owner and recovery](#cause-TerminalAuthenticationAbsent).
    TerminalAuthenticationAbsent,
    /// Terminal family. [Detection, owner and recovery](#cause-TerminalFamily).
    TerminalFamily,
    /// Terminal message absent. [Detection, owner and recovery](#cause-TerminalMessageAbsent).
    TerminalMessageAbsent,
    /// Terminal report absent. [Detection, owner and recovery](#cause-TerminalReportAbsent).
    TerminalReportAbsent,
    /// Transfer storage accounting. [Detection, owner and recovery](#cause-TransferStorageAccounting).
    TransferStorageAccounting,

}

impl std::fmt::Display for RestorationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::CSetOperationStateUnavailable => f.write_str("C_SetOperationState unavailable"),
            Self::BlockCipherDestinationReferenceProfile => {
                f.write_str("block cipher destination reference profile")
            }
            Self::CaptureRecordIsNotAnActiveCryptographicOperation => {
                f.write_str("capture record is not an active cryptographic operation")
            }
            Self::CheckpointDestinationRoles => f.write_str("checkpoint destination roles"),
            Self::DestinationContinuationAlreadyBound => {
                f.write_str("destination continuation already bound")
            }
            Self::DetachedContinuationAssociation => {
                f.write_str("detached continuation association")
            }
            Self::DetachedReconstructedCapacity => f.write_str("detached reconstructed capacity"),
            Self::DetachedReconstructionOwner => f.write_str("detached reconstruction owner"),
            Self::DuplicateKeyCandidateAlreadyOccupied => {
                f.write_str("duplicate key candidate already occupied")
            }
            Self::ForeignOrConsumedReplacementTicket => {
                f.write_str("foreign or consumed replacement ticket")
            }
            Self::ForeignOrConsumedRestorationTicket => {
                f.write_str("foreign or consumed restoration ticket")
            }
            Self::GenericMessageArchiveBodyAbsent => {
                f.write_str("generic message archive body absent")
            }
            Self::GenericMessageDestinationPreparationRequired => {
                f.write_str("generic message destination preparation required")
            }
            Self::GenericMessageReconstructionFamily => {
                f.write_str("generic message reconstruction family")
            }
            Self::ReconstructionAuthenticationKey => {
                f.write_str("reconstruction authentication key")
            }
            Self::ReconstructionCandidateAbsent => f.write_str("reconstruction candidate absent"),
            Self::ReconstructionCipherKey => f.write_str("reconstruction cipher key"),
            Self::ReconstructionKeysAbsent => f.write_str("reconstruction keys absent"),
            Self::ReconstructionMetadata => f.write_str("reconstruction metadata"),
            Self::ReconstructionOutputCapacity => f.write_str("reconstruction output capacity"),
            Self::ReconstructionStorageFamilyChanged => {
                f.write_str("reconstruction storage family changed")
            }
            Self::RecordDestinationKeyRoles => f.write_str("record destination key roles"),
            Self::RecordKeyCandidateAlreadyOccupied => {
                f.write_str("record key candidate already occupied")
            }
            Self::RecordMechanismWidth => f.write_str("record mechanism width"),
            Self::RecordValidationAccounting => f.write_str("record validation accounting"),
            Self::RecoveryDestinationKeyAbsent => f.write_str("recovery destination key absent"),
            Self::RecoveryPreparationFamily => f.write_str("recovery preparation family"),
            Self::RecoveryValidationCapacity => f.write_str("recovery validation capacity"),
            Self::RestorationInitializationAccounting => {
                f.write_str("restoration initialization accounting")
            }
            Self::RestorationInitializationCapacity => {
                f.write_str("restoration initialization capacity")
            }
            Self::RestorationInitializationOwnerMismatch => {
                f.write_str("restoration initialization owner mismatch")
            }
            Self::RestorationKeyStorageAccounting => {
                f.write_str("restoration key storage accounting")
            }
            Self::RestorationPublicationStorageAbsent => {
                f.write_str("restoration publication storage absent")
            }
            Self::RestorationStorageSize => f.write_str("restoration storage size"),
            Self::RestorationTransferAbsent => f.write_str("restoration transfer absent"),
            Self::RestorationTransferCeiling => f.write_str("restoration transfer ceiling"),
            Self::RestorationTransferProvenanceAbsent => {
                f.write_str("restoration transfer provenance absent")
            }
            Self::RestorationTransferUncertain => f.write_str("restoration transfer uncertain"),
            Self::RestoreJoinedStorageAbsent => f.write_str("restore joined storage absent"),
            Self::RestoreKeyMechanismPolicy => f.write_str("restore key mechanism policy"),
            Self::RestoreNativeStorageAbsent => f.write_str("restore native storage absent"),
            Self::RestoreSymmetricReferenceRequired => {
                f.write_str("restore symmetric reference required")
            }
            Self::RestoreTransferDestinationKeyRoles => {
                f.write_str("restore transfer destination key roles")
            }
            Self::SavedStateConsumed => f.write_str("saved state consumed"),
            Self::SavedStateContextMismatch => f.write_str("saved state context mismatch"),
            Self::SavedStateModuleAbsent => f.write_str("saved state module absent"),
            Self::SignatureMessageAbsent => f.write_str("signature message absent"),
            Self::SignatureParametersAbsent => f.write_str("signature parameters absent"),
            Self::StaleReplacementTicket => f.write_str("stale replacement ticket"),
            Self::StaleRestorationTicket => f.write_str("stale restoration ticket"),
            Self::TerminalAuthenticationAbsent => f.write_str("terminal authentication absent"),
            Self::TerminalFamily => f.write_str("terminal family"),
            Self::TerminalMessageAbsent => f.write_str("terminal message absent"),
            Self::TerminalReportAbsent => f.write_str("terminal report absent"),
            Self::TransferStorageAccounting => f.write_str("transfer storage accounting"),
        }
    }
}
