// SPDX-License-Identifier: Apache-2.0
//! ObjectCreation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object creation.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_creation.md")]
pub enum ObjectCreationRejection {
    /// KEM call absent. [Detection, owner and recovery](#cause-KemCallAbsent).
    KemCallAbsent,
    /// KEM completion phase. [Detection, owner and recovery](#cause-KemCompletionPhase).
    KemCompletionPhase,
    /// KEM completion unknown. [Detection, owner and recovery](#cause-KemCompletionUnknown).
    KemCompletionUnknown,
    /// KEM dispatch phase. [Detection, owner and recovery](#cause-KemDispatchPhase).
    KemDispatchPhase,
    /// KEM native outcome absent. [Detection, owner and recovery](#cause-KemNativeOutcomeAbsent).
    KemNativeOutcomeAbsent,
    /// KEM observation storage size. [Detection, owner and recovery](#cause-KemObservationStorageSize).
    KemObservationStorageSize,
    /// KEM output evidence absent. [Detection, owner and recovery](#cause-KemOutputEvidenceAbsent).
    KemOutputEvidenceAbsent,
    /// ML-KEM native ciphertext length. [Detection, owner and recovery](#cause-MlKemNativeCiphertextLength).
    MlKemNativeCiphertextLength,
    /// TLS output kind. [Detection, owner and recovery](#cause-TlsOutputKind).
    TlsOutputKind,
    /// Attribute mutation activity changed. [Detection, owner and recovery](#cause-AttributeMutationActivityChanged).
    AttributeMutationActivityChanged,
    /// Attribute mutation activity changed after return. [Detection, owner and recovery](#cause-AttributeMutationActivityChangedAfterReturn).
    AttributeMutationActivityChangedAfterReturn,
    /// Attribute mutation activity unavailable. [Detection, owner and recovery](#cause-AttributeMutationActivityUnavailable).
    AttributeMutationActivityUnavailable,
    /// Attribute mutation activity unavailable after return. [Detection, owner and recovery](#cause-AttributeMutationActivityUnavailableAfterReturn).
    AttributeMutationActivityUnavailableAfterReturn,
    /// Attribute mutation creator changed. [Detection, owner and recovery](#cause-AttributeMutationCreatorChanged).
    AttributeMutationCreatorChanged,
    /// Attribute mutation creator changed after return. [Detection, owner and recovery](#cause-AttributeMutationCreatorChangedAfterReturn).
    AttributeMutationCreatorChangedAfterReturn,
    /// Attribute mutation creator lost after return. [Detection, owner and recovery](#cause-AttributeMutationCreatorLostAfterReturn).
    AttributeMutationCreatorLostAfterReturn,
    /// Attribute mutation creator unavailable. [Detection, owner and recovery](#cause-AttributeMutationCreatorUnavailable).
    AttributeMutationCreatorUnavailable,
    /// Attribute mutation destination reservation. [Detection, owner and recovery](#cause-AttributeMutationDestinationReservation).
    AttributeMutationDestinationReservation,
    /// Attribute mutation metadata owner. [Detection, owner and recovery](#cause-AttributeMutationMetadataOwner).
    AttributeMutationMetadataOwner,
    /// Attribute mutation module released. [Detection, owner and recovery](#cause-AttributeMutationModuleReleased).
    AttributeMutationModuleReleased,
    /// Attribute mutation prepared origin owner. [Detection, owner and recovery](#cause-AttributeMutationPreparedOriginOwner).
    AttributeMutationPreparedOriginOwner,
    /// Conflicting creation classes. [Detection, owner and recovery](#cause-ConflictingCreationClasses).
    ConflictingCreationClasses,
    /// Coordination copy allocation. [Detection, owner and recovery](#cause-CoordinationCopyAllocation).
    CoordinationCopyAllocation,
    /// Copy diagnostics absent. [Detection, owner and recovery](#cause-CopyDiagnosticsAbsent).
    CopyDiagnosticsAbsent,
    /// Copy source absent. [Detection, owner and recovery](#cause-CopySourceAbsent).
    CopySourceAbsent,
    /// Created object absent. [Detection, owner and recovery](#cause-CreatedObjectAbsent).
    CreatedObjectAbsent,
    /// Created object handles. [Detection, owner and recovery](#cause-CreatedObjectHandles).
    CreatedObjectHandles,
    /// Created object record changed. [Detection, owner and recovery](#cause-CreatedObjectRecordChanged).
    CreatedObjectRecordChanged,
    /// Created object record missing. [Detection, owner and recovery](#cause-CreatedObjectRecordMissing).
    CreatedObjectRecordMissing,
    /// Creating session closed. [Detection, owner and recovery](#cause-CreatingSessionClosed).
    CreatingSessionClosed,
    /// Creating session closing or uncertain. [Detection, owner and recovery](#cause-CreatingSessionClosingOrUncertain).
    CreatingSessionClosingOrUncertain,
    /// Creating session released. [Detection, owner and recovery](#cause-CreatingSessionReleased).
    CreatingSessionReleased,
    /// Creation activity allocation. [Detection, owner and recovery](#cause-CreationActivityAllocation).
    CreationActivityAllocation,
    /// Creation admission phase. [Detection, owner and recovery](#cause-CreationAdmissionPhase).
    CreationAdmissionPhase,
    /// Creation admission preparation absent. [Detection, owner and recovery](#cause-CreationAdmissionPreparationAbsent).
    CreationAdmissionPreparationAbsent,
    /// Creation aggregate accounting. [Detection, owner and recovery](#cause-CreationAggregateAccounting).
    CreationAggregateAccounting,
    /// Creation candidate kind. [Detection, owner and recovery](#cause-CreationCandidateKind).
    CreationCandidateKind,
    /// Creation class ABI representation. [Detection, owner and recovery](#cause-CreationClassAbiRepresentation).
    CreationClassAbiRepresentation,
    /// Creation class is required. [Detection, owner and recovery](#cause-CreationClassIsRequired).
    CreationClassIsRequired,
    /// Creation cleanup size. [Detection, owner and recovery](#cause-CreationCleanupSize).
    CreationCleanupSize,
    /// Creation completion phase. [Detection, owner and recovery](#cause-CreationCompletionPhase).
    CreationCompletionPhase,
    /// Creation continuation changed. [Detection, owner and recovery](#cause-CreationContinuationChanged).
    CreationContinuationChanged,
    /// Creation destination. [Detection, owner and recovery](#cause-CreationDestination).
    CreationDestination,
    /// Creation destination phase. [Detection, owner and recovery](#cause-CreationDestinationPhase).
    CreationDestinationPhase,
    /// Creation diagnostic absent. [Detection, owner and recovery](#cause-CreationDiagnosticAbsent).
    CreationDiagnosticAbsent,
    /// Creation metadata phase. [Detection, owner and recovery](#cause-CreationMetadataPhase).
    CreationMetadataPhase,
    /// Creation metadata storage accounting. [Detection, owner and recovery](#cause-CreationMetadataStorageAccounting).
    CreationMetadataStorageAccounting,
    /// Creation native lifetime absent. [Detection, owner and recovery](#cause-CreationNativeLifetimeAbsent).
    CreationNativeLifetimeAbsent,
    /// Creation origin unavailable for cleanup. [Detection, owner and recovery](#cause-CreationOriginUnavailableForCleanup).
    CreationOriginUnavailableForCleanup,
    /// Creation owner absent. [Detection, owner and recovery](#cause-CreationOwnerAbsent).
    CreationOwnerAbsent,
    /// Creation owner changed before cleanup. [Detection, owner and recovery](#cause-CreationOwnerChangedBeforeCleanup).
    CreationOwnerChangedBeforeCleanup,
    /// Creation owner unavailable. [Detection, owner and recovery](#cause-CreationOwnerUnavailable).
    CreationOwnerUnavailable,
    /// Creation possession absent. [Detection, owner and recovery](#cause-CreationPossessionAbsent).
    CreationPossessionAbsent,
    /// Creation preparation already consumed. [Detection, owner and recovery](#cause-CreationPreparationAlreadyConsumed).
    CreationPreparationAlreadyConsumed,
    /// Creation publication accounting. [Detection, owner and recovery](#cause-CreationPublicationAccounting).
    CreationPublicationAccounting,
    /// Creation publication capacity. [Detection, owner and recovery](#cause-CreationPublicationCapacity).
    CreationPublicationCapacity,
    /// Creation publication capacity changed. [Detection, owner and recovery](#cause-CreationPublicationCapacityChanged).
    CreationPublicationCapacityChanged,
    /// Creation publication quota absent. [Detection, owner and recovery](#cause-CreationPublicationQuotaAbsent).
    CreationPublicationQuotaAbsent,
    /// Creation publication quota transferred. [Detection, owner and recovery](#cause-CreationPublicationQuotaTransferred).
    CreationPublicationQuotaTransferred,
    /// Creation publication slot exhausted. [Detection, owner and recovery](#cause-CreationPublicationSlotExhausted).
    CreationPublicationSlotExhausted,
    /// Creation record changed. [Detection, owner and recovery](#cause-CreationRecordChanged).
    CreationRecordChanged,
    /// Creation record missing. [Detection, owner and recovery](#cause-CreationRecordMissing).
    CreationRecordMissing,
    /// Creation resource need absent. [Detection, owner and recovery](#cause-CreationResourceNeedAbsent).
    CreationResourceNeedAbsent,
    /// Creation session released. [Detection, owner and recovery](#cause-CreationSessionReleased).
    CreationSessionReleased,
    /// Creation storage size. [Detection, owner and recovery](#cause-CreationStorageSize).
    CreationStorageSize,
    /// Foreign creation reservation. [Detection, owner and recovery](#cause-ForeignCreationReservation).
    ForeignCreationReservation,
    /// Foreign forgotten resource. [Detection, owner and recovery](#cause-ForeignForgottenResource).
    ForeignForgottenResource,
    /// Generated object absent. [Detection, owner and recovery](#cause-GeneratedObjectAbsent).
    GeneratedObjectAbsent,
    /// Generated output kind. [Detection, owner and recovery](#cause-GeneratedOutputKind).
    GeneratedOutputKind,
    /// Generated private object absent. [Detection, owner and recovery](#cause-GeneratedPrivateObjectAbsent).
    GeneratedPrivateObjectAbsent,
    /// Generated public object absent. [Detection, owner and recovery](#cause-GeneratedPublicObjectAbsent).
    GeneratedPublicObjectAbsent,
    /// Group creation scope. [Detection, owner and recovery](#cause-GroupCreationScope).
    GroupCreationScope,
    /// Key generation storage accounting. [Detection, owner and recovery](#cause-KeyGenerationStorageAccounting).
    KeyGenerationStorageAccounting,
    /// Key-material observation layout. [Detection, owner and recovery](#cause-KeyMaterialObservationLayout).
    KeyMaterialObservationLayout,
    /// Key-material request accounting. [Detection, owner and recovery](#cause-KeyMaterialRequestAccounting).
    KeyMaterialRequestAccounting,
    /// Key-material result accounting. [Detection, owner and recovery](#cause-KeyMaterialResultAccounting).
    KeyMaterialResultAccounting,
    /// Key-material result allocation. [Detection, owner and recovery](#cause-KeyMaterialResultAllocation).
    KeyMaterialResultAllocation,
    /// Key-pair generation storage accounting. [Detection, owner and recovery](#cause-KeyPairGenerationStorageAccounting).
    KeyPairGenerationStorageAccounting,
    /// Logout alias snapshot allocation. [Detection, owner and recovery](#cause-LogoutAliasSnapshotAllocation).
    LogoutAliasSnapshotAllocation,
    /// Logout alias snapshot size. [Detection, owner and recovery](#cause-LogoutAliasSnapshotSize).
    LogoutAliasSnapshotSize,
    /// Mutation module released. [Detection, owner and recovery](#cause-MutationModuleReleased).
    MutationModuleReleased,
    /// Native creation aggregate accounting. [Detection, owner and recovery](#cause-NativeCreationAggregateAccounting).
    NativeCreationAggregateAccounting,
    /// Native creation storage accounting. [Detection, owner and recovery](#cause-NativeCreationStorageAccounting).
    NativeCreationStorageAccounting,
    /// Object already created. [Detection, owner and recovery](#cause-ObjectAlreadyCreated).
    ObjectAlreadyCreated,
    /// Object creation incomplete. [Detection, owner and recovery](#cause-ObjectCreationIncomplete).
    ObjectCreationIncomplete,
    /// Object creation stopped. [Detection, owner and recovery](#cause-ObjectCreationStopped).
    ObjectCreationStopped,
    /// Object creator allocation. [Detection, owner and recovery](#cause-ObjectCreatorAllocation).
    ObjectCreatorAllocation,
    /// Object creator already recorded. [Detection, owner and recovery](#cause-ObjectCreatorAlreadyRecorded).
    ObjectCreatorAlreadyRecorded,
    /// Pair auxiliary output owner. [Detection, owner and recovery](#cause-PairAuxiliaryOutputOwner).
    PairAuxiliaryOutputOwner,
    /// Pair parameter preparation changed. [Detection, owner and recovery](#cause-PairParameterPreparationChanged).
    PairParameterPreparationChanged,
    /// Private creation observation storage size. [Detection, owner and recovery](#cause-PrivateCreationObservationStorageSize).
    PrivateCreationObservationStorageSize,
    /// Private import evidence absent. [Detection, owner and recovery](#cause-PrivateImportEvidenceAbsent).
    PrivateImportEvidenceAbsent,
    /// Private observation storage size. [Detection, owner and recovery](#cause-PrivateObservationStorageSize).
    PrivateObservationStorageSize,
    /// Public DER publication pairing. [Detection, owner and recovery](#cause-PublicDerPublicationPairing).
    PublicDerPublicationPairing,
    /// Public creation storage size. [Detection, owner and recovery](#cause-PublicCreationStorageSize).
    PublicCreationStorageSize,
    /// Public import mechanism report absent. [Detection, owner and recovery](#cause-PublicImportMechanismReportAbsent).
    PublicImportMechanismReportAbsent,
    /// Rename creator changed. [Detection, owner and recovery](#cause-RenameCreatorChanged).
    RenameCreatorChanged,
    /// Rename creator unavailable. [Detection, owner and recovery](#cause-RenameCreatorUnavailable).
    RenameCreatorUnavailable,
    /// Rename destination reservation. [Detection, owner and recovery](#cause-RenameDestinationReservation).
    RenameDestinationReservation,
    /// Rename module released. [Detection, owner and recovery](#cause-RenameModuleReleased).
    RenameModuleReleased,
    /// Restoration evidence absent. [Detection, owner and recovery](#cause-RestorationEvidenceAbsent).
    RestorationEvidenceAbsent,
    /// Restoration observation storage size. [Detection, owner and recovery](#cause-RestorationObservationStorageSize).
    RestorationObservationStorageSize,
    /// Signing import evidence absent. [Detection, owner and recovery](#cause-SigningImportEvidenceAbsent).
    SigningImportEvidenceAbsent,
    /// Unexpected KEM unwrap. [Detection, owner and recovery](#cause-UnexpectedKemUnwrap).
    UnexpectedKemUnwrap,
    /// Unexpected native KEM. [Detection, owner and recovery](#cause-UnexpectedNativeKem).
    UnexpectedNativeKem,
    /// Unexpected native unwrap. [Detection, owner and recovery](#cause-UnexpectedNativeUnwrap).
    UnexpectedNativeUnwrap,
    /// Unexpected restoration KEM. [Detection, owner and recovery](#cause-UnexpectedRestorationKem).
    UnexpectedRestorationKem,
    /// Unexpected signing evidence. [Detection, owner and recovery](#cause-UnexpectedSigningEvidence).
    UnexpectedSigningEvidence,
    /// Unwrap call absent. [Detection, owner and recovery](#cause-UnwrapCallAbsent).
    UnwrapCallAbsent,
    /// Unwrap completion phase. [Detection, owner and recovery](#cause-UnwrapCompletionPhase).
    UnwrapCompletionPhase,
    /// Unwrap completion unknown. [Detection, owner and recovery](#cause-UnwrapCompletionUnknown).
    UnwrapCompletionUnknown,
    /// Unwrap dispatch phase. [Detection, owner and recovery](#cause-UnwrapDispatchPhase).
    UnwrapDispatchPhase,
}

impl std::fmt::Display for ObjectCreationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KemCallAbsent => f.write_str("KEM call absent"),
            Self::KemCompletionPhase => f.write_str("KEM completion phase"),
            Self::KemCompletionUnknown => f.write_str("KEM completion unknown"),
            Self::KemDispatchPhase => f.write_str("KEM dispatch phase"),
            Self::KemNativeOutcomeAbsent => f.write_str("KEM native outcome absent"),
            Self::KemObservationStorageSize => f.write_str("KEM observation storage size"),
            Self::KemOutputEvidenceAbsent => f.write_str("KEM output evidence absent"),
            Self::MlKemNativeCiphertextLength => f.write_str("ML-KEM native ciphertext length"),
            Self::TlsOutputKind => f.write_str("TLS output kind"),
            Self::AttributeMutationActivityChanged => {
                f.write_str("attribute mutation activity changed")
            }
            Self::AttributeMutationActivityChangedAfterReturn => {
                f.write_str("attribute mutation activity changed after return")
            }
            Self::AttributeMutationActivityUnavailable => {
                f.write_str("attribute mutation activity unavailable")
            }
            Self::AttributeMutationActivityUnavailableAfterReturn => {
                f.write_str("attribute mutation activity unavailable after return")
            }
            Self::AttributeMutationCreatorChanged => {
                f.write_str("attribute mutation creator changed")
            }
            Self::AttributeMutationCreatorChangedAfterReturn => {
                f.write_str("attribute mutation creator changed after return")
            }
            Self::AttributeMutationCreatorLostAfterReturn => {
                f.write_str("attribute mutation creator lost after return")
            }
            Self::AttributeMutationCreatorUnavailable => {
                f.write_str("attribute mutation creator unavailable")
            }
            Self::AttributeMutationDestinationReservation => {
                f.write_str("attribute mutation destination reservation")
            }
            Self::AttributeMutationMetadataOwner => {
                f.write_str("attribute mutation metadata owner")
            }
            Self::AttributeMutationModuleReleased => {
                f.write_str("attribute mutation module released")
            }
            Self::AttributeMutationPreparedOriginOwner => {
                f.write_str("attribute mutation prepared origin owner")
            }
            Self::ConflictingCreationClasses => f.write_str("conflicting creation classes"),
            Self::CoordinationCopyAllocation => f.write_str("coordination copy allocation"),
            Self::CopyDiagnosticsAbsent => f.write_str("copy diagnostics absent"),
            Self::CopySourceAbsent => f.write_str("copy source absent"),
            Self::CreatedObjectAbsent => f.write_str("created object absent"),
            Self::CreatedObjectHandles => f.write_str("created object handles"),
            Self::CreatedObjectRecordChanged => f.write_str("created object record changed"),
            Self::CreatedObjectRecordMissing => f.write_str("created object record missing"),
            Self::CreatingSessionClosed => f.write_str("creating session closed"),
            Self::CreatingSessionClosingOrUncertain => {
                f.write_str("creating session closing or uncertain")
            }
            Self::CreatingSessionReleased => f.write_str("creating session released"),
            Self::CreationActivityAllocation => f.write_str("creation activity allocation"),
            Self::CreationAdmissionPhase => f.write_str("creation admission phase"),
            Self::CreationAdmissionPreparationAbsent => {
                f.write_str("creation admission preparation absent")
            }
            Self::CreationAggregateAccounting => f.write_str("creation aggregate accounting"),
            Self::CreationCandidateKind => f.write_str("creation candidate kind"),
            Self::CreationClassAbiRepresentation => {
                f.write_str("creation class ABI representation")
            }
            Self::CreationClassIsRequired => f.write_str("creation class is required"),
            Self::CreationCleanupSize => f.write_str("creation cleanup size"),
            Self::CreationCompletionPhase => f.write_str("creation completion phase"),
            Self::CreationContinuationChanged => f.write_str("creation continuation changed"),
            Self::CreationDestination => f.write_str("creation destination"),
            Self::CreationDestinationPhase => f.write_str("creation destination phase"),
            Self::CreationDiagnosticAbsent => f.write_str("creation diagnostic absent"),
            Self::CreationMetadataPhase => f.write_str("creation metadata phase"),
            Self::CreationMetadataStorageAccounting => {
                f.write_str("creation metadata storage accounting")
            }
            Self::CreationNativeLifetimeAbsent => f.write_str("creation native lifetime absent"),
            Self::CreationOriginUnavailableForCleanup => {
                f.write_str("creation origin unavailable for cleanup")
            }
            Self::CreationOwnerAbsent => f.write_str("creation owner absent"),
            Self::CreationOwnerChangedBeforeCleanup => {
                f.write_str("creation owner changed before cleanup")
            }
            Self::CreationOwnerUnavailable => f.write_str("creation owner unavailable"),
            Self::CreationPossessionAbsent => f.write_str("creation possession absent"),
            Self::CreationPreparationAlreadyConsumed => {
                f.write_str("creation preparation already consumed")
            }
            Self::CreationPublicationAccounting => f.write_str("creation publication accounting"),
            Self::CreationPublicationCapacity => f.write_str("creation publication capacity"),
            Self::CreationPublicationCapacityChanged => {
                f.write_str("creation publication capacity changed")
            }
            Self::CreationPublicationQuotaAbsent => {
                f.write_str("creation publication quota absent")
            }
            Self::CreationPublicationQuotaTransferred => {
                f.write_str("creation publication quota transferred")
            }
            Self::CreationPublicationSlotExhausted => {
                f.write_str("creation publication slot exhausted")
            }
            Self::CreationRecordChanged => f.write_str("creation record changed"),
            Self::CreationRecordMissing => f.write_str("creation record missing"),
            Self::CreationResourceNeedAbsent => f.write_str("creation resource need absent"),
            Self::CreationSessionReleased => f.write_str("creation session released"),
            Self::CreationStorageSize => f.write_str("creation storage size"),
            Self::ForeignCreationReservation => f.write_str("foreign creation reservation"),
            Self::ForeignForgottenResource => f.write_str("foreign forgotten resource"),
            Self::GeneratedObjectAbsent => f.write_str("generated object absent"),
            Self::GeneratedOutputKind => f.write_str("generated output kind"),
            Self::GeneratedPrivateObjectAbsent => f.write_str("generated private object absent"),
            Self::GeneratedPublicObjectAbsent => f.write_str("generated public object absent"),
            Self::GroupCreationScope => f.write_str("group creation scope"),
            Self::KeyGenerationStorageAccounting => {
                f.write_str("key generation storage accounting")
            }
            Self::KeyMaterialObservationLayout => f.write_str("key-material observation layout"),
            Self::KeyMaterialRequestAccounting => f.write_str("key-material request accounting"),
            Self::KeyMaterialResultAccounting => f.write_str("key-material result accounting"),
            Self::KeyMaterialResultAllocation => f.write_str("key-material result allocation"),
            Self::KeyPairGenerationStorageAccounting => {
                f.write_str("key-pair generation storage accounting")
            }
            Self::LogoutAliasSnapshotAllocation => f.write_str("logout alias snapshot allocation"),
            Self::LogoutAliasSnapshotSize => f.write_str("logout alias snapshot size"),
            Self::MutationModuleReleased => f.write_str("mutation module released"),
            Self::NativeCreationAggregateAccounting => {
                f.write_str("native creation aggregate accounting")
            }
            Self::NativeCreationStorageAccounting => {
                f.write_str("native creation storage accounting")
            }
            Self::ObjectAlreadyCreated => f.write_str("object already created"),
            Self::ObjectCreationIncomplete => f.write_str("object creation incomplete"),
            Self::ObjectCreationStopped => f.write_str("object creation stopped"),
            Self::ObjectCreatorAllocation => f.write_str("object creator allocation"),
            Self::ObjectCreatorAlreadyRecorded => f.write_str("object creator already recorded"),
            Self::PairAuxiliaryOutputOwner => f.write_str("pair auxiliary output owner"),
            Self::PairParameterPreparationChanged => {
                f.write_str("pair parameter preparation changed")
            }
            Self::PrivateCreationObservationStorageSize => {
                f.write_str("private creation observation storage size")
            }
            Self::PrivateImportEvidenceAbsent => f.write_str("private import evidence absent"),
            Self::PrivateObservationStorageSize => f.write_str("private observation storage size"),
            Self::PublicDerPublicationPairing => f.write_str("public DER publication pairing"),
            Self::PublicCreationStorageSize => f.write_str("public creation storage size"),
            Self::PublicImportMechanismReportAbsent => {
                f.write_str("public import mechanism report absent")
            }
            Self::RenameCreatorChanged => f.write_str("rename creator changed"),
            Self::RenameCreatorUnavailable => f.write_str("rename creator unavailable"),
            Self::RenameDestinationReservation => f.write_str("rename destination reservation"),
            Self::RenameModuleReleased => f.write_str("rename module released"),
            Self::RestorationEvidenceAbsent => f.write_str("restoration evidence absent"),
            Self::RestorationObservationStorageSize => {
                f.write_str("restoration observation storage size")
            }
            Self::SigningImportEvidenceAbsent => f.write_str("signing import evidence absent"),
            Self::UnexpectedKemUnwrap => f.write_str("unexpected KEM unwrap"),
            Self::UnexpectedNativeKem => f.write_str("unexpected native KEM"),
            Self::UnexpectedNativeUnwrap => f.write_str("unexpected native unwrap"),
            Self::UnexpectedRestorationKem => f.write_str("unexpected restoration KEM"),
            Self::UnexpectedSigningEvidence => f.write_str("unexpected signing evidence"),
            Self::UnwrapCallAbsent => f.write_str("unwrap call absent"),
            Self::UnwrapCompletionPhase => f.write_str("unwrap completion phase"),
            Self::UnwrapCompletionUnknown => f.write_str("unwrap completion unknown"),
            Self::UnwrapDispatchPhase => f.write_str("unwrap dispatch phase"),
        }
    }
}
