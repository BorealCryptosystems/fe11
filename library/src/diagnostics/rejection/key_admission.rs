// SPDX-License-Identifier: Apache-2.0
//! KeyAdmission causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to key admission.
#[doc = include_str!("../../../docs/diagnostics/rejection-key_admission.md")]
pub enum KeyAdmissionRejection {
    /// AES KEK admission result owner mismatch. [Detection, owner and recovery](#cause-AesKekAdmissionResultOwnerMismatch).
    AesKekAdmissionResultOwnerMismatch,
    /// AES key required. [Detection, owner and recovery](#cause-AesKeyRequired).
    AesKeyRequired,
    /// ML-KEM creation result owner mismatch. [Detection, owner and recovery](#cause-MlKemCreationResultOwnerMismatch).
    MlKemCreationResultOwnerMismatch,
    /// ML-KEM initial preparation changed. [Detection, owner and recovery](#cause-MlKemInitialPreparationChanged).
    MlKemInitialPreparationChanged,
    /// ML-KEM pair SPKI mismatch. [Detection, owner and recovery](#cause-MlKemPairSpkiMismatch).
    MlKemPairSpkiMismatch,
    /// ML-KEM selection result owner mismatch. [Detection, owner and recovery](#cause-MlKemSelectionResultOwnerMismatch).
    MlKemSelectionResultOwnerMismatch,
    /// PQC admission result owner mismatch. [Detection, owner and recovery](#cause-PqcAdmissionResultOwnerMismatch).
    PqcAdmissionResultOwnerMismatch,
    /// PQC initial preparation changed. [Detection, owner and recovery](#cause-PqcInitialPreparationChanged).
    PqcInitialPreparationChanged,
    /// PQC pair SPKI mismatch. [Detection, owner and recovery](#cause-PqcPairSpkiMismatch).
    PqcPairSpkiMismatch,
    /// RSA transport result owner mismatch. [Detection, owner and recovery](#cause-RsaTransportResultOwnerMismatch).
    RsaTransportResultOwnerMismatch,
    /// Admission asynchronous version. [Detection, owner and recovery](#cause-AdmissionAsynchronousVersion).
    AdmissionAsynchronousVersion,
    /// Admission attributes absent. [Detection, owner and recovery](#cause-AdmissionAttributesAbsent).
    AdmissionAttributesAbsent,
    /// Admission diagnostic byte count. [Detection, owner and recovery](#cause-AdmissionDiagnosticByteCount).
    AdmissionDiagnosticByteCount,
    /// Admission failed; explicit cleanup required. [Detection, owner and recovery](#cause-AdmissionFailedExplicitCleanupRequired).
    AdmissionFailedExplicitCleanupRequired,
    /// Admission frame phase. [Detection, owner and recovery](#cause-AdmissionFramePhase).
    AdmissionFramePhase,
    /// Admission functions unavailable. [Detection, owner and recovery](#cause-AdmissionFunctionsUnavailable).
    AdmissionFunctionsUnavailable,
    /// Admission incomplete. [Detection, owner and recovery](#cause-AdmissionIncomplete).
    AdmissionIncomplete,
    /// Admission metadata allocation. [Detection, owner and recovery](#cause-AdmissionMetadataAllocation).
    AdmissionMetadataAllocation,
    /// Admission metadata byte count. [Detection, owner and recovery](#cause-AdmissionMetadataByteCount).
    AdmissionMetadataByteCount,
    /// Admission not active. [Detection, owner and recovery](#cause-AdmissionNotActive).
    AdmissionNotActive,
    /// Admission not pending. [Detection, owner and recovery](#cause-AdmissionNotPending).
    AdmissionNotPending,
    /// Admission observation plan exceeded. [Detection, owner and recovery](#cause-AdmissionObservationPlanExceeded).
    AdmissionObservationPlanExceeded,
    /// Admission preparation changed. [Detection, owner and recovery](#cause-AdmissionPreparationChanged).
    AdmissionPreparationChanged,
    /// Admission protection observations absent. [Detection, owner and recovery](#cause-AdmissionProtectionObservationsAbsent).
    AdmissionProtectionObservationsAbsent,
    /// Admission search functions unavailable. [Detection, owner and recovery](#cause-AdmissionSearchFunctionsUnavailable).
    AdmissionSearchFunctionsUnavailable,
    /// Admission selected handle absent. [Detection, owner and recovery](#cause-AdmissionSelectedHandleAbsent).
    AdmissionSelectedHandleAbsent,
    /// Agreement pair result owner mismatch. [Detection, owner and recovery](#cause-AgreementPairResultOwnerMismatch).
    AgreementPairResultOwnerMismatch,
    /// Attribute descriptor changed. [Detection, owner and recovery](#cause-AttributeDescriptorChanged).
    AttributeDescriptorChanged,
    /// Attribute frame absent. [Detection, owner and recovery](#cause-AttributeFrameAbsent).
    AttributeFrameAbsent,
    /// Attribute length exceeds allocated value buffer. [Detection, owner and recovery](#cause-AttributeLengthExceedsAllocatedValueBuffer).
    AttributeLengthExceedsAllocatedValueBuffer,
    /// Attribute owner absent. [Detection, owner and recovery](#cause-AttributeOwnerAbsent).
    AttributeOwnerAbsent,
    /// Attribute preparation changed. [Detection, owner and recovery](#cause-AttributePreparationChanged).
    AttributePreparationChanged,
    /// Attribute projection storage size. [Detection, owner and recovery](#cause-AttributeProjectionStorageSize).
    AttributeProjectionStorageSize,
    /// Attribute read detachment deferred. [Detection, owner and recovery](#cause-AttributeReadDetachmentDeferred).
    AttributeReadDetachmentDeferred,
    /// Attribute read incomplete. [Detection, owner and recovery](#cause-AttributeReadIncomplete).
    AttributeReadIncomplete,
    /// Attribute sizing owner shared. [Detection, owner and recovery](#cause-AttributeSizingOwnerShared).
    AttributeSizingOwnerShared,
    /// Attribute value already consumed. [Detection, owner and recovery](#cause-AttributeValueAlreadyConsumed).
    AttributeValueAlreadyConsumed,
    /// Base envelope absent. [Detection, owner and recovery](#cause-BaseEnvelopeAbsent).
    BaseEnvelopeAbsent,
    /// Base mechanism report absent. [Detection, owner and recovery](#cause-BaseMechanismReportAbsent).
    BaseMechanismReportAbsent,
    /// Base object report absent. [Detection, owner and recovery](#cause-BaseObjectReportAbsent).
    BaseObjectReportAbsent,
    /// Classical admission result owner mismatch. [Detection, owner and recovery](#cause-ClassicalAdmissionResultOwnerMismatch).
    ClassicalAdmissionResultOwnerMismatch,
    /// Classical material is part of its structural observation. [Detection, owner and recovery](#cause-ClassicalMaterialIsPartOfItsStructuralObservation).
    ClassicalMaterialIsPartOfItsStructuralObservation,
    /// Classical pair SPKI mismatch. [Detection, owner and recovery](#cause-ClassicalPairSpkiMismatch).
    ClassicalPairSpkiMismatch,
    /// Creation destination owner. [Detection, owner and recovery](#cause-CreationDestinationOwner).
    CreationDestinationOwner,
    /// Creation dispatch stage. [Detection, owner and recovery](#cause-CreationDispatchStage).
    CreationDispatchStage,
    /// Creation ticket absent. [Detection, owner and recovery](#cause-CreationTicketAbsent).
    CreationTicketAbsent,
    /// Creation ticket absent for cleanup. [Detection, owner and recovery](#cause-CreationTicketAbsentForCleanup).
    CreationTicketAbsentForCleanup,
    /// Derivation base publication class. [Detection, owner and recovery](#cause-DerivationBasePublicationClass).
    DerivationBasePublicationClass,
    /// Derivation base result owner mismatch. [Detection, owner and recovery](#cause-DerivationBaseResultOwnerMismatch).
    DerivationBaseResultOwnerMismatch,
    /// Destination owner absent. [Detection, owner and recovery](#cause-DestinationOwnerAbsent).
    DestinationOwnerAbsent,
    /// Destination owner allocation. [Detection, owner and recovery](#cause-DestinationOwnerAllocation).
    DestinationOwnerAllocation,
    /// Destination owner size. [Detection, owner and recovery](#cause-DestinationOwnerSize).
    DestinationOwnerSize,
    /// Destination preparation state. [Detection, owner and recovery](#cause-DestinationPreparationState).
    DestinationPreparationState,
    /// Destination report absent. [Detection, owner and recovery](#cause-DestinationReportAbsent).
    DestinationReportAbsent,
    /// Destination report incomplete. [Detection, owner and recovery](#cause-DestinationReportIncomplete).
    DestinationReportIncomplete,
    /// Destination transition. [Detection, owner and recovery](#cause-DestinationTransition).
    DestinationTransition,
    /// Duplicate admission completion. [Detection, owner and recovery](#cause-DuplicateAdmissionCompletion).
    DuplicateAdmissionCompletion,
    /// Duplicate attribute. [Detection, owner and recovery](#cause-DuplicateAttribute).
    DuplicateAttribute,
    /// Duplicate native generation. [Detection, owner and recovery](#cause-DuplicateNativeGeneration).
    DuplicateNativeGeneration,
    /// Family input absent. [Detection, owner and recovery](#cause-FamilyInputAbsent).
    FamilyInputAbsent,
    /// Generated pair handles. [Detection, owner and recovery](#cause-GeneratedPairHandles).
    GeneratedPairHandles,
    /// Generation candidate absent. [Detection, owner and recovery](#cause-GenerationCandidateAbsent).
    GenerationCandidateAbsent,
    /// Generation fixed allocation length. [Detection, owner and recovery](#cause-GenerationFixedAllocationLength).
    GenerationFixedAllocationLength,
    /// Generation functions unavailable. [Detection, owner and recovery](#cause-GenerationFunctionsUnavailable).
    GenerationFunctionsUnavailable,
    /// Generation input changed. [Detection, owner and recovery](#cause-GenerationInputChanged).
    GenerationInputChanged,
    /// Generation module unavailable. [Detection, owner and recovery](#cause-GenerationModuleUnavailable).
    GenerationModuleUnavailable,
    /// Generation owner absent. [Detection, owner and recovery](#cause-GenerationOwnerAbsent).
    GenerationOwnerAbsent,
    /// Generation policy. [Detection, owner and recovery](#cause-GenerationPolicy).
    GenerationPolicy,
    /// Generation publication absent. [Detection, owner and recovery](#cause-GenerationPublicationAbsent).
    GenerationPublicationAbsent,
    /// Generation publication arity. [Detection, owner and recovery](#cause-GenerationPublicationArity).
    GenerationPublicationArity,
    /// Generation publication incomplete. [Detection, owner and recovery](#cause-GenerationPublicationIncomplete).
    GenerationPublicationIncomplete,
    /// Generation retained metadata size. [Detection, owner and recovery](#cause-GenerationRetainedMetadataSize).
    GenerationRetainedMetadataSize,
    /// Generation stable allocation. [Detection, owner and recovery](#cause-GenerationStableAllocation).
    GenerationStableAllocation,
    /// Generation template arity. [Detection, owner and recovery](#cause-GenerationTemplateArity).
    GenerationTemplateArity,
    /// Generation ticket absent. [Detection, owner and recovery](#cause-GenerationTicketAbsent).
    GenerationTicketAbsent,
    /// Generation ticket already prepared. [Detection, owner and recovery](#cause-GenerationTicketAlreadyPrepared).
    GenerationTicketAlreadyPrepared,
    /// History observation owner absent. [Detection, owner and recovery](#cause-HistoryObservationOwnerAbsent).
    HistoryObservationOwnerAbsent,
    /// Initial family preparation changed. [Detection, owner and recovery](#cause-InitialFamilyPreparationChanged).
    InitialFamilyPreparationChanged,
    /// Initial family size. [Detection, owner and recovery](#cause-InitialFamilySize).
    InitialFamilySize,
    /// Introduced symmetric result owner mismatch. [Detection, owner and recovery](#cause-IntroducedSymmetricResultOwnerMismatch).
    IntroducedSymmetricResultOwnerMismatch,
    /// Invalid or repeated object handle. [Detection, owner and recovery](#cause-InvalidOrRepeatedObjectHandle).
    InvalidOrRepeatedObjectHandle,
    /// Joined admission output contract unresolved. [Detection, owner and recovery](#cause-JoinedAdmissionOutputContractUnresolved).
    JoinedAdmissionOutputContractUnresolved,
    /// Mechanism admission report absent. [Detection, owner and recovery](#cause-MechanismAdmissionReportAbsent).
    MechanismAdmissionReportAbsent,
    /// Mechanism projection absent. [Detection, owner and recovery](#cause-MechanismProjectionAbsent).
    MechanismProjectionAbsent,
    /// Mechanism projection allocation. [Detection, owner and recovery](#cause-MechanismProjectionAllocation).
    MechanismProjectionAllocation,
    /// Mechanism projection phase. [Detection, owner and recovery](#cause-MechanismProjectionPhase).
    MechanismProjectionPhase,
    /// Mechanism projection storage size. [Detection, owner and recovery](#cause-MechanismProjectionStorageSize).
    MechanismProjectionStorageSize,
    /// Object admission metadata byte count. [Detection, owner and recovery](#cause-ObjectAdmissionMetadataByteCount).
    ObjectAdmissionMetadataByteCount,
    /// Object admission report absent. [Detection, owner and recovery](#cause-ObjectAdmissionReportAbsent).
    ObjectAdmissionReportAbsent,
    /// Object report absent. [Detection, owner and recovery](#cause-ObjectReportAbsent).
    ObjectReportAbsent,
    /// Object search detachment deferred. [Detection, owner and recovery](#cause-ObjectSearchDetachmentDeferred).
    ObjectSearchDetachmentDeferred,
    /// Owned attribute allocation. [Detection, owner and recovery](#cause-OwnedAttributeAllocation).
    OwnedAttributeAllocation,
    /// Owned attribute metadata. [Detection, owner and recovery](#cause-OwnedAttributeMetadata).
    OwnedAttributeMetadata,
    /// Owned attribute metadata allocation. [Detection, owner and recovery](#cause-OwnedAttributeMetadataAllocation).
    OwnedAttributeMetadataAllocation,
    /// Owned attribute request. [Detection, owner and recovery](#cause-OwnedAttributeRequest).
    OwnedAttributeRequest,
    /// Pair envelope absent. [Detection, owner and recovery](#cause-PairEnvelopeAbsent).
    PairEnvelopeAbsent,
    /// Pair family absent. [Detection, owner and recovery](#cause-PairFamilyAbsent).
    PairFamilyAbsent,
    /// Pair history owner absent. [Detection, owner and recovery](#cause-PairHistoryOwnerAbsent).
    PairHistoryOwnerAbsent,
    /// Pair initial candidate absent. [Detection, owner and recovery](#cause-PairInitialCandidateAbsent).
    PairInitialCandidateAbsent,
    /// Pair initial preparation absent. [Detection, owner and recovery](#cause-PairInitialPreparationAbsent).
    PairInitialPreparationAbsent,
    /// Pair initial preparation changed. [Detection, owner and recovery](#cause-PairInitialPreparationChanged).
    PairInitialPreparationChanged,
    /// Pair owner storage accounting. [Detection, owner and recovery](#cause-PairOwnerStorageAccounting).
    PairOwnerStorageAccounting,
    /// Pair public observations absent. [Detection, owner and recovery](#cause-PairPublicObservationsAbsent).
    PairPublicObservationsAbsent,
    /// Prepared empty selector absent. [Detection, owner and recovery](#cause-PreparedEmptySelectorAbsent).
    PreparedEmptySelectorAbsent,
    /// Private material read is not an admission. [Detection, owner and recovery](#cause-PrivateMaterialReadIsNotAnAdmission).
    PrivateMaterialReadIsNotAnAdmission,
    /// Private search selector absent. [Detection, owner and recovery](#cause-PrivateSearchSelectorAbsent).
    PrivateSearchSelectorAbsent,
    /// Public material owner absent. [Detection, owner and recovery](#cause-PublicMaterialOwnerAbsent).
    PublicMaterialOwnerAbsent,
    /// Public mechanism admission report absent. [Detection, owner and recovery](#cause-PublicMechanismAdmissionReportAbsent).
    PublicMechanismAdmissionReportAbsent,
    /// Public object admission report absent. [Detection, owner and recovery](#cause-PublicObjectAdmissionReportAbsent).
    PublicObjectAdmissionReportAbsent,
    /// Search preparation changed. [Detection, owner and recovery](#cause-SearchPreparationChanged).
    SearchPreparationChanged,
    /// Search response acceptance changed. [Detection, owner and recovery](#cause-SearchResponseAcceptanceChanged).
    SearchResponseAcceptanceChanged,
    /// Session close during admission; explicit cleanup required. [Detection, owner and recovery](#cause-SessionCloseDuringAdmissionExplicitCleanupRequired).
    SessionCloseDuringAdmissionExplicitCleanupRequired,
    /// Session close during admission; rediscover. [Detection, owner and recovery](#cause-SessionCloseDuringAdmissionRediscover).
    SessionCloseDuringAdmissionRediscover,
    /// Symmetric admission metadata byte count. [Detection, owner and recovery](#cause-SymmetricAdmissionMetadataByteCount).
    SymmetricAdmissionMetadataByteCount,
    /// Symmetric admission result owner mismatch. [Detection, owner and recovery](#cause-SymmetricAdmissionResultOwnerMismatch).
    SymmetricAdmissionResultOwnerMismatch,
    /// Symmetric mechanism report absent. [Detection, owner and recovery](#cause-SymmetricMechanismReportAbsent).
    SymmetricMechanismReportAbsent,
    /// Synchronous admission pending; explicit close required. [Detection, owner and recovery](#cause-SynchronousAdmissionPendingExplicitCloseRequired).
    SynchronousAdmissionPendingExplicitCloseRequired,
    /// Transport signing result owner mismatch. [Detection, owner and recovery](#cause-TransportSigningResultOwnerMismatch).
    TransportSigningResultOwnerMismatch,
    /// Verification selection result owner mismatch. [Detection, owner and recovery](#cause-VerificationSelectionResultOwnerMismatch).
    VerificationSelectionResultOwnerMismatch,


}

impl std::fmt::Display for KeyAdmissionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AesKekAdmissionResultOwnerMismatch => {
                f.write_str("AES KEK admission result owner mismatch")
            }
            Self::AesKeyRequired => f.write_str("AES key required"),
            Self::MlKemCreationResultOwnerMismatch => {
                f.write_str("ML-KEM creation result owner mismatch")
            }
            Self::MlKemInitialPreparationChanged => {
                f.write_str("ML-KEM initial preparation changed")
            }
            Self::MlKemPairSpkiMismatch => f.write_str("ML-KEM pair SPKI mismatch"),
            Self::MlKemSelectionResultOwnerMismatch => {
                f.write_str("ML-KEM selection result owner mismatch")
            }
            Self::PqcAdmissionResultOwnerMismatch => {
                f.write_str("PQC admission result owner mismatch")
            }
            Self::PqcInitialPreparationChanged => f.write_str("PQC initial preparation changed"),
            Self::PqcPairSpkiMismatch => f.write_str("PQC pair SPKI mismatch"),
            Self::RsaTransportResultOwnerMismatch => {
                f.write_str("RSA transport result owner mismatch")
            }
            Self::AdmissionAsynchronousVersion => f.write_str("admission asynchronous version"),
            Self::AdmissionAttributesAbsent => f.write_str("admission attributes absent"),
            Self::AdmissionDiagnosticByteCount => f.write_str("admission diagnostic byte count"),
            Self::AdmissionFailedExplicitCleanupRequired => {
                f.write_str("admission failed; explicit cleanup required")
            }
            Self::AdmissionFramePhase => f.write_str("admission frame phase"),
            Self::AdmissionFunctionsUnavailable => f.write_str("admission functions unavailable"),
            Self::AdmissionIncomplete => f.write_str("admission incomplete"),
            Self::AdmissionMetadataAllocation => f.write_str("admission metadata allocation"),
            Self::AdmissionMetadataByteCount => f.write_str("admission metadata byte count"),
            Self::AdmissionNotActive => f.write_str("admission not active"),
            Self::AdmissionNotPending => f.write_str("admission not pending"),
            Self::AdmissionObservationPlanExceeded => {
                f.write_str("admission observation plan exceeded")
            }
            Self::AdmissionPreparationChanged => f.write_str("admission preparation changed"),
            Self::AdmissionProtectionObservationsAbsent => {
                f.write_str("admission protection observations absent")
            }
            Self::AdmissionSearchFunctionsUnavailable => {
                f.write_str("admission search functions unavailable")
            }
            Self::AdmissionSelectedHandleAbsent => f.write_str("admission selected handle absent"),
            Self::AgreementPairResultOwnerMismatch => {
                f.write_str("agreement pair result owner mismatch")
            }
            Self::AttributeDescriptorChanged => f.write_str("attribute descriptor changed"),
            Self::AttributeFrameAbsent => f.write_str("attribute frame absent"),
            Self::AttributeLengthExceedsAllocatedValueBuffer => {
                f.write_str("attribute length exceeds allocated value buffer")
            }
            Self::AttributeOwnerAbsent => f.write_str("attribute owner absent"),
            Self::AttributePreparationChanged => f.write_str("attribute preparation changed"),
            Self::AttributeProjectionStorageSize => {
                f.write_str("attribute projection storage size")
            }
            Self::AttributeReadDetachmentDeferred => {
                f.write_str("attribute read detachment deferred")
            }
            Self::AttributeReadIncomplete => f.write_str("attribute read incomplete"),
            Self::AttributeSizingOwnerShared => f.write_str("attribute sizing owner shared"),
            Self::AttributeValueAlreadyConsumed => f.write_str("attribute value already consumed"),
            Self::BaseEnvelopeAbsent => f.write_str("base envelope absent"),
            Self::BaseMechanismReportAbsent => f.write_str("base mechanism report absent"),
            Self::BaseObjectReportAbsent => f.write_str("base object report absent"),
            Self::ClassicalAdmissionResultOwnerMismatch => {
                f.write_str("classical admission result owner mismatch")
            }
            Self::ClassicalMaterialIsPartOfItsStructuralObservation => {
                f.write_str("classical material is part of its structural observation")
            }
            Self::ClassicalPairSpkiMismatch => f.write_str("classical pair SPKI mismatch"),
            Self::CreationDestinationOwner => f.write_str("creation destination owner"),
            Self::CreationDispatchStage => f.write_str("creation dispatch stage"),
            Self::CreationTicketAbsent => f.write_str("creation ticket absent"),
            Self::CreationTicketAbsentForCleanup => {
                f.write_str("creation ticket absent for cleanup")
            }
            Self::DerivationBasePublicationClass => {
                f.write_str("derivation base publication class")
            }
            Self::DerivationBaseResultOwnerMismatch => {
                f.write_str("derivation base result owner mismatch")
            }
            Self::DestinationOwnerAbsent => f.write_str("destination owner absent"),
            Self::DestinationOwnerAllocation => f.write_str("destination owner allocation"),
            Self::DestinationOwnerSize => f.write_str("destination owner size"),
            Self::DestinationPreparationState => f.write_str("destination preparation state"),
            Self::DestinationReportAbsent => f.write_str("destination report absent"),
            Self::DestinationReportIncomplete => f.write_str("destination report incomplete"),
            Self::DestinationTransition => f.write_str("destination transition"),
            Self::DuplicateAdmissionCompletion => f.write_str("duplicate admission completion"),
            Self::DuplicateAttribute => f.write_str("duplicate attribute"),
            Self::DuplicateNativeGeneration => f.write_str("duplicate native generation"),
            Self::FamilyInputAbsent => f.write_str("family input absent"),
            Self::GeneratedPairHandles => f.write_str("generated pair handles"),
            Self::GenerationCandidateAbsent => f.write_str("generation candidate absent"),
            Self::GenerationFixedAllocationLength => {
                f.write_str("generation fixed allocation length")
            }
            Self::GenerationFunctionsUnavailable => f.write_str("generation functions unavailable"),
            Self::GenerationInputChanged => f.write_str("generation input changed"),
            Self::GenerationModuleUnavailable => f.write_str("generation module unavailable"),
            Self::GenerationOwnerAbsent => f.write_str("generation owner absent"),
            Self::GenerationPolicy => f.write_str("generation policy"),
            Self::GenerationPublicationAbsent => f.write_str("generation publication absent"),
            Self::GenerationPublicationArity => f.write_str("generation publication arity"),
            Self::GenerationPublicationIncomplete => {
                f.write_str("generation publication incomplete")
            }
            Self::GenerationRetainedMetadataSize => {
                f.write_str("generation retained metadata size")
            }
            Self::GenerationStableAllocation => f.write_str("generation stable allocation"),
            Self::GenerationTemplateArity => f.write_str("generation template arity"),
            Self::GenerationTicketAbsent => f.write_str("generation ticket absent"),
            Self::GenerationTicketAlreadyPrepared => {
                f.write_str("generation ticket already prepared")
            }
            Self::HistoryObservationOwnerAbsent => f.write_str("history observation owner absent"),
            Self::InitialFamilyPreparationChanged => {
                f.write_str("initial family preparation changed")
            }
            Self::InitialFamilySize => f.write_str("initial family size"),
            Self::IntroducedSymmetricResultOwnerMismatch => {
                f.write_str("introduced symmetric result owner mismatch")
            }
            Self::InvalidOrRepeatedObjectHandle => f.write_str("invalid or repeated object handle"),
            Self::JoinedAdmissionOutputContractUnresolved => {
                f.write_str("joined admission output contract unresolved")
            }
            Self::MechanismAdmissionReportAbsent => {
                f.write_str("mechanism admission report absent")
            }
            Self::MechanismProjectionAbsent => f.write_str("mechanism projection absent"),
            Self::MechanismProjectionAllocation => f.write_str("mechanism projection allocation"),
            Self::MechanismProjectionPhase => f.write_str("mechanism projection phase"),
            Self::MechanismProjectionStorageSize => {
                f.write_str("mechanism projection storage size")
            }
            Self::ObjectAdmissionMetadataByteCount => {
                f.write_str("object admission metadata byte count")
            }
            Self::ObjectAdmissionReportAbsent => f.write_str("object admission report absent"),
            Self::ObjectReportAbsent => f.write_str("object report absent"),
            Self::ObjectSearchDetachmentDeferred => {
                f.write_str("object search detachment deferred")
            }
            Self::OwnedAttributeAllocation => f.write_str("owned attribute allocation"),
            Self::OwnedAttributeMetadata => f.write_str("owned attribute metadata"),
            Self::OwnedAttributeMetadataAllocation => {
                f.write_str("owned attribute metadata allocation")
            }
            Self::OwnedAttributeRequest => f.write_str("owned attribute request"),
            Self::PairEnvelopeAbsent => f.write_str("pair envelope absent"),
            Self::PairFamilyAbsent => f.write_str("pair family absent"),
            Self::PairHistoryOwnerAbsent => f.write_str("pair history owner absent"),
            Self::PairInitialCandidateAbsent => f.write_str("pair initial candidate absent"),
            Self::PairInitialPreparationAbsent => f.write_str("pair initial preparation absent"),
            Self::PairInitialPreparationChanged => f.write_str("pair initial preparation changed"),
            Self::PairOwnerStorageAccounting => f.write_str("pair owner storage accounting"),
            Self::PairPublicObservationsAbsent => f.write_str("pair public observations absent"),
            Self::PreparedEmptySelectorAbsent => f.write_str("prepared empty selector absent"),
            Self::PrivateMaterialReadIsNotAnAdmission => {
                f.write_str("private material read is not an admission")
            }
            Self::PrivateSearchSelectorAbsent => f.write_str("private search selector absent"),
            Self::PublicMaterialOwnerAbsent => f.write_str("public material owner absent"),
            Self::PublicMechanismAdmissionReportAbsent => {
                f.write_str("public mechanism admission report absent")
            }
            Self::PublicObjectAdmissionReportAbsent => {
                f.write_str("public object admission report absent")
            }
            Self::SearchPreparationChanged => f.write_str("search preparation changed"),
            Self::SearchResponseAcceptanceChanged => {
                f.write_str("search response acceptance changed")
            }
            Self::SessionCloseDuringAdmissionExplicitCleanupRequired => {
                f.write_str("session close during admission; explicit cleanup required")
            }
            Self::SessionCloseDuringAdmissionRediscover => {
                f.write_str("session close during admission; rediscover")
            }
            Self::SymmetricAdmissionMetadataByteCount => {
                f.write_str("symmetric admission metadata byte count")
            }
            Self::SymmetricAdmissionResultOwnerMismatch => {
                f.write_str("symmetric admission result owner mismatch")
            }
            Self::SymmetricMechanismReportAbsent => {
                f.write_str("symmetric mechanism report absent")
            }
            Self::SynchronousAdmissionPendingExplicitCloseRequired => {
                f.write_str("synchronous admission pending; explicit close required")
            }
            Self::TransportSigningResultOwnerMismatch => {
                f.write_str("transport signing result owner mismatch")
            }
            Self::VerificationSelectionResultOwnerMismatch => {
                f.write_str("verification selection result owner mismatch")
            }
        }
    }
}
