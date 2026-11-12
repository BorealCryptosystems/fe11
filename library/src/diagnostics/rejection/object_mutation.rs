// SPDX-License-Identifier: Apache-2.0
//! ObjectMutation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object mutation.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_mutation.md")]
pub enum ObjectMutationRejection {
    /// C_SetAttributeValue unavailable. [Detection, owner and recovery](#cause-CSetAttributeValueUnavailable).
    CSetAttributeValueUnavailable,
    /// Attribute mutation already dispatched. [Detection, owner and recovery](#cause-AttributeMutationAlreadyDispatched).
    AttributeMutationAlreadyDispatched,
    /// Attribute mutation candidate kind. [Detection, owner and recovery](#cause-AttributeMutationCandidateKind).
    AttributeMutationCandidateKind,
    /// Attribute mutation completion phase. [Detection, owner and recovery](#cause-AttributeMutationCompletionPhase).
    AttributeMutationCompletionPhase,
    /// Attribute mutation continuation changed. [Detection, owner and recovery](#cause-AttributeMutationContinuationChanged).
    AttributeMutationContinuationChanged,
    /// Attribute mutation incomplete. [Detection, owner and recovery](#cause-AttributeMutationIncomplete).
    AttributeMutationIncomplete,
    /// Attribute mutation input changed. [Detection, owner and recovery](#cause-AttributeMutationInputChanged).
    AttributeMutationInputChanged,
    /// Attribute mutation owner absent. [Detection, owner and recovery](#cause-AttributeMutationOwnerAbsent).
    AttributeMutationOwnerAbsent,
    /// Attribute mutation possession absent. [Detection, owner and recovery](#cause-AttributeMutationPossessionAbsent).
    AttributeMutationPossessionAbsent,
    /// Attribute mutation preparation accounting. [Detection, owner and recovery](#cause-AttributeMutationPreparationAccounting).
    AttributeMutationPreparationAccounting,
    /// Attribute mutation resource need absent. [Detection, owner and recovery](#cause-AttributeMutationResourceNeedAbsent).
    AttributeMutationResourceNeedAbsent,
    /// Attribute mutation stopped. [Detection, owner and recovery](#cause-AttributeMutationStopped).
    AttributeMutationStopped,
    /// Attribute mutation storage size. [Detection, owner and recovery](#cause-AttributeMutationStorageSize).
    AttributeMutationStorageSize,
    /// Certificate DER. [Detection, owner and recovery](#cause-CertificateDer).
    CertificateDer,
    /// Certificate category native width. [Detection, owner and recovery](#cause-CertificateCategoryNativeWidth).
    CertificateCategoryNativeWidth,
    /// Certificate encoding. [Detection, owner and recovery](#cause-CertificateEncoding).
    CertificateEncoding,
    /// Certificate size. [Detection, owner and recovery](#cause-CertificateSize).
    CertificateSize,
    /// Content class absent. [Detection, owner and recovery](#cause-ContentClassAbsent).
    ContentClassAbsent,
    /// Content creation storage size. [Detection, owner and recovery](#cause-ContentCreationStorageSize).
    ContentCreationStorageSize,
    /// Data type OID. [Detection, owner and recovery](#cause-DataTypeOid).
    DataTypeOid,
    /// Data type OID encoding. [Detection, owner and recovery](#cause-DataTypeOidEncoding).
    DataTypeOidEncoding,
    /// Destination allocation. [Detection, owner and recovery](#cause-DestinationAllocation).
    DestinationAllocation,
    /// Destination class exceeds native width. [Detection, owner and recovery](#cause-DestinationClassExceedsNativeWidth).
    DestinationClassExceedsNativeWidth,
    /// Destination class tuple shape. [Detection, owner and recovery](#cause-DestinationClassTupleShape).
    DestinationClassTupleShape,
    /// Destination count. [Detection, owner and recovery](#cause-DestinationCount).
    DestinationCount,
    /// Destination outside reservation. [Detection, owner and recovery](#cause-DestinationOutsideReservation).
    DestinationOutsideReservation,
    /// Destination preparation allocation. [Detection, owner and recovery](#cause-DestinationPreparationAllocation).
    DestinationPreparationAllocation,
    /// Destination probe already consumed. [Detection, owner and recovery](#cause-DestinationProbeAlreadyConsumed).
    DestinationProbeAlreadyConsumed,
    /// Destination quota exceeded. [Detection, owner and recovery](#cause-DestinationQuotaExceeded).
    DestinationQuotaExceeded,
    /// Duplicate selection. [Detection, owner and recovery](#cause-DuplicateSelection).
    DuplicateSelection,
    /// Dynamic reader aggregate accounting. [Detection, owner and recovery](#cause-DynamicReaderAggregateAccounting).
    DynamicReaderAggregateAccounting,
    /// Foreign inventory preparation. [Detection, owner and recovery](#cause-ForeignInventoryPreparation).
    ForeignInventoryPreparation,
    /// Foreign operation destination. [Detection, owner and recovery](#cause-ForeignOperationDestination).
    ForeignOperationDestination,
    /// Foreign operation reservation. [Detection, owner and recovery](#cause-ForeignOperationReservation).
    ForeignOperationReservation,
    /// Foreign operation selection. [Detection, owner and recovery](#cause-ForeignOperationSelection).
    ForeignOperationSelection,
    /// Foreign prepared selection. [Detection, owner and recovery](#cause-ForeignPreparedSelection).
    ForeignPreparedSelection,
    /// Generation coordination accounting. [Detection, owner and recovery](#cause-GenerationCoordinationAccounting).
    GenerationCoordinationAccounting,
    /// Generation destination accounting. [Detection, owner and recovery](#cause-GenerationDestinationAccounting).
    GenerationDestinationAccounting,
    /// Generation probe already consumed. [Detection, owner and recovery](#cause-GenerationProbeAlreadyConsumed).
    GenerationProbeAlreadyConsumed,
    /// Invalid resource activity handle. [Detection, owner and recovery](#cause-InvalidResourceActivityHandle).
    InvalidResourceActivityHandle,
    /// Inventory allocation. [Detection, owner and recovery](#cause-InventoryAllocation).
    InventoryAllocation,
    /// Inventory count. [Detection, owner and recovery](#cause-InventoryCount).
    InventoryCount,
    /// Inventory owner allocation. [Detection, owner and recovery](#cause-InventoryOwnerAllocation).
    InventoryOwnerAllocation,
    /// Inventory owner size. [Detection, owner and recovery](#cause-InventoryOwnerSize).
    InventoryOwnerSize,
    /// Inventory preparation already published. [Detection, owner and recovery](#cause-InventoryPreparationAlreadyPublished).
    InventoryPreparationAlreadyPublished,
    /// Inventory preparation already shared. [Detection, owner and recovery](#cause-InventoryPreparationAlreadyShared).
    InventoryPreparationAlreadyShared,
    /// Issuer encoding. [Detection, owner and recovery](#cause-IssuerEncoding).
    IssuerEncoding,
    /// Key selection class. [Detection, owner and recovery](#cause-KeySelectionClass).
    KeySelectionClass,
    /// Label admission phase. [Detection, owner and recovery](#cause-LabelAdmissionPhase).
    LabelAdmissionPhase,
    /// Label admission preparation absent. [Detection, owner and recovery](#cause-LabelAdmissionPreparationAbsent).
    LabelAdmissionPreparationAbsent,
    /// Label already dispatched. [Detection, owner and recovery](#cause-LabelAlreadyDispatched).
    LabelAlreadyDispatched,
    /// Label candidate kind. [Detection, owner and recovery](#cause-LabelCandidateKind).
    LabelCandidateKind,
    /// Label class preparation absent. [Detection, owner and recovery](#cause-LabelClassPreparationAbsent).
    LabelClassPreparationAbsent,
    /// Label continuation changed. [Detection, owner and recovery](#cause-LabelContinuationChanged).
    LabelContinuationChanged,
    /// Label destination phase. [Detection, owner and recovery](#cause-LabelDestinationPhase).
    LabelDestinationPhase,
    /// Label destination preparation absent. [Detection, owner and recovery](#cause-LabelDestinationPreparationAbsent).
    LabelDestinationPreparationAbsent,
    /// Label metadata phase. [Detection, owner and recovery](#cause-LabelMetadataPhase).
    LabelMetadataPhase,
    /// Label mutation completion phase. [Detection, owner and recovery](#cause-LabelMutationCompletionPhase).
    LabelMutationCompletionPhase,
    /// Label mutation incomplete. [Detection, owner and recovery](#cause-LabelMutationIncomplete).
    LabelMutationIncomplete,
    /// Label mutation stopped. [Detection, owner and recovery](#cause-LabelMutationStopped).
    LabelMutationStopped,
    /// Label mutation storage size. [Detection, owner and recovery](#cause-LabelMutationStorageSize).
    LabelMutationStorageSize,
    /// Label owner absent. [Detection, owner and recovery](#cause-LabelOwnerAbsent).
    LabelOwnerAbsent,
    /// Label possession absent. [Detection, owner and recovery](#cause-LabelPossessionAbsent).
    LabelPossessionAbsent,
    /// Label publication quota transferred. [Detection, owner and recovery](#cause-LabelPublicationQuotaTransferred).
    LabelPublicationQuotaTransferred,
    /// Label reference phase. [Detection, owner and recovery](#cause-LabelReferencePhase).
    LabelReferencePhase,
    /// Label resource need absent. [Detection, owner and recovery](#cause-LabelResourceNeedAbsent).
    LabelResourceNeedAbsent,
    /// Managed selection allocation. [Detection, owner and recovery](#cause-ManagedSelectionAllocation).
    ManagedSelectionAllocation,
    /// Mutation content phase. [Detection, owner and recovery](#cause-MutationContentPhase).
    MutationContentPhase,
    /// Mutation destination phase. [Detection, owner and recovery](#cause-MutationDestinationPhase).
    MutationDestinationPhase,
    /// Mutation fingerprint phase. [Detection, owner and recovery](#cause-MutationFingerprintPhase).
    MutationFingerprintPhase,
    /// Mutation fingerprint selection. [Detection, owner and recovery](#cause-MutationFingerprintSelection).
    MutationFingerprintSelection,
    /// Mutation metadata phase. [Detection, owner and recovery](#cause-MutationMetadataPhase).
    MutationMetadataPhase,
    /// Mutation observation field count. [Detection, owner and recovery](#cause-MutationObservationFieldCount).
    MutationObservationFieldCount,
    /// Mutation observation requires prepared owner. [Detection, owner and recovery](#cause-MutationObservationRequiresPreparedOwner).
    MutationObservationRequiresPreparedOwner,
    /// Mutation owner absent. [Detection, owner and recovery](#cause-MutationOwnerAbsent).
    MutationOwnerAbsent,
    /// Mutation reference phase. [Detection, owner and recovery](#cause-MutationReferencePhase).
    MutationReferencePhase,
    /// Mutation source preparation absent. [Detection, owner and recovery](#cause-MutationSourcePreparationAbsent).
    MutationSourcePreparationAbsent,
    /// Noncanonical certificate. [Detection, owner and recovery](#cause-NoncanonicalCertificate).
    NoncanonicalCertificate,
    /// Noncanonical data type. [Detection, owner and recovery](#cause-NoncanonicalDataType).
    NoncanonicalDataType,
    /// Object destination reserved. [Detection, owner and recovery](#cause-ObjectDestinationReserved).
    ObjectDestinationReserved,
    /// Operation activity allocation. [Detection, owner and recovery](#cause-OperationActivityAllocation).
    OperationActivityAllocation,
    /// Operation destination allocation. [Detection, owner and recovery](#cause-OperationDestinationAllocation).
    OperationDestinationAllocation,
    /// Operation destination changed. [Detection, owner and recovery](#cause-OperationDestinationChanged).
    OperationDestinationChanged,
    /// Operation destination count. [Detection, owner and recovery](#cause-OperationDestinationCount).
    OperationDestinationCount,
    /// Operation retention absent. [Detection, owner and recovery](#cause-OperationRetentionAbsent).
    OperationRetentionAbsent,
    /// Operation selection allocation. [Detection, owner and recovery](#cause-OperationSelectionAllocation).
    OperationSelectionAllocation,
    /// Pair selection allocation. [Detection, owner and recovery](#cause-PairSelectionAllocation).
    PairSelectionAllocation,
    /// Public pair selection preparation. [Detection, owner and recovery](#cause-PublicPairSelectionPreparation).
    PublicPairSelectionPreparation,
    /// Requested destination operand unavailable. [Detection, owner and recovery](#cause-RequestedDestinationOperandUnavailable).
    RequestedDestinationOperandUnavailable,
    /// Reservation activity allocation. [Detection, owner and recovery](#cause-ReservationActivityAllocation).
    ReservationActivityAllocation,
    /// Reservation activity storage size. [Detection, owner and recovery](#cause-ReservationActivityStorageSize).
    ReservationActivityStorageSize,
    /// Reservation activity vector size. [Detection, owner and recovery](#cause-ReservationActivityVectorSize).
    ReservationActivityVectorSize,
    /// Reservation destination allocation. [Detection, owner and recovery](#cause-ReservationDestinationAllocation).
    ReservationDestinationAllocation,
    /// Reservation preparation size. [Detection, owner and recovery](#cause-ReservationPreparationSize).
    ReservationPreparationSize,
    /// Reservation vector size. [Detection, owner and recovery](#cause-ReservationVectorSize).
    ReservationVectorSize,
    /// Resource activity allocation. [Detection, owner and recovery](#cause-ResourceActivityAllocation).
    ResourceActivityAllocation,
    /// Resource publication capacity. [Detection, owner and recovery](#cause-ResourcePublicationCapacity).
    ResourcePublicationCapacity,
    /// Selection allocation. [Detection, owner and recovery](#cause-SelectionAllocation).
    SelectionAllocation,
    /// Selection count. [Detection, owner and recovery](#cause-SelectionCount).
    SelectionCount,
    /// Serial encoding. [Detection, owner and recovery](#cause-SerialEncoding).
    SerialEncoding,
    /// Subject encoding. [Detection, owner and recovery](#cause-SubjectEncoding).
    SubjectEncoding,
    /// Unknown class selection contract. [Detection, owner and recovery](#cause-UnknownClassSelectionContract).
    UnknownClassSelectionContract,
    /// Unobserved destination class. [Detection, owner and recovery](#cause-UnobservedDestinationClass).
    UnobservedDestinationClass,
    /// Unselected mutation content. [Detection, owner and recovery](#cause-UnselectedMutationContent).
    UnselectedMutationContent,
}

impl std::fmt::Display for ObjectMutationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CSetAttributeValueUnavailable => f.write_str("C_SetAttributeValue unavailable"),
            Self::AttributeMutationAlreadyDispatched => {
                f.write_str("attribute mutation already dispatched")
            }
            Self::AttributeMutationCandidateKind => {
                f.write_str("attribute mutation candidate kind")
            }
            Self::AttributeMutationCompletionPhase => {
                f.write_str("attribute mutation completion phase")
            }
            Self::AttributeMutationContinuationChanged => {
                f.write_str("attribute mutation continuation changed")
            }
            Self::AttributeMutationIncomplete => f.write_str("attribute mutation incomplete"),
            Self::AttributeMutationInputChanged => f.write_str("attribute mutation input changed"),
            Self::AttributeMutationOwnerAbsent => f.write_str("attribute mutation owner absent"),
            Self::AttributeMutationPossessionAbsent => {
                f.write_str("attribute mutation possession absent")
            }
            Self::AttributeMutationPreparationAccounting => {
                f.write_str("attribute mutation preparation accounting")
            }
            Self::AttributeMutationResourceNeedAbsent => {
                f.write_str("attribute mutation resource need absent")
            }
            Self::AttributeMutationStopped => f.write_str("attribute mutation stopped"),
            Self::AttributeMutationStorageSize => f.write_str("attribute mutation storage size"),
            Self::CertificateDer => f.write_str("certificate DER"),
            Self::CertificateCategoryNativeWidth => {
                f.write_str("certificate category native width")
            }
            Self::CertificateEncoding => f.write_str("certificate encoding"),
            Self::CertificateSize => f.write_str("certificate size"),
            Self::ContentClassAbsent => f.write_str("content class absent"),
            Self::ContentCreationStorageSize => f.write_str("content creation storage size"),
            Self::DataTypeOid => f.write_str("data type OID"),
            Self::DataTypeOidEncoding => f.write_str("data type OID encoding"),
            Self::DestinationAllocation => f.write_str("destination allocation"),
            Self::DestinationClassExceedsNativeWidth => {
                f.write_str("destination class exceeds native width")
            }
            Self::DestinationClassTupleShape => f.write_str("destination class tuple shape"),
            Self::DestinationCount => f.write_str("destination count"),
            Self::DestinationOutsideReservation => f.write_str("destination outside reservation"),
            Self::DestinationPreparationAllocation => {
                f.write_str("destination preparation allocation")
            }
            Self::DestinationProbeAlreadyConsumed => {
                f.write_str("destination probe already consumed")
            }
            Self::DestinationQuotaExceeded => f.write_str("destination quota exceeded"),
            Self::DuplicateSelection => f.write_str("duplicate selection"),
            Self::DynamicReaderAggregateAccounting => {
                f.write_str("dynamic reader aggregate accounting")
            }
            Self::ForeignInventoryPreparation => f.write_str("foreign inventory preparation"),
            Self::ForeignOperationDestination => f.write_str("foreign operation destination"),
            Self::ForeignOperationReservation => f.write_str("foreign operation reservation"),
            Self::ForeignOperationSelection => f.write_str("foreign operation selection"),
            Self::ForeignPreparedSelection => f.write_str("foreign prepared selection"),
            Self::GenerationCoordinationAccounting => {
                f.write_str("generation coordination accounting")
            }
            Self::GenerationDestinationAccounting => {
                f.write_str("generation destination accounting")
            }
            Self::GenerationProbeAlreadyConsumed => {
                f.write_str("generation probe already consumed")
            }
            Self::InvalidResourceActivityHandle => f.write_str("invalid resource activity handle"),
            Self::InventoryAllocation => f.write_str("inventory allocation"),
            Self::InventoryCount => f.write_str("inventory count"),
            Self::InventoryOwnerAllocation => f.write_str("inventory owner allocation"),
            Self::InventoryOwnerSize => f.write_str("inventory owner size"),
            Self::InventoryPreparationAlreadyPublished => {
                f.write_str("inventory preparation already published")
            }
            Self::InventoryPreparationAlreadyShared => {
                f.write_str("inventory preparation already shared")
            }
            Self::IssuerEncoding => f.write_str("issuer encoding"),
            Self::KeySelectionClass => f.write_str("key selection class"),
            Self::LabelAdmissionPhase => f.write_str("label admission phase"),
            Self::LabelAdmissionPreparationAbsent => {
                f.write_str("label admission preparation absent")
            }
            Self::LabelAlreadyDispatched => f.write_str("label already dispatched"),
            Self::LabelCandidateKind => f.write_str("label candidate kind"),
            Self::LabelClassPreparationAbsent => f.write_str("label class preparation absent"),
            Self::LabelContinuationChanged => f.write_str("label continuation changed"),
            Self::LabelDestinationPhase => f.write_str("label destination phase"),
            Self::LabelDestinationPreparationAbsent => {
                f.write_str("label destination preparation absent")
            }
            Self::LabelMetadataPhase => f.write_str("label metadata phase"),
            Self::LabelMutationCompletionPhase => f.write_str("label mutation completion phase"),
            Self::LabelMutationIncomplete => f.write_str("label mutation incomplete"),
            Self::LabelMutationStopped => f.write_str("label mutation stopped"),
            Self::LabelMutationStorageSize => f.write_str("label mutation storage size"),
            Self::LabelOwnerAbsent => f.write_str("label owner absent"),
            Self::LabelPossessionAbsent => f.write_str("label possession absent"),
            Self::LabelPublicationQuotaTransferred => {
                f.write_str("label publication quota transferred")
            }
            Self::LabelReferencePhase => f.write_str("label reference phase"),
            Self::LabelResourceNeedAbsent => f.write_str("label resource need absent"),
            Self::ManagedSelectionAllocation => f.write_str("managed selection allocation"),
            Self::MutationContentPhase => f.write_str("mutation content phase"),
            Self::MutationDestinationPhase => f.write_str("mutation destination phase"),
            Self::MutationFingerprintPhase => f.write_str("mutation fingerprint phase"),
            Self::MutationFingerprintSelection => f.write_str("mutation fingerprint selection"),
            Self::MutationMetadataPhase => f.write_str("mutation metadata phase"),
            Self::MutationObservationFieldCount => f.write_str("mutation observation field count"),
            Self::MutationObservationRequiresPreparedOwner => {
                f.write_str("mutation observation requires prepared owner")
            }
            Self::MutationOwnerAbsent => f.write_str("mutation owner absent"),
            Self::MutationReferencePhase => f.write_str("mutation reference phase"),
            Self::MutationSourcePreparationAbsent => {
                f.write_str("mutation source preparation absent")
            }
            Self::NoncanonicalCertificate => f.write_str("noncanonical certificate"),
            Self::NoncanonicalDataType => f.write_str("noncanonical data type"),
            Self::ObjectDestinationReserved => f.write_str("object destination reserved"),
            Self::OperationActivityAllocation => f.write_str("operation activity allocation"),
            Self::OperationDestinationAllocation => f.write_str("operation destination allocation"),
            Self::OperationDestinationChanged => f.write_str("operation destination changed"),
            Self::OperationDestinationCount => f.write_str("operation destination count"),
            Self::OperationRetentionAbsent => f.write_str("operation retention absent"),
            Self::OperationSelectionAllocation => f.write_str("operation selection allocation"),
            Self::PairSelectionAllocation => f.write_str("pair selection allocation"),
            Self::PublicPairSelectionPreparation => {
                f.write_str("public pair selection preparation")
            }
            Self::RequestedDestinationOperandUnavailable => {
                f.write_str("requested destination operand unavailable")
            }
            Self::ReservationActivityAllocation => f.write_str("reservation activity allocation"),
            Self::ReservationActivityStorageSize => {
                f.write_str("reservation activity storage size")
            }
            Self::ReservationActivityVectorSize => f.write_str("reservation activity vector size"),
            Self::ReservationDestinationAllocation => {
                f.write_str("reservation destination allocation")
            }
            Self::ReservationPreparationSize => f.write_str("reservation preparation size"),
            Self::ReservationVectorSize => f.write_str("reservation vector size"),
            Self::ResourceActivityAllocation => f.write_str("resource activity allocation"),
            Self::ResourcePublicationCapacity => f.write_str("resource publication capacity"),
            Self::SelectionAllocation => f.write_str("selection allocation"),
            Self::SelectionCount => f.write_str("selection count"),
            Self::SerialEncoding => f.write_str("serial encoding"),
            Self::SubjectEncoding => f.write_str("subject encoding"),
            Self::UnknownClassSelectionContract => f.write_str("unknown class selection contract"),
            Self::UnobservedDestinationClass => f.write_str("unobserved destination class"),
            Self::UnselectedMutationContent => f.write_str("unselected mutation content"),
        }
    }
}
