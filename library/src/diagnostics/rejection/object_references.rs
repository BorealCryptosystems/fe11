// SPDX-License-Identifier: Apache-2.0
//! ObjectReferences causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object references.
#[doc = include_str!("../../../docs/diagnostics/rejection-object_references.md")]
pub enum ObjectReferencesRejection {
    /// C_GetObjectSize unavailable. [Detection, owner and recovery](#cause-CGetObjectSizeUnavailable).
    CGetObjectSizeUnavailable,
    /// RSA observed publication absent. [Detection, owner and recovery](#cause-RsaObservedPublicationAbsent).
    RsaObservedPublicationAbsent,
    /// RSA private evidence absent. [Detection, owner and recovery](#cause-RsaPrivateEvidenceAbsent).
    RsaPrivateEvidenceAbsent,
    /// RSA readmission storage size. [Detection, owner and recovery](#cause-RsaReadmissionStorageSize).
    RsaReadmissionStorageSize,
    /// RSA reference preparation absent. [Detection, owner and recovery](#cause-RsaReferencePreparationAbsent).
    RsaReferencePreparationAbsent,
    /// RSA reference quota transferred. [Detection, owner and recovery](#cause-RsaReferenceQuotaTransferred).
    RsaReferenceQuotaTransferred,
    /// Destination aggregate accounting. [Detection, owner and recovery](#cause-DestinationAggregateAccounting).
    DestinationAggregateAccounting,
    /// Destruction already dispatched. [Detection, owner and recovery](#cause-DestructionAlreadyDispatched).
    DestructionAlreadyDispatched,
    /// Destruction diagnostic already consumed. [Detection, owner and recovery](#cause-DestructionDiagnosticAlreadyConsumed).
    DestructionDiagnosticAlreadyConsumed,
    /// Destruction observation absent. [Detection, owner and recovery](#cause-DestructionObservationAbsent).
    DestructionObservationAbsent,
    /// Destruction owner absent. [Detection, owner and recovery](#cause-DestructionOwnerAbsent).
    DestructionOwnerAbsent,
    /// Destruction possession absent. [Detection, owner and recovery](#cause-DestructionPossessionAbsent).
    DestructionPossessionAbsent,
    /// Destruction preparation accounting. [Detection, owner and recovery](#cause-DestructionPreparationAccounting).
    DestructionPreparationAccounting,
    /// Destruction resource need absent. [Detection, owner and recovery](#cause-DestructionResourceNeedAbsent).
    DestructionResourceNeedAbsent,
    /// Destruction storage size. [Detection, owner and recovery](#cause-DestructionStorageSize).
    DestructionStorageSize,
    /// Discovery activity already bound. [Detection, owner and recovery](#cause-DiscoveryActivityAlreadyBound).
    DiscoveryActivityAlreadyBound,
    /// Discovery identity already shared. [Detection, owner and recovery](#cause-DiscoveryIdentityAlreadyShared).
    DiscoveryIdentityAlreadyShared,
    /// Discovery identity mismatch. [Detection, owner and recovery](#cause-DiscoveryIdentityMismatch).
    DiscoveryIdentityMismatch,
    /// Foreign destruction resource. [Detection, owner and recovery](#cause-ForeignDestructionResource).
    ForeignDestructionResource,
    /// Foreign native object. [Detection, owner and recovery](#cause-ForeignNativeObject).
    ForeignNativeObject,
    /// Foreign or stale managed object. [Detection, owner and recovery](#cause-ForeignOrStaleManagedObject).
    ForeignOrStaleManagedObject,
    /// Foreign or stale native object. [Detection, owner and recovery](#cause-ForeignOrStaleNativeObject).
    ForeignOrStaleNativeObject,
    /// Invalid admitted handle. [Detection, owner and recovery](#cause-InvalidAdmittedHandle).
    InvalidAdmittedHandle,
    /// Invalid returned native handle. [Detection, owner and recovery](#cause-InvalidReturnedNativeHandle).
    InvalidReturnedNativeHandle,
    /// Inventory sort capacity. [Detection, owner and recovery](#cause-InventorySortCapacity).
    InventorySortCapacity,
    /// Key evidence preparation absent. [Detection, owner and recovery](#cause-KeyEvidencePreparationAbsent).
    KeyEvidencePreparationAbsent,
    /// Key publication absent. [Detection, owner and recovery](#cause-KeyPublicationAbsent).
    KeyPublicationAbsent,
    /// Key readmission candidate kind. [Detection, owner and recovery](#cause-KeyReadmissionCandidateKind).
    KeyReadmissionCandidateKind,
    /// Key readmission completion phase. [Detection, owner and recovery](#cause-KeyReadmissionCompletionPhase).
    KeyReadmissionCompletionPhase,
    /// Key readmission continuation changed. [Detection, owner and recovery](#cause-KeyReadmissionContinuationChanged).
    KeyReadmissionContinuationChanged,
    /// Key readmission incomplete. [Detection, owner and recovery](#cause-KeyReadmissionIncomplete).
    KeyReadmissionIncomplete,
    /// Key readmission need absent. [Detection, owner and recovery](#cause-KeyReadmissionNeedAbsent).
    KeyReadmissionNeedAbsent,
    /// Key readmission owner absent. [Detection, owner and recovery](#cause-KeyReadmissionOwnerAbsent).
    KeyReadmissionOwnerAbsent,
    /// Key readmission possession absent. [Detection, owner and recovery](#cause-KeyReadmissionPossessionAbsent).
    KeyReadmissionPossessionAbsent,
    /// Key readmission stopped. [Detection, owner and recovery](#cause-KeyReadmissionStopped).
    KeyReadmissionStopped,
    /// Key readmission storage size. [Detection, owner and recovery](#cause-KeyReadmissionStorageSize).
    KeyReadmissionStorageSize,
    /// Key reference preparation absent. [Detection, owner and recovery](#cause-KeyReferencePreparationAbsent).
    KeyReferencePreparationAbsent,
    /// Key reference quota transferred. [Detection, owner and recovery](#cause-KeyReferenceQuotaTransferred).
    KeyReferenceQuotaTransferred,
    /// Key type width. [Detection, owner and recovery](#cause-KeyTypeWidth).
    KeyTypeWidth,
    /// Native creation already published. [Detection, owner and recovery](#cause-NativeCreationAlreadyPublished).
    NativeCreationAlreadyPublished,
    /// Native creation not published. [Detection, owner and recovery](#cause-NativeCreationNotPublished).
    NativeCreationNotPublished,
    /// Native identity activity already bound. [Detection, owner and recovery](#cause-NativeIdentityActivityAlreadyBound).
    NativeIdentityActivityAlreadyBound,
    /// Native identity not published. [Detection, owner and recovery](#cause-NativeIdentityNotPublished).
    NativeIdentityNotPublished,
    /// Native identity preparation already shared. [Detection, owner and recovery](#cause-NativeIdentityPreparationAlreadyShared).
    NativeIdentityPreparationAlreadyShared,
    /// Native identity preparation mismatch. [Detection, owner and recovery](#cause-NativeIdentityPreparationMismatch).
    NativeIdentityPreparationMismatch,
    /// Object observation lifetime changed. [Detection, owner and recovery](#cause-ObjectObservationLifetimeChanged).
    ObjectObservationLifetimeChanged,
    /// Object size aggregate accounting overflow. [Detection, owner and recovery](#cause-ObjectSizeAggregateAccountingOverflow).
    ObjectSizeAggregateAccountingOverflow,
    /// Object size metadata accounting overflow. [Detection, owner and recovery](#cause-ObjectSizeMetadataAccountingOverflow).
    ObjectSizeMetadataAccountingOverflow,
    /// Observation native handle changed. [Detection, owner and recovery](#cause-ObservationNativeHandleChanged).
    ObservationNativeHandleChanged,
    /// Public fingerprint candidate kind. [Detection, owner and recovery](#cause-PublicFingerprintCandidateKind).
    PublicFingerprintCandidateKind,
    /// Public fingerprint completion phase. [Detection, owner and recovery](#cause-PublicFingerprintCompletionPhase).
    PublicFingerprintCompletionPhase,
    /// Public fingerprint content phase. [Detection, owner and recovery](#cause-PublicFingerprintContentPhase).
    PublicFingerprintContentPhase,
    /// Public fingerprint continuation changed. [Detection, owner and recovery](#cause-PublicFingerprintContinuationChanged).
    PublicFingerprintContinuationChanged,
    /// Public fingerprint incomplete. [Detection, owner and recovery](#cause-PublicFingerprintIncomplete).
    PublicFingerprintIncomplete,
    /// Public fingerprint need absent. [Detection, owner and recovery](#cause-PublicFingerprintNeedAbsent).
    PublicFingerprintNeedAbsent,
    /// Public fingerprint owner absent. [Detection, owner and recovery](#cause-PublicFingerprintOwnerAbsent).
    PublicFingerprintOwnerAbsent,
    /// Public fingerprint possession absent. [Detection, owner and recovery](#cause-PublicFingerprintPossessionAbsent).
    PublicFingerprintPossessionAbsent,
    /// Public fingerprint search phase. [Detection, owner and recovery](#cause-PublicFingerprintSearchPhase).
    PublicFingerprintSearchPhase,
    /// Public fingerprint stopped. [Detection, owner and recovery](#cause-PublicFingerprintStopped).
    PublicFingerprintStopped,
    /// Public fingerprint storage size. [Detection, owner and recovery](#cause-PublicFingerprintStorageSize).
    PublicFingerprintStorageSize,
    /// Public-key evidence absent. [Detection, owner and recovery](#cause-PublicKeyEvidenceAbsent).
    PublicKeyEvidenceAbsent,
    /// Readmission selection absent. [Detection, owner and recovery](#cause-ReadmissionSelectionAbsent).
    ReadmissionSelectionAbsent,
    /// Reference candidate kind. [Detection, owner and recovery](#cause-ReferenceCandidateKind).
    ReferenceCandidateKind,
    /// Reference cardinality width. [Detection, owner and recovery](#cause-ReferenceCardinalityWidth).
    ReferenceCardinalityWidth,
    /// Reference completion phase. [Detection, owner and recovery](#cause-ReferenceCompletionPhase).
    ReferenceCompletionPhase,
    /// Reference content phase. [Detection, owner and recovery](#cause-ReferenceContentPhase).
    ReferenceContentPhase,
    /// Reference continuation changed. [Detection, owner and recovery](#cause-ReferenceContinuationChanged).
    ReferenceContinuationChanged,
    /// Reference diagnostic storage size. [Detection, owner and recovery](#cause-ReferenceDiagnosticStorageSize).
    ReferenceDiagnosticStorageSize,
    /// Reference fingerprint phase. [Detection, owner and recovery](#cause-ReferenceFingerprintPhase).
    ReferenceFingerprintPhase,
    /// Reference fingerprint selection. [Detection, owner and recovery](#cause-ReferenceFingerprintSelection).
    ReferenceFingerprintSelection,
    /// Reference incomplete. [Detection, owner and recovery](#cause-ReferenceIncomplete).
    ReferenceIncomplete,
    /// Reference metadata allocation. [Detection, owner and recovery](#cause-ReferenceMetadataAllocation).
    ReferenceMetadataAllocation,
    /// Reference metadata phase. [Detection, owner and recovery](#cause-ReferenceMetadataPhase).
    ReferenceMetadataPhase,
    /// Reference metadata size. [Detection, owner and recovery](#cause-ReferenceMetadataSize).
    ReferenceMetadataSize,
    /// Reference observation requires prepared owner. [Detection, owner and recovery](#cause-ReferenceObservationRequiresPreparedOwner).
    ReferenceObservationRequiresPreparedOwner,
    /// Reference observation stopped. [Detection, owner and recovery](#cause-ReferenceObservationStopped).
    ReferenceObservationStopped,
    /// Reference owner absent. [Detection, owner and recovery](#cause-ReferenceOwnerAbsent).
    ReferenceOwnerAbsent,
    /// Reference possession absent. [Detection, owner and recovery](#cause-ReferencePossessionAbsent).
    ReferencePossessionAbsent,
    /// Reference preparation already bound. [Detection, owner and recovery](#cause-ReferencePreparationAlreadyBound).
    ReferencePreparationAlreadyBound,
    /// Reference preparation already consumed. [Detection, owner and recovery](#cause-ReferencePreparationAlreadyConsumed).
    ReferencePreparationAlreadyConsumed,
    /// Reference preparation invalidated. [Detection, owner and recovery](#cause-ReferencePreparationInvalidated).
    ReferencePreparationInvalidated,
    /// Reference resource need absent. [Detection, owner and recovery](#cause-ReferenceResourceNeedAbsent).
    ReferenceResourceNeedAbsent,
    /// Reference search phase. [Detection, owner and recovery](#cause-ReferenceSearchPhase).
    ReferenceSearchPhase,
    /// Reference search preparation absent. [Detection, owner and recovery](#cause-ReferenceSearchPreparationAbsent).
    ReferenceSearchPreparationAbsent,
    /// Reference snapshot length. [Detection, owner and recovery](#cause-ReferenceSnapshotLength).
    ReferenceSnapshotLength,
    /// Reference source changed. [Detection, owner and recovery](#cause-ReferenceSourceChanged).
    ReferenceSourceChanged,
    /// Reference storage size. [Detection, owner and recovery](#cause-ReferenceStorageSize).
    ReferenceStorageSize,
    /// Revocation preparation already consumed. [Detection, owner and recovery](#cause-RevocationPreparationAlreadyConsumed).
    RevocationPreparationAlreadyConsumed,
    /// Revocation reference allocation. [Detection, owner and recovery](#cause-RevocationReferenceAllocation).
    RevocationReferenceAllocation,
    /// Revocation reference storage accounting. [Detection, owner and recovery](#cause-RevocationReferenceStorageAccounting).
    RevocationReferenceStorageAccounting,
    /// Revocation retention accounting. [Detection, owner and recovery](#cause-RevocationRetentionAccounting).
    RevocationRetentionAccounting,
    /// Revocation retention allocation. [Detection, owner and recovery](#cause-RevocationRetentionAllocation).
    RevocationRetentionAllocation,
    /// Revocation retention already consumed. [Detection, owner and recovery](#cause-RevocationRetentionAlreadyConsumed).
    RevocationRetentionAlreadyConsumed,
    /// Revocation set storage accounting. [Detection, owner and recovery](#cause-RevocationSetStorageAccounting).
    RevocationSetStorageAccounting,
    /// Second RSA search preparation absent. [Detection, owner and recovery](#cause-SecondRsaSearchPreparationAbsent).
    SecondRsaSearchPreparationAbsent,
    /// Second RSA selection phase. [Detection, owner and recovery](#cause-SecondRsaSelectionPhase).
    SecondRsaSelectionPhase,
    /// Second selection preparation absent. [Detection, owner and recovery](#cause-SecondSelectionPreparationAbsent).
    SecondSelectionPreparationAbsent,
    /// Selection is not a storage request. [Detection, owner and recovery](#cause-SelectionIsNotAStorageRequest).
    SelectionIsNotAStorageRequest,
    /// Signing evidence absent. [Detection, owner and recovery](#cause-SigningEvidenceAbsent).
    SigningEvidenceAbsent,
    /// Signing reference preparation absent. [Detection, owner and recovery](#cause-SigningReferencePreparationAbsent).
    SigningReferencePreparationAbsent,
    /// Signing reference quota transferred. [Detection, owner and recovery](#cause-SigningReferenceQuotaTransferred).
    SigningReferenceQuotaTransferred,
    /// Unselected reference content. [Detection, owner and recovery](#cause-UnselectedReferenceContent).
    UnselectedReferenceContent,


}

impl std::fmt::Display for ObjectReferencesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::CGetObjectSizeUnavailable => f.write_str("C_GetObjectSize unavailable"),
            Self::RsaObservedPublicationAbsent => f.write_str("RSA observed publication absent"),
            Self::RsaPrivateEvidenceAbsent => f.write_str("RSA private evidence absent"),
            Self::RsaReadmissionStorageSize => f.write_str("RSA readmission storage size"),
            Self::RsaReferencePreparationAbsent => f.write_str("RSA reference preparation absent"),
            Self::RsaReferenceQuotaTransferred => f.write_str("RSA reference quota transferred"),
            Self::DestinationAggregateAccounting => f.write_str("destination aggregate accounting"),
            Self::DestructionAlreadyDispatched => f.write_str("destruction already dispatched"),
            Self::DestructionDiagnosticAlreadyConsumed => {
                f.write_str("destruction diagnostic already consumed")
            }
            Self::DestructionObservationAbsent => f.write_str("destruction observation absent"),
            Self::DestructionOwnerAbsent => f.write_str("destruction owner absent"),
            Self::DestructionPossessionAbsent => f.write_str("destruction possession absent"),
            Self::DestructionPreparationAccounting => {
                f.write_str("destruction preparation accounting")
            }
            Self::DestructionResourceNeedAbsent => f.write_str("destruction resource need absent"),
            Self::DestructionStorageSize => f.write_str("destruction storage size"),
            Self::DiscoveryActivityAlreadyBound => f.write_str("discovery activity already bound"),
            Self::DiscoveryIdentityAlreadyShared => {
                f.write_str("discovery identity already shared")
            }
            Self::DiscoveryIdentityMismatch => f.write_str("discovery identity mismatch"),
            Self::ForeignDestructionResource => f.write_str("foreign destruction resource"),
            Self::ForeignNativeObject => f.write_str("foreign native object"),
            Self::ForeignOrStaleManagedObject => f.write_str("foreign or stale managed object"),
            Self::ForeignOrStaleNativeObject => f.write_str("foreign or stale native object"),
            Self::InvalidAdmittedHandle => f.write_str("invalid admitted handle"),
            Self::InvalidReturnedNativeHandle => f.write_str("invalid returned native handle"),
            Self::InventorySortCapacity => f.write_str("inventory sort capacity"),
            Self::KeyEvidencePreparationAbsent => f.write_str("key evidence preparation absent"),
            Self::KeyPublicationAbsent => f.write_str("key publication absent"),
            Self::KeyReadmissionCandidateKind => f.write_str("key readmission candidate kind"),
            Self::KeyReadmissionCompletionPhase => f.write_str("key readmission completion phase"),
            Self::KeyReadmissionContinuationChanged => {
                f.write_str("key readmission continuation changed")
            }
            Self::KeyReadmissionIncomplete => f.write_str("key readmission incomplete"),
            Self::KeyReadmissionNeedAbsent => f.write_str("key readmission need absent"),
            Self::KeyReadmissionOwnerAbsent => f.write_str("key readmission owner absent"),
            Self::KeyReadmissionPossessionAbsent => {
                f.write_str("key readmission possession absent")
            }
            Self::KeyReadmissionStopped => f.write_str("key readmission stopped"),
            Self::KeyReadmissionStorageSize => f.write_str("key readmission storage size"),
            Self::KeyReferencePreparationAbsent => f.write_str("key reference preparation absent"),
            Self::KeyReferenceQuotaTransferred => f.write_str("key reference quota transferred"),
            Self::KeyTypeWidth => f.write_str("key type width"),
            Self::NativeCreationAlreadyPublished => {
                f.write_str("native creation already published")
            }
            Self::NativeCreationNotPublished => f.write_str("native creation not published"),
            Self::NativeIdentityActivityAlreadyBound => {
                f.write_str("native identity activity already bound")
            }
            Self::NativeIdentityNotPublished => f.write_str("native identity not published"),
            Self::NativeIdentityPreparationAlreadyShared => {
                f.write_str("native identity preparation already shared")
            }
            Self::NativeIdentityPreparationMismatch => {
                f.write_str("native identity preparation mismatch")
            }
            Self::ObjectObservationLifetimeChanged => {
                f.write_str("object observation lifetime changed")
            }
            Self::ObjectSizeAggregateAccountingOverflow => {
                f.write_str("object size aggregate accounting overflow")
            }
            Self::ObjectSizeMetadataAccountingOverflow => {
                f.write_str("object size metadata accounting overflow")
            }
            Self::ObservationNativeHandleChanged => {
                f.write_str("observation native handle changed")
            }
            Self::PublicFingerprintCandidateKind => {
                f.write_str("public fingerprint candidate kind")
            }
            Self::PublicFingerprintCompletionPhase => {
                f.write_str("public fingerprint completion phase")
            }
            Self::PublicFingerprintContentPhase => f.write_str("public fingerprint content phase"),
            Self::PublicFingerprintContinuationChanged => {
                f.write_str("public fingerprint continuation changed")
            }
            Self::PublicFingerprintIncomplete => f.write_str("public fingerprint incomplete"),
            Self::PublicFingerprintNeedAbsent => f.write_str("public fingerprint need absent"),
            Self::PublicFingerprintOwnerAbsent => f.write_str("public fingerprint owner absent"),
            Self::PublicFingerprintPossessionAbsent => {
                f.write_str("public fingerprint possession absent")
            }
            Self::PublicFingerprintSearchPhase => f.write_str("public fingerprint search phase"),
            Self::PublicFingerprintStopped => f.write_str("public fingerprint stopped"),
            Self::PublicFingerprintStorageSize => f.write_str("public fingerprint storage size"),
            Self::PublicKeyEvidenceAbsent => f.write_str("public-key evidence absent"),
            Self::ReadmissionSelectionAbsent => f.write_str("readmission selection absent"),
            Self::ReferenceCandidateKind => f.write_str("reference candidate kind"),
            Self::ReferenceCardinalityWidth => f.write_str("reference cardinality width"),
            Self::ReferenceCompletionPhase => f.write_str("reference completion phase"),
            Self::ReferenceContentPhase => f.write_str("reference content phase"),
            Self::ReferenceContinuationChanged => f.write_str("reference continuation changed"),
            Self::ReferenceDiagnosticStorageSize => {
                f.write_str("reference diagnostic storage size")
            }
            Self::ReferenceFingerprintPhase => f.write_str("reference fingerprint phase"),
            Self::ReferenceFingerprintSelection => f.write_str("reference fingerprint selection"),
            Self::ReferenceIncomplete => f.write_str("reference incomplete"),
            Self::ReferenceMetadataAllocation => f.write_str("reference metadata allocation"),
            Self::ReferenceMetadataPhase => f.write_str("reference metadata phase"),
            Self::ReferenceMetadataSize => f.write_str("reference metadata size"),
            Self::ReferenceObservationRequiresPreparedOwner => {
                f.write_str("reference observation requires prepared owner")
            }
            Self::ReferenceObservationStopped => f.write_str("reference observation stopped"),
            Self::ReferenceOwnerAbsent => f.write_str("reference owner absent"),
            Self::ReferencePossessionAbsent => f.write_str("reference possession absent"),
            Self::ReferencePreparationAlreadyBound => {
                f.write_str("reference preparation already bound")
            }
            Self::ReferencePreparationAlreadyConsumed => {
                f.write_str("reference preparation already consumed")
            }
            Self::ReferencePreparationInvalidated => {
                f.write_str("reference preparation invalidated")
            }
            Self::ReferenceResourceNeedAbsent => f.write_str("reference resource need absent"),
            Self::ReferenceSearchPhase => f.write_str("reference search phase"),
            Self::ReferenceSearchPreparationAbsent => {
                f.write_str("reference search preparation absent")
            }
            Self::ReferenceSnapshotLength => f.write_str("reference snapshot length"),
            Self::ReferenceSourceChanged => f.write_str("reference source changed"),
            Self::ReferenceStorageSize => f.write_str("reference storage size"),
            Self::RevocationPreparationAlreadyConsumed => {
                f.write_str("revocation preparation already consumed")
            }
            Self::RevocationReferenceAllocation => f.write_str("revocation reference allocation"),
            Self::RevocationReferenceStorageAccounting => {
                f.write_str("revocation reference storage accounting")
            }
            Self::RevocationRetentionAccounting => f.write_str("revocation retention accounting"),
            Self::RevocationRetentionAllocation => f.write_str("revocation retention allocation"),
            Self::RevocationRetentionAlreadyConsumed => {
                f.write_str("revocation retention already consumed")
            }
            Self::RevocationSetStorageAccounting => {
                f.write_str("revocation set storage accounting")
            }
            Self::SecondRsaSearchPreparationAbsent => {
                f.write_str("second RSA search preparation absent")
            }
            Self::SecondRsaSelectionPhase => f.write_str("second RSA selection phase"),
            Self::SecondSelectionPreparationAbsent => {
                f.write_str("second selection preparation absent")
            }
            Self::SelectionIsNotAStorageRequest => {
                f.write_str("selection is not a storage request")
            }
            Self::SigningEvidenceAbsent => f.write_str("signing evidence absent"),
            Self::SigningReferencePreparationAbsent => {
                f.write_str("signing reference preparation absent")
            }
            Self::SigningReferenceQuotaTransferred => {
                f.write_str("signing reference quota transferred")
            }
            Self::UnselectedReferenceContent => f.write_str("unselected reference content"),
        }
    }
}
