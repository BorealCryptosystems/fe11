// SPDX-License-Identifier: Apache-2.0
//! KeyDerivation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to key derivation.
#[doc = include_str!("../../../docs/diagnostics/rejection-key_derivation.md")]
pub enum KeyDerivationRejection {
    /// ECDH KDF identifier width. [Detection, owner and recovery](#cause-EcdhKdfIdentifierWidth).
    EcdhKdfIdentifierWidth,
    /// HKDF derivation path required. [Detection, owner and recovery](#cause-HkdfDerivationPathRequired).
    HkdfDerivationPathRequired,
    /// HKDF hash identifier width. [Detection, owner and recovery](#cause-HkdfHashIdentifierWidth).
    HkdfHashIdentifierWidth,
    /// HKDF salt owner unavailable. [Detection, owner and recovery](#cause-HkdfSaltOwnerUnavailable).
    HkdfSaltOwnerUnavailable,
    /// HKDF salt reference unavailable. [Detection, owner and recovery](#cause-HkdfSaltReferenceUnavailable).
    HkdfSaltReferenceUnavailable,
    /// KEM output evidence family mismatch. [Detection, owner and recovery](#cause-KemOutputEvidenceFamilyMismatch).
    KemOutputEvidenceFamilyMismatch,
    /// ML-KEM shared secret length is 32 bytes. [Detection, owner and recovery](#cause-MlKemSharedSecretLengthIs32Bytes).
    MlKemSharedSecretLengthIs32Bytes,
    /// Montgomery SPKI DER. [Detection, owner and recovery](#cause-MontgomerySpkiDer).
    MontgomerySpkiDer,
    /// Montgomery SPKI algorithm. [Detection, owner and recovery](#cause-MontgomerySpkiAlgorithm).
    MontgomerySpkiAlgorithm,
    /// Montgomery SPKI encoding. [Detection, owner and recovery](#cause-MontgomerySpkiEncoding).
    MontgomerySpkiEncoding,
    /// Montgomery SPKI noncanonical. [Detection, owner and recovery](#cause-MontgomerySpkiNoncanonical).
    MontgomerySpkiNoncanonical,
    /// Montgomery SPKI parameters must be absent. [Detection, owner and recovery](#cause-MontgomerySpkiParametersMustBeAbsent).
    MontgomerySpkiParametersMustBeAbsent,
    /// Montgomery SPKI unused bits. [Detection, owner and recovery](#cause-MontgomerySpkiUnusedBits).
    MontgomerySpkiUnusedBits,
    /// Montgomery agreement domain mismatch. [Detection, owner and recovery](#cause-MontgomeryAgreementDomainMismatch).
    MontgomeryAgreementDomainMismatch,
    /// Montgomery generation result owner mismatch. [Detection, owner and recovery](#cause-MontgomeryGenerationResultOwnerMismatch).
    MontgomeryGenerationResultOwnerMismatch,
    /// Montgomery public allocation. [Detection, owner and recovery](#cause-MontgomeryPublicAllocation).
    MontgomeryPublicAllocation,
    /// Montgomery public bit string. [Detection, owner and recovery](#cause-MontgomeryPublicBitString).
    MontgomeryPublicBitString,
    /// Montgomery public coordinate width. [Detection, owner and recovery](#cause-MontgomeryPublicCoordinateWidth).
    MontgomeryPublicCoordinateWidth,
    /// OAEP requires a secret-key destination. [Detection, owner and recovery](#cause-OaepRequiresASecretKeyDestination).
    OaepRequiresASecretKeyDestination,
    /// RFC7748 named domain has no implicit RFC8410 conversion. [Detection, owner and recovery](#cause-Rfc7748NamedDomainHasNoImplicitRfc8410Conversion).
    Rfc7748NamedDomainHasNoImplicitRfc8410Conversion,
    /// Weierstrass generation result owner mismatch. [Detection, owner and recovery](#cause-WeierstrassGenerationResultOwnerMismatch).
    WeierstrassGenerationResultOwnerMismatch,
    /// Agreement OID. [Detection, owner and recovery](#cause-AgreementOid).
    AgreementOid,
    /// Agreement SPKI encoding. [Detection, owner and recovery](#cause-AgreementSpkiEncoding).
    AgreementSpkiEncoding,
    /// Agreement curve mismatch. [Detection, owner and recovery](#cause-AgreementCurveMismatch).
    AgreementCurveMismatch,
    /// Agreement history already observed. [Detection, owner and recovery](#cause-AgreementHistoryAlreadyObserved).
    AgreementHistoryAlreadyObserved,
    /// Agreement history observation absent. [Detection, owner and recovery](#cause-AgreementHistoryObservationAbsent).
    AgreementHistoryObservationAbsent,
    /// Agreement native domain. [Detection, owner and recovery](#cause-AgreementNativeDomain).
    AgreementNativeDomain,
    /// Agreement native point DER. [Detection, owner and recovery](#cause-AgreementNativePointDer).
    AgreementNativePointDer,
    /// Agreement owner size. [Detection, owner and recovery](#cause-AgreementOwnerSize).
    AgreementOwnerSize,
    /// Agreement peer domain. [Detection, owner and recovery](#cause-AgreementPeerDomain).
    AgreementPeerDomain,
    /// Agreement point bit string. [Detection, owner and recovery](#cause-AgreementPointBitString).
    AgreementPointBitString,
    /// Agreement point encoding. [Detection, owner and recovery](#cause-AgreementPointEncoding).
    AgreementPointEncoding,
    /// Agreement point noncanonical. [Detection, owner and recovery](#cause-AgreementPointNoncanonical).
    AgreementPointNoncanonical,
    /// Agreement private family. [Detection, owner and recovery](#cause-AgreementPrivateFamily).
    AgreementPrivateFamily,
    /// Agreement public allocation. [Detection, owner and recovery](#cause-AgreementPublicAllocation).
    AgreementPublicAllocation,
    /// Agreement public identity already observed. [Detection, owner and recovery](#cause-AgreementPublicIdentityAlreadyObserved).
    AgreementPublicIdentityAlreadyObserved,
    /// Agreement public material requires identity. [Detection, owner and recovery](#cause-AgreementPublicMaterialRequiresIdentity).
    AgreementPublicMaterialRequiresIdentity,
    /// Agreement public observation incomplete. [Detection, owner and recovery](#cause-AgreementPublicObservationIncomplete).
    AgreementPublicObservationIncomplete,
    /// Agreement public size. [Detection, owner and recovery](#cause-AgreementPublicSize).
    AgreementPublicSize,
    /// Agreement public storage family. [Detection, owner and recovery](#cause-AgreementPublicStorageFamily).
    AgreementPublicStorageFamily,
    /// Agreement publication family mismatch. [Detection, owner and recovery](#cause-AgreementPublicationFamilyMismatch).
    AgreementPublicationFamilyMismatch,
    /// Agreement request already published. [Detection, owner and recovery](#cause-AgreementRequestAlreadyPublished).
    AgreementRequestAlreadyPublished,
    /// Agreement request size. [Detection, owner and recovery](#cause-AgreementRequestSize).
    AgreementRequestSize,
    /// Derivation base already published. [Detection, owner and recovery](#cause-DerivationBaseAlreadyPublished).
    DerivationBaseAlreadyPublished,
    /// Derivation base history already observed. [Detection, owner and recovery](#cause-DerivationBaseHistoryAlreadyObserved).
    DerivationBaseHistoryAlreadyObserved,
    /// Derivation base history observation absent. [Detection, owner and recovery](#cause-DerivationBaseHistoryObservationAbsent).
    DerivationBaseHistoryObservationAbsent,
    /// Derivation base integer encoding. [Detection, owner and recovery](#cause-DerivationBaseIntegerEncoding).
    DerivationBaseIntegerEncoding,
    /// Derivation base owner size. [Detection, owner and recovery](#cause-DerivationBaseOwnerSize).
    DerivationBaseOwnerSize,
    /// Derivation base publication report mismatch. [Detection, owner and recovery](#cause-DerivationBasePublicationReportMismatch).
    DerivationBasePublicationReportMismatch,
    /// Derivation base request size. [Detection, owner and recovery](#cause-DerivationBaseRequestSize).
    DerivationBaseRequestSize,
    /// Derivation base requested identity mismatch. [Detection, owner and recovery](#cause-DerivationBaseRequestedIdentityMismatch).
    DerivationBaseRequestedIdentityMismatch,
    /// Derivation call absent. [Detection, owner and recovery](#cause-DerivationCallAbsent).
    DerivationCallAbsent,
    /// Derivation candidate kind. [Detection, owner and recovery](#cause-DerivationCandidateKind).
    DerivationCandidateKind,
    /// Derivation completion phase. [Detection, owner and recovery](#cause-DerivationCompletionPhase).
    DerivationCompletionPhase,
    /// Derivation completion unknown. [Detection, owner and recovery](#cause-DerivationCompletionUnknown).
    DerivationCompletionUnknown,
    /// Derivation continuation changed. [Detection, owner and recovery](#cause-DerivationContinuationChanged).
    DerivationContinuationChanged,
    /// Derivation destination absent. [Detection, owner and recovery](#cause-DerivationDestinationAbsent).
    DerivationDestinationAbsent,
    /// Derivation destination phase. [Detection, owner and recovery](#cause-DerivationDestinationPhase).
    DerivationDestinationPhase,
    /// Derivation dispatch phase. [Detection, owner and recovery](#cause-DerivationDispatchPhase).
    DerivationDispatchPhase,
    /// Derivation graph overflow. [Detection, owner and recovery](#cause-DerivationGraphOverflow).
    DerivationGraphOverflow,
    /// Derivation incomplete. [Detection, owner and recovery](#cause-DerivationIncomplete).
    DerivationIncomplete,
    /// Derivation is not a resource request. [Detection, owner and recovery](#cause-DerivationIsNotAResourceRequest).
    DerivationIsNotAResourceRequest,
    /// Derivation native input mutation. [Detection, owner and recovery](#cause-DerivationNativeInputMutation).
    DerivationNativeInputMutation,
    /// Derivation native lifetime absent. [Detection, owner and recovery](#cause-DerivationNativeLifetimeAbsent).
    DerivationNativeLifetimeAbsent,
    /// Derivation observation attachment phase. [Detection, owner and recovery](#cause-DerivationObservationAttachmentPhase).
    DerivationObservationAttachmentPhase,
    /// Derivation observation graph size. [Detection, owner and recovery](#cause-DerivationObservationGraphSize).
    DerivationObservationGraphSize,
    /// Derivation observation incomplete. [Detection, owner and recovery](#cause-DerivationObservationIncomplete).
    DerivationObservationIncomplete,
    /// Derivation observation stopped. [Detection, owner and recovery](#cause-DerivationObservationStopped).
    DerivationObservationStopped,
    /// Derivation observation storage size. [Detection, owner and recovery](#cause-DerivationObservationStorageSize).
    DerivationObservationStorageSize,
    /// Derivation observation transition. [Detection, owner and recovery](#cause-DerivationObservationTransition).
    DerivationObservationTransition,
    /// Derivation owner absent. [Detection, owner and recovery](#cause-DerivationOwnerAbsent).
    DerivationOwnerAbsent,
    /// Derivation parameter overflow. [Detection, owner and recovery](#cause-DerivationParameterOverflow).
    DerivationParameterOverflow,
    /// Derivation possession absent. [Detection, owner and recovery](#cause-DerivationPossessionAbsent).
    DerivationPossessionAbsent,
    /// Derivation publication quota absent. [Detection, owner and recovery](#cause-DerivationPublicationQuotaAbsent).
    DerivationPublicationQuotaAbsent,
    /// Derivation resource need absent. [Detection, owner and recovery](#cause-DerivationResourceNeedAbsent).
    DerivationResourceNeedAbsent,
    /// Derivation return phase. [Detection, owner and recovery](#cause-DerivationReturnPhase).
    DerivationReturnPhase,
    /// Derivation storage recipe mismatch. [Detection, owner and recovery](#cause-DerivationStorageRecipeMismatch).
    DerivationStorageRecipeMismatch,
    /// Derive returned salt handle. [Detection, owner and recovery](#cause-DeriveReturnedSaltHandle).
    DeriveReturnedSaltHandle,
    /// Derived mechanism recipe absent. [Detection, owner and recovery](#cause-DerivedMechanismRecipeAbsent).
    DerivedMechanismRecipeAbsent,
    /// Derived object absent. [Detection, owner and recovery](#cause-DerivedObjectAbsent).
    DerivedObjectAbsent,
    /// Derived output attachment phase. [Detection, owner and recovery](#cause-DerivedOutputAttachmentPhase).
    DerivedOutputAttachmentPhase,
    /// Derived output evidence kind. [Detection, owner and recovery](#cause-DerivedOutputEvidenceKind).
    DerivedOutputEvidenceKind,
    /// Derived output incomplete. [Detection, owner and recovery](#cause-DerivedOutputIncomplete).
    DerivedOutputIncomplete,
    /// Derived output observation stopped. [Detection, owner and recovery](#cause-DerivedOutputObservationStopped).
    DerivedOutputObservationStopped,
    /// Derived output observation storage size. [Detection, owner and recovery](#cause-DerivedOutputObservationStorageSize).
    DerivedOutputObservationStorageSize,
    /// Derived output preparation absent. [Detection, owner and recovery](#cause-DerivedOutputPreparationAbsent).
    DerivedOutputPreparationAbsent,
    /// Derived output transition. [Detection, owner and recovery](#cause-DerivedOutputTransition).
    DerivedOutputTransition,
    /// Derived reference preparation absent. [Detection, owner and recovery](#cause-DerivedReferencePreparationAbsent).
    DerivedReferencePreparationAbsent,
    /// Derived reference quota transferred. [Detection, owner and recovery](#cause-DerivedReferenceQuotaTransferred).
    DerivedReferenceQuotaTransferred,
    /// Existing derivation base has no generation request. [Detection, owner and recovery](#cause-ExistingDerivationBaseHasNoGenerationRequest).
    ExistingDerivationBaseHasNoGenerationRequest,
    /// Family input plan absent. [Detection, owner and recovery](#cause-FamilyInputPlanAbsent).
    FamilyInputPlanAbsent,
    /// Family owner storage absent. [Detection, owner and recovery](#cause-FamilyOwnerStorageAbsent).
    FamilyOwnerStorageAbsent,
    /// Find_agreement_key result owner mismatch. [Detection, owner and recovery](#cause-FindAgreementKeyResultOwnerMismatch).
    FindAgreementKeyResultOwnerMismatch,
    /// Find_hkdf_key result owner mismatch. [Detection, owner and recovery](#cause-FindHkdfKeyResultOwnerMismatch).
    FindHkdfKeyResultOwnerMismatch,
    /// Find_montgomery_key result owner mismatch. [Detection, owner and recovery](#cause-FindMontgomeryKeyResultOwnerMismatch).
    FindMontgomeryKeyResultOwnerMismatch,
    /// Generate_hkdf_key result owner mismatch. [Detection, owner and recovery](#cause-GenerateHkdfKeyResultOwnerMismatch).
    GenerateHkdfKeyResultOwnerMismatch,
    /// History observation descriptor allocation. [Detection, owner and recovery](#cause-HistoryObservationDescriptorAllocation).
    HistoryObservationDescriptorAllocation,
    /// Imported agreement history report absent. [Detection, owner and recovery](#cause-ImportedAgreementHistoryReportAbsent).
    ImportedAgreementHistoryReportAbsent,
    /// Introduced agreement destination. [Detection, owner and recovery](#cause-IntroducedAgreementDestination).
    IntroducedAgreementDestination,
    /// Introduced agreement identity or domain. [Detection, owner and recovery](#cause-IntroducedAgreementIdentityOrDomain).
    IntroducedAgreementIdentityOrDomain,
    /// Introduced agreement selection result owner mismatch. [Detection, owner and recovery](#cause-IntroducedAgreementSelectionResultOwnerMismatch).
    IntroducedAgreementSelectionResultOwnerMismatch,
    /// Introduced derivation evidence kind. [Detection, owner and recovery](#cause-IntroducedDerivationEvidenceKind).
    IntroducedDerivationEvidenceKind,
    /// Introduced derivation provenance kind. [Detection, owner and recovery](#cause-IntroducedDerivationProvenanceKind).
    IntroducedDerivationProvenanceKind,
    /// Key history class. [Detection, owner and recovery](#cause-KeyHistoryClass).
    KeyHistoryClass,
    /// Ordinary derivation provenance kind. [Detection, owner and recovery](#cause-OrdinaryDerivationProvenanceKind).
    OrdinaryDerivationProvenanceKind,
    /// Parent observation preparation absent. [Detection, owner and recovery](#cause-ParentObservationPreparationAbsent).
    ParentObservationPreparationAbsent,
    /// Restored agreement history report absent. [Detection, owner and recovery](#cause-RestoredAgreementHistoryReportAbsent).
    RestoredAgreementHistoryReportAbsent,
    /// Restored agreement mechanism report absent. [Detection, owner and recovery](#cause-RestoredAgreementMechanismReportAbsent).
    RestoredAgreementMechanismReportAbsent,
    /// Single base generation requires HKDF. [Detection, owner and recovery](#cause-SingleBaseGenerationRequiresHkdf).
    SingleBaseGenerationRequiresHkdf,
    /// Transport agreement generation result owner mismatch. [Detection, owner and recovery](#cause-TransportAgreementGenerationResultOwnerMismatch).
    TransportAgreementGenerationResultOwnerMismatch,
}

impl std::fmt::Display for KeyDerivationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EcdhKdfIdentifierWidth => f.write_str("ECDH KDF identifier width"),
            Self::HkdfDerivationPathRequired => f.write_str("HKDF derivation path required"),
            Self::HkdfHashIdentifierWidth => f.write_str("HKDF hash identifier width"),
            Self::HkdfSaltOwnerUnavailable => f.write_str("HKDF salt owner unavailable"),
            Self::HkdfSaltReferenceUnavailable => f.write_str("HKDF salt reference unavailable"),
            Self::KemOutputEvidenceFamilyMismatch => {
                f.write_str("KEM output evidence family mismatch")
            }
            Self::MlKemSharedSecretLengthIs32Bytes => {
                f.write_str("ML-KEM shared secret length is 32 bytes")
            }
            Self::MontgomerySpkiDer => f.write_str("Montgomery SPKI DER"),
            Self::MontgomerySpkiAlgorithm => f.write_str("Montgomery SPKI algorithm"),
            Self::MontgomerySpkiEncoding => f.write_str("Montgomery SPKI encoding"),
            Self::MontgomerySpkiNoncanonical => f.write_str("Montgomery SPKI noncanonical"),
            Self::MontgomerySpkiParametersMustBeAbsent => {
                f.write_str("Montgomery SPKI parameters must be absent")
            }
            Self::MontgomerySpkiUnusedBits => f.write_str("Montgomery SPKI unused bits"),
            Self::MontgomeryAgreementDomainMismatch => {
                f.write_str("Montgomery agreement domain mismatch")
            }
            Self::MontgomeryGenerationResultOwnerMismatch => {
                f.write_str("Montgomery generation result owner mismatch")
            }
            Self::MontgomeryPublicAllocation => f.write_str("Montgomery public allocation"),
            Self::MontgomeryPublicBitString => f.write_str("Montgomery public bit string"),
            Self::MontgomeryPublicCoordinateWidth => {
                f.write_str("Montgomery public coordinate width")
            }
            Self::OaepRequiresASecretKeyDestination => {
                f.write_str("OAEP requires a secret-key destination")
            }
            Self::Rfc7748NamedDomainHasNoImplicitRfc8410Conversion => {
                f.write_str("RFC7748 named domain has no implicit RFC8410 conversion")
            }
            Self::WeierstrassGenerationResultOwnerMismatch => {
                f.write_str("Weierstrass generation result owner mismatch")
            }
            Self::AgreementOid => f.write_str("agreement OID"),
            Self::AgreementSpkiEncoding => f.write_str("agreement SPKI encoding"),
            Self::AgreementCurveMismatch => f.write_str("agreement curve mismatch"),
            Self::AgreementHistoryAlreadyObserved => {
                f.write_str("agreement history already observed")
            }
            Self::AgreementHistoryObservationAbsent => {
                f.write_str("agreement history observation absent")
            }
            Self::AgreementNativeDomain => f.write_str("agreement native domain"),
            Self::AgreementNativePointDer => f.write_str("agreement native point DER"),
            Self::AgreementOwnerSize => f.write_str("agreement owner size"),
            Self::AgreementPeerDomain => f.write_str("agreement peer domain"),
            Self::AgreementPointBitString => f.write_str("agreement point bit string"),
            Self::AgreementPointEncoding => f.write_str("agreement point encoding"),
            Self::AgreementPointNoncanonical => f.write_str("agreement point noncanonical"),
            Self::AgreementPrivateFamily => f.write_str("agreement private family"),
            Self::AgreementPublicAllocation => f.write_str("agreement public allocation"),
            Self::AgreementPublicIdentityAlreadyObserved => {
                f.write_str("agreement public identity already observed")
            }
            Self::AgreementPublicMaterialRequiresIdentity => {
                f.write_str("agreement public material requires identity")
            }
            Self::AgreementPublicObservationIncomplete => {
                f.write_str("agreement public observation incomplete")
            }
            Self::AgreementPublicSize => f.write_str("agreement public size"),
            Self::AgreementPublicStorageFamily => f.write_str("agreement public storage family"),
            Self::AgreementPublicationFamilyMismatch => {
                f.write_str("agreement publication family mismatch")
            }
            Self::AgreementRequestAlreadyPublished => {
                f.write_str("agreement request already published")
            }
            Self::AgreementRequestSize => f.write_str("agreement request size"),
            Self::DerivationBaseAlreadyPublished => {
                f.write_str("derivation base already published")
            }
            Self::DerivationBaseHistoryAlreadyObserved => {
                f.write_str("derivation base history already observed")
            }
            Self::DerivationBaseHistoryObservationAbsent => {
                f.write_str("derivation base history observation absent")
            }
            Self::DerivationBaseIntegerEncoding => f.write_str("derivation base integer encoding"),
            Self::DerivationBaseOwnerSize => f.write_str("derivation base owner size"),
            Self::DerivationBasePublicationReportMismatch => {
                f.write_str("derivation base publication report mismatch")
            }
            Self::DerivationBaseRequestSize => f.write_str("derivation base request size"),
            Self::DerivationBaseRequestedIdentityMismatch => {
                f.write_str("derivation base requested identity mismatch")
            }
            Self::DerivationCallAbsent => f.write_str("derivation call absent"),
            Self::DerivationCandidateKind => f.write_str("derivation candidate kind"),
            Self::DerivationCompletionPhase => f.write_str("derivation completion phase"),
            Self::DerivationCompletionUnknown => f.write_str("derivation completion unknown"),
            Self::DerivationContinuationChanged => f.write_str("derivation continuation changed"),
            Self::DerivationDestinationAbsent => f.write_str("derivation destination absent"),
            Self::DerivationDestinationPhase => f.write_str("derivation destination phase"),
            Self::DerivationDispatchPhase => f.write_str("derivation dispatch phase"),
            Self::DerivationGraphOverflow => f.write_str("derivation graph overflow"),
            Self::DerivationIncomplete => f.write_str("derivation incomplete"),
            Self::DerivationIsNotAResourceRequest => {
                f.write_str("derivation is not a resource request")
            }
            Self::DerivationNativeInputMutation => f.write_str("derivation native input mutation"),
            Self::DerivationNativeLifetimeAbsent => {
                f.write_str("derivation native lifetime absent")
            }
            Self::DerivationObservationAttachmentPhase => {
                f.write_str("derivation observation attachment phase")
            }
            Self::DerivationObservationGraphSize => {
                f.write_str("derivation observation graph size")
            }
            Self::DerivationObservationIncomplete => {
                f.write_str("derivation observation incomplete")
            }
            Self::DerivationObservationStopped => f.write_str("derivation observation stopped"),
            Self::DerivationObservationStorageSize => {
                f.write_str("derivation observation storage size")
            }
            Self::DerivationObservationTransition => {
                f.write_str("derivation observation transition")
            }
            Self::DerivationOwnerAbsent => f.write_str("derivation owner absent"),
            Self::DerivationParameterOverflow => f.write_str("derivation parameter overflow"),
            Self::DerivationPossessionAbsent => f.write_str("derivation possession absent"),
            Self::DerivationPublicationQuotaAbsent => {
                f.write_str("derivation publication quota absent")
            }
            Self::DerivationResourceNeedAbsent => f.write_str("derivation resource need absent"),
            Self::DerivationReturnPhase => f.write_str("derivation return phase"),
            Self::DerivationStorageRecipeMismatch => {
                f.write_str("derivation storage recipe mismatch")
            }
            Self::DeriveReturnedSaltHandle => f.write_str("derive returned salt handle"),
            Self::DerivedMechanismRecipeAbsent => f.write_str("derived mechanism recipe absent"),
            Self::DerivedObjectAbsent => f.write_str("derived object absent"),
            Self::DerivedOutputAttachmentPhase => f.write_str("derived output attachment phase"),
            Self::DerivedOutputEvidenceKind => f.write_str("derived output evidence kind"),
            Self::DerivedOutputIncomplete => f.write_str("derived output incomplete"),
            Self::DerivedOutputObservationStopped => {
                f.write_str("derived output observation stopped")
            }
            Self::DerivedOutputObservationStorageSize => {
                f.write_str("derived output observation storage size")
            }
            Self::DerivedOutputPreparationAbsent => {
                f.write_str("derived output preparation absent")
            }
            Self::DerivedOutputTransition => f.write_str("derived output transition"),
            Self::DerivedReferencePreparationAbsent => {
                f.write_str("derived reference preparation absent")
            }
            Self::DerivedReferenceQuotaTransferred => {
                f.write_str("derived reference quota transferred")
            }
            Self::ExistingDerivationBaseHasNoGenerationRequest => {
                f.write_str("existing derivation base has no generation request")
            }
            Self::FamilyInputPlanAbsent => f.write_str("family input plan absent"),
            Self::FamilyOwnerStorageAbsent => f.write_str("family owner storage absent"),
            Self::FindAgreementKeyResultOwnerMismatch => {
                f.write_str("find_agreement_key result owner mismatch")
            }
            Self::FindHkdfKeyResultOwnerMismatch => {
                f.write_str("find_hkdf_key result owner mismatch")
            }
            Self::FindMontgomeryKeyResultOwnerMismatch => {
                f.write_str("find_montgomery_key result owner mismatch")
            }
            Self::GenerateHkdfKeyResultOwnerMismatch => {
                f.write_str("generate_hkdf_key result owner mismatch")
            }
            Self::HistoryObservationDescriptorAllocation => {
                f.write_str("history observation descriptor allocation")
            }
            Self::ImportedAgreementHistoryReportAbsent => {
                f.write_str("imported agreement history report absent")
            }
            Self::IntroducedAgreementDestination => f.write_str("introduced agreement destination"),
            Self::IntroducedAgreementIdentityOrDomain => {
                f.write_str("introduced agreement identity or domain")
            }
            Self::IntroducedAgreementSelectionResultOwnerMismatch => {
                f.write_str("introduced agreement selection result owner mismatch")
            }
            Self::IntroducedDerivationEvidenceKind => {
                f.write_str("introduced derivation evidence kind")
            }
            Self::IntroducedDerivationProvenanceKind => {
                f.write_str("introduced derivation provenance kind")
            }
            Self::KeyHistoryClass => f.write_str("key history class"),
            Self::OrdinaryDerivationProvenanceKind => {
                f.write_str("ordinary derivation provenance kind")
            }
            Self::ParentObservationPreparationAbsent => {
                f.write_str("parent observation preparation absent")
            }
            Self::RestoredAgreementHistoryReportAbsent => {
                f.write_str("restored agreement history report absent")
            }
            Self::RestoredAgreementMechanismReportAbsent => {
                f.write_str("restored agreement mechanism report absent")
            }
            Self::SingleBaseGenerationRequiresHkdf => {
                f.write_str("single base generation requires HKDF")
            }
            Self::TransportAgreementGenerationResultOwnerMismatch => {
                f.write_str("transport agreement generation result owner mismatch")
            }
        }
    }
}
