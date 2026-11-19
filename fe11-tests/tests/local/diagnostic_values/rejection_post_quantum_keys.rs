// SPDX-License-Identifier: Apache-2.0
//! Public PostQuantumKeysRejection values retain identity through category conversion.
use fe11::{Error, PostQuantumKeysRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        PostQuantumKeysRejection::CVerifySignatureUnavailable,
        PostQuantumKeysRejection::CVerifySignatureFinalUnavailable,
        PostQuantumKeysRejection::CVerifySignatureInitUnavailable,
        PostQuantumKeysRejection::CVerifySignatureUpdateUnavailable,
        PostQuantumKeysRejection::MlDsaImportedKeyFamily,
        PostQuantumKeysRejection::PqcVerifysignatureCompletionUnproven,
        PostQuantumKeysRejection::PqcVerifysignatureInputChanged,
        PostQuantumKeysRejection::PqcContextLength,
        PostQuantumKeysRejection::PqcExportAccessOwner,
        PostQuantumKeysRejection::PqcExportCandidateKind,
        PostQuantumKeysRejection::PqcExportCompletionPhase,
        PostQuantumKeysRejection::PqcExportContinuationChanged,
        PostQuantumKeysRejection::PqcExportIdentityPreparationAbsent,
        PostQuantumKeysRejection::PqcExportIncomplete,
        PostQuantumKeysRejection::PqcExportMetadataPhase,
        PostQuantumKeysRejection::PqcExportMetadataSize,
        PostQuantumKeysRejection::PqcExportOwnerAbsent,
        PostQuantumKeysRejection::PqcExportPossessionAbsent,
        PostQuantumKeysRejection::PqcExportRequiresPrivateKey,
        PostQuantumKeysRejection::PqcExportResourceNeedAbsent,
        PostQuantumKeysRejection::PqcExportStopped,
        PostQuantumKeysRejection::PqcExportStorageSize,
        PostQuantumKeysRejection::PqcImportPublicLength,
        PostQuantumKeysRejection::PqcImportSeedLength,
        PostQuantumKeysRejection::PqcImportValueLength,
        PostQuantumKeysRejection::PqcInputPreparationChanged,
        PostQuantumKeysRejection::PqcMessageCeiling,
        PostQuantumKeysRejection::PqcNativeFrameAccounting,
        PostQuantumKeysRejection::PqcNativeParameterStorage,
        PostQuantumKeysRejection::PqcNativeSignatureLength,
        PostQuantumKeysRejection::PqcNativeSignatureWidth,
        PostQuantumKeysRejection::PqcNativeStorageSize,
        PostQuantumKeysRejection::PqcPairObservationBudget,
        PostQuantumKeysRejection::PqcPairOwnerSize,
        PostQuantumKeysRejection::PqcPairSourceStorage,
        PostQuantumKeysRejection::PqcPrehashLength,
        PostQuantumKeysRejection::PqcPrivateAttributeDescriptorOrLength,
        PostQuantumKeysRejection::PqcPrivateDescriptorOrCapacityChanged,
        PostQuantumKeysRejection::PqcPrivateIdentityChangedDuringExport,
        PostQuantumKeysRejection::PqcPrivateIdentityEncoding,
        PostQuantumKeysRejection::PqcPublicSpkiDer,
        PostQuantumKeysRejection::PqcPublicSpkiBound,
        PostQuantumKeysRejection::PqcPublicAlgorithm,
        PostQuantumKeysRejection::PqcPublicAllocation,
        PostQuantumKeysRejection::PqcPublicBitString,
        PostQuantumKeysRejection::PqcPublicContextAllocation,
        PostQuantumKeysRejection::PqcPublicContextBound,
        PostQuantumKeysRejection::PqcPublicEncoding,
        PostQuantumKeysRejection::PqcPublicIdentityAlreadyObserved,
        PostQuantumKeysRejection::PqcPublicKeyLength,
        PostQuantumKeysRejection::PqcPublicNoncanonicalDer,
        PostQuantumKeysRejection::PqcPublicObservationIncomplete,
        PostQuantumKeysRejection::PqcPublicParametersMustBeAbsent,
        PostQuantumKeysRejection::PqcPublicPrehashFramingAllocation,
        PostQuantumKeysRejection::PqcPublicPrehashFramingBounds,
        PostQuantumKeysRejection::PqcPublicUnusedBits,
        PostQuantumKeysRejection::PqcPublicVerificationBounds,
        PostQuantumKeysRejection::PqcSelectionIdAllocation,
        PostQuantumKeysRejection::PqcSignatureAlgorithmMismatch,
        PostQuantumKeysRejection::PqcSignatureCompletionUnproven,
        PostQuantumKeysRejection::PqcSignatureInputChanged,
        PostQuantumKeysRejection::PqcSignatureLength,
        PostQuantumKeysRejection::PqcSignatureParametersChanged,
        PostQuantumKeysRejection::PqcSignatureParametersChangedDuringContextAuthentication,
        PostQuantumKeysRejection::PqcValueRequiresPublicIdentity,
        PostQuantumKeysRejection::PqcVerificationCompletionUnproven,
        PostQuantumKeysRejection::PqcVerificationInputChanged,
        PostQuantumKeysRejection::PqcVerificationParametersChanged,
        PostQuantumKeysRejection::ExistingPqcPairHasNoCreationTemplates,
        PostQuantumKeysRejection::ExistingPqcPairHasNoGenerationRequest,
        PostQuantumKeysRejection::SinglePartPqcSignatureRequiresOneInput,
        PostQuantumKeysRejection::SinglePartPqcVerificationRequiresOneInput,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::PostQuantumKeys(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::PostQuantumKeys(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
