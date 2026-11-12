// SPDX-License-Identifier: Apache-2.0
//! PostQuantumKeys causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to post quantum keys.
#[doc = include_str!("../../../docs/diagnostics/rejection-post_quantum_keys.md")]
pub enum PostQuantumKeysRejection {
    /// C_VerifySignature unavailable. [Detection, owner and recovery](#cause-CVerifySignatureUnavailable).
    CVerifySignatureUnavailable,
    /// C_VerifySignatureFinal unavailable. [Detection, owner and recovery](#cause-CVerifySignatureFinalUnavailable).
    CVerifySignatureFinalUnavailable,
    /// C_VerifySignatureInit unavailable. [Detection, owner and recovery](#cause-CVerifySignatureInitUnavailable).
    CVerifySignatureInitUnavailable,
    /// C_VerifySignatureUpdate unavailable. [Detection, owner and recovery](#cause-CVerifySignatureUpdateUnavailable).
    CVerifySignatureUpdateUnavailable,
    /// ML-DSA imported key family. [Detection, owner and recovery](#cause-MlDsaImportedKeyFamily).
    MlDsaImportedKeyFamily,
    /// PQC VerifySignature completion unproven. [Detection, owner and recovery](#cause-PqcVerifysignatureCompletionUnproven).
    PqcVerifysignatureCompletionUnproven,
    /// PQC VerifySignature input changed. [Detection, owner and recovery](#cause-PqcVerifysignatureInputChanged).
    PqcVerifysignatureInputChanged,
    /// PQC context length. [Detection, owner and recovery](#cause-PqcContextLength).
    PqcContextLength,
    /// PQC export access owner. [Detection, owner and recovery](#cause-PqcExportAccessOwner).
    PqcExportAccessOwner,
    /// PQC export candidate kind. [Detection, owner and recovery](#cause-PqcExportCandidateKind).
    PqcExportCandidateKind,
    /// PQC export completion phase. [Detection, owner and recovery](#cause-PqcExportCompletionPhase).
    PqcExportCompletionPhase,
    /// PQC export continuation changed. [Detection, owner and recovery](#cause-PqcExportContinuationChanged).
    PqcExportContinuationChanged,
    /// PQC export identity preparation absent. [Detection, owner and recovery](#cause-PqcExportIdentityPreparationAbsent).
    PqcExportIdentityPreparationAbsent,
    /// PQC export incomplete. [Detection, owner and recovery](#cause-PqcExportIncomplete).
    PqcExportIncomplete,
    /// PQC export metadata phase. [Detection, owner and recovery](#cause-PqcExportMetadataPhase).
    PqcExportMetadataPhase,
    /// PQC export metadata size. [Detection, owner and recovery](#cause-PqcExportMetadataSize).
    PqcExportMetadataSize,
    /// PQC export owner absent. [Detection, owner and recovery](#cause-PqcExportOwnerAbsent).
    PqcExportOwnerAbsent,
    /// PQC export possession absent. [Detection, owner and recovery](#cause-PqcExportPossessionAbsent).
    PqcExportPossessionAbsent,
    /// PQC export requires private key. [Detection, owner and recovery](#cause-PqcExportRequiresPrivateKey).
    PqcExportRequiresPrivateKey,
    /// PQC export resource need absent. [Detection, owner and recovery](#cause-PqcExportResourceNeedAbsent).
    PqcExportResourceNeedAbsent,
    /// PQC export stopped. [Detection, owner and recovery](#cause-PqcExportStopped).
    PqcExportStopped,
    /// PQC export storage size. [Detection, owner and recovery](#cause-PqcExportStorageSize).
    PqcExportStorageSize,
    /// PQC import public length. [Detection, owner and recovery](#cause-PqcImportPublicLength).
    PqcImportPublicLength,
    /// PQC import seed length. [Detection, owner and recovery](#cause-PqcImportSeedLength).
    PqcImportSeedLength,
    /// PQC import value length. [Detection, owner and recovery](#cause-PqcImportValueLength).
    PqcImportValueLength,
    /// PQC input preparation changed. [Detection, owner and recovery](#cause-PqcInputPreparationChanged).
    PqcInputPreparationChanged,
    /// PQC message ceiling. [Detection, owner and recovery](#cause-PqcMessageCeiling).
    PqcMessageCeiling,
    /// PQC native frame accounting. [Detection, owner and recovery](#cause-PqcNativeFrameAccounting).
    PqcNativeFrameAccounting,
    /// PQC native parameter storage. [Detection, owner and recovery](#cause-PqcNativeParameterStorage).
    PqcNativeParameterStorage,
    /// PQC native signature length. [Detection, owner and recovery](#cause-PqcNativeSignatureLength).
    PqcNativeSignatureLength,
    /// PQC native signature width. [Detection, owner and recovery](#cause-PqcNativeSignatureWidth).
    PqcNativeSignatureWidth,
    /// PQC native storage size. [Detection, owner and recovery](#cause-PqcNativeStorageSize).
    PqcNativeStorageSize,
    /// PQC pair observation budget. [Detection, owner and recovery](#cause-PqcPairObservationBudget).
    PqcPairObservationBudget,
    /// PQC pair owner size. [Detection, owner and recovery](#cause-PqcPairOwnerSize).
    PqcPairOwnerSize,
    /// PQC pair source storage. [Detection, owner and recovery](#cause-PqcPairSourceStorage).
    PqcPairSourceStorage,
    /// PQC prehash length. [Detection, owner and recovery](#cause-PqcPrehashLength).
    PqcPrehashLength,
    /// PQC private attribute descriptor or length. [Detection, owner and recovery](#cause-PqcPrivateAttributeDescriptorOrLength).
    PqcPrivateAttributeDescriptorOrLength,
    /// PQC private descriptor or capacity changed. [Detection, owner and recovery](#cause-PqcPrivateDescriptorOrCapacityChanged).
    PqcPrivateDescriptorOrCapacityChanged,
    /// PQC private identity changed during export. [Detection, owner and recovery](#cause-PqcPrivateIdentityChangedDuringExport).
    PqcPrivateIdentityChangedDuringExport,
    /// PQC private identity encoding. [Detection, owner and recovery](#cause-PqcPrivateIdentityEncoding).
    PqcPrivateIdentityEncoding,
    /// PQC public SPKI DER. [Detection, owner and recovery](#cause-PqcPublicSpkiDer).
    PqcPublicSpkiDer,
    /// PQC public SPKI bound. [Detection, owner and recovery](#cause-PqcPublicSpkiBound).
    PqcPublicSpkiBound,
    /// PQC public algorithm. [Detection, owner and recovery](#cause-PqcPublicAlgorithm).
    PqcPublicAlgorithm,
    /// PQC public allocation. [Detection, owner and recovery](#cause-PqcPublicAllocation).
    PqcPublicAllocation,
    /// PQC public bit string. [Detection, owner and recovery](#cause-PqcPublicBitString).
    PqcPublicBitString,
    /// PQC public context allocation. [Detection, owner and recovery](#cause-PqcPublicContextAllocation).
    PqcPublicContextAllocation,
    /// PQC public context bound. [Detection, owner and recovery](#cause-PqcPublicContextBound).
    PqcPublicContextBound,
    /// PQC public encoding. [Detection, owner and recovery](#cause-PqcPublicEncoding).
    PqcPublicEncoding,
    /// PQC public identity already observed. [Detection, owner and recovery](#cause-PqcPublicIdentityAlreadyObserved).
    PqcPublicIdentityAlreadyObserved,
    /// PQC public key length. [Detection, owner and recovery](#cause-PqcPublicKeyLength).
    PqcPublicKeyLength,
    /// PQC public noncanonical DER. [Detection, owner and recovery](#cause-PqcPublicNoncanonicalDer).
    PqcPublicNoncanonicalDer,
    /// PQC public observation incomplete. [Detection, owner and recovery](#cause-PqcPublicObservationIncomplete).
    PqcPublicObservationIncomplete,
    /// PQC public parameters must be absent. [Detection, owner and recovery](#cause-PqcPublicParametersMustBeAbsent).
    PqcPublicParametersMustBeAbsent,
    /// PQC public prehash framing allocation. [Detection, owner and recovery](#cause-PqcPublicPrehashFramingAllocation).
    PqcPublicPrehashFramingAllocation,
    /// PQC public prehash framing bounds. [Detection, owner and recovery](#cause-PqcPublicPrehashFramingBounds).
    PqcPublicPrehashFramingBounds,
    /// PQC public unused bits. [Detection, owner and recovery](#cause-PqcPublicUnusedBits).
    PqcPublicUnusedBits,
    /// PQC public verification bounds. [Detection, owner and recovery](#cause-PqcPublicVerificationBounds).
    PqcPublicVerificationBounds,
    /// PQC selection ID allocation. [Detection, owner and recovery](#cause-PqcSelectionIdAllocation).
    PqcSelectionIdAllocation,
    /// PQC signature algorithm mismatch. [Detection, owner and recovery](#cause-PqcSignatureAlgorithmMismatch).
    PqcSignatureAlgorithmMismatch,
    /// PQC signature completion unproven. [Detection, owner and recovery](#cause-PqcSignatureCompletionUnproven).
    PqcSignatureCompletionUnproven,
    /// PQC signature input changed. [Detection, owner and recovery](#cause-PqcSignatureInputChanged).
    PqcSignatureInputChanged,
    /// PQC signature length. [Detection, owner and recovery](#cause-PqcSignatureLength).
    PqcSignatureLength,
    /// PQC signature parameters changed. [Detection, owner and recovery](#cause-PqcSignatureParametersChanged).
    PqcSignatureParametersChanged,
    /// PQC signature parameters changed during context authentication. [Detection, owner and recovery](#cause-PqcSignatureParametersChangedDuringContextAuthentication).
    PqcSignatureParametersChangedDuringContextAuthentication,
    /// PQC value requires public identity. [Detection, owner and recovery](#cause-PqcValueRequiresPublicIdentity).
    PqcValueRequiresPublicIdentity,
    /// PQC verification completion unproven. [Detection, owner and recovery](#cause-PqcVerificationCompletionUnproven).
    PqcVerificationCompletionUnproven,
    /// PQC verification input changed. [Detection, owner and recovery](#cause-PqcVerificationInputChanged).
    PqcVerificationInputChanged,
    /// PQC verification parameters changed. [Detection, owner and recovery](#cause-PqcVerificationParametersChanged).
    PqcVerificationParametersChanged,
    /// Existing PQC pair has no creation templates. [Detection, owner and recovery](#cause-ExistingPqcPairHasNoCreationTemplates).
    ExistingPqcPairHasNoCreationTemplates,
    /// Existing PQC pair has no generation request. [Detection, owner and recovery](#cause-ExistingPqcPairHasNoGenerationRequest).
    ExistingPqcPairHasNoGenerationRequest,


    /// Single-part PQC signature requires one input. [Detection, owner and recovery](#cause-SinglePartPqcSignatureRequiresOneInput).
    SinglePartPqcSignatureRequiresOneInput,
    /// Single-part PQC verification requires one input. [Detection, owner and recovery](#cause-SinglePartPqcVerificationRequiresOneInput).
    SinglePartPqcVerificationRequiresOneInput,


}

impl std::fmt::Display for PostQuantumKeysRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::CVerifySignatureUnavailable => f.write_str("C_VerifySignature unavailable"),
            Self::CVerifySignatureFinalUnavailable => {
                f.write_str("C_VerifySignatureFinal unavailable")
            }
            Self::CVerifySignatureInitUnavailable => {
                f.write_str("C_VerifySignatureInit unavailable")
            }
            Self::CVerifySignatureUpdateUnavailable => {
                f.write_str("C_VerifySignatureUpdate unavailable")
            }
            Self::MlDsaImportedKeyFamily => f.write_str("ML-DSA imported key family"),
            Self::PqcVerifysignatureCompletionUnproven => {
                f.write_str("PQC VerifySignature completion unproven")
            }
            Self::PqcVerifysignatureInputChanged => {
                f.write_str("PQC VerifySignature input changed")
            }
            Self::PqcContextLength => f.write_str("PQC context length"),
            Self::PqcExportAccessOwner => f.write_str("PQC export access owner"),
            Self::PqcExportCandidateKind => f.write_str("PQC export candidate kind"),
            Self::PqcExportCompletionPhase => f.write_str("PQC export completion phase"),
            Self::PqcExportContinuationChanged => f.write_str("PQC export continuation changed"),
            Self::PqcExportIdentityPreparationAbsent => {
                f.write_str("PQC export identity preparation absent")
            }
            Self::PqcExportIncomplete => f.write_str("PQC export incomplete"),
            Self::PqcExportMetadataPhase => f.write_str("PQC export metadata phase"),
            Self::PqcExportMetadataSize => f.write_str("PQC export metadata size"),
            Self::PqcExportOwnerAbsent => f.write_str("PQC export owner absent"),
            Self::PqcExportPossessionAbsent => f.write_str("PQC export possession absent"),
            Self::PqcExportRequiresPrivateKey => f.write_str("PQC export requires private key"),
            Self::PqcExportResourceNeedAbsent => f.write_str("PQC export resource need absent"),
            Self::PqcExportStopped => f.write_str("PQC export stopped"),
            Self::PqcExportStorageSize => f.write_str("PQC export storage size"),
            Self::PqcImportPublicLength => f.write_str("PQC import public length"),
            Self::PqcImportSeedLength => f.write_str("PQC import seed length"),
            Self::PqcImportValueLength => f.write_str("PQC import value length"),
            Self::PqcInputPreparationChanged => f.write_str("PQC input preparation changed"),
            Self::PqcMessageCeiling => f.write_str("PQC message ceiling"),
            Self::PqcNativeFrameAccounting => f.write_str("PQC native frame accounting"),
            Self::PqcNativeParameterStorage => f.write_str("PQC native parameter storage"),
            Self::PqcNativeSignatureLength => f.write_str("PQC native signature length"),
            Self::PqcNativeSignatureWidth => f.write_str("PQC native signature width"),
            Self::PqcNativeStorageSize => f.write_str("PQC native storage size"),
            Self::PqcPairObservationBudget => f.write_str("PQC pair observation budget"),
            Self::PqcPairOwnerSize => f.write_str("PQC pair owner size"),
            Self::PqcPairSourceStorage => f.write_str("PQC pair source storage"),
            Self::PqcPrehashLength => f.write_str("PQC prehash length"),
            Self::PqcPrivateAttributeDescriptorOrLength => {
                f.write_str("PQC private attribute descriptor or length")
            }
            Self::PqcPrivateDescriptorOrCapacityChanged => {
                f.write_str("PQC private descriptor or capacity changed")
            }
            Self::PqcPrivateIdentityChangedDuringExport => {
                f.write_str("PQC private identity changed during export")
            }
            Self::PqcPrivateIdentityEncoding => f.write_str("PQC private identity encoding"),
            Self::PqcPublicSpkiDer => f.write_str("PQC public SPKI DER"),
            Self::PqcPublicSpkiBound => f.write_str("PQC public SPKI bound"),
            Self::PqcPublicAlgorithm => f.write_str("PQC public algorithm"),
            Self::PqcPublicAllocation => f.write_str("PQC public allocation"),
            Self::PqcPublicBitString => f.write_str("PQC public bit string"),
            Self::PqcPublicContextAllocation => f.write_str("PQC public context allocation"),
            Self::PqcPublicContextBound => f.write_str("PQC public context bound"),
            Self::PqcPublicEncoding => f.write_str("PQC public encoding"),
            Self::PqcPublicIdentityAlreadyObserved => {
                f.write_str("PQC public identity already observed")
            }
            Self::PqcPublicKeyLength => f.write_str("PQC public key length"),
            Self::PqcPublicNoncanonicalDer => f.write_str("PQC public noncanonical DER"),
            Self::PqcPublicObservationIncomplete => {
                f.write_str("PQC public observation incomplete")
            }
            Self::PqcPublicParametersMustBeAbsent => {
                f.write_str("PQC public parameters must be absent")
            }
            Self::PqcPublicPrehashFramingAllocation => {
                f.write_str("PQC public prehash framing allocation")
            }
            Self::PqcPublicPrehashFramingBounds => f.write_str("PQC public prehash framing bounds"),
            Self::PqcPublicUnusedBits => f.write_str("PQC public unused bits"),
            Self::PqcPublicVerificationBounds => f.write_str("PQC public verification bounds"),
            Self::PqcSelectionIdAllocation => f.write_str("PQC selection ID allocation"),
            Self::PqcSignatureAlgorithmMismatch => f.write_str("PQC signature algorithm mismatch"),
            Self::PqcSignatureCompletionUnproven => {
                f.write_str("PQC signature completion unproven")
            }
            Self::PqcSignatureInputChanged => f.write_str("PQC signature input changed"),
            Self::PqcSignatureLength => f.write_str("PQC signature length"),
            Self::PqcSignatureParametersChanged => f.write_str("PQC signature parameters changed"),
            Self::PqcSignatureParametersChangedDuringContextAuthentication => {
                f.write_str("PQC signature parameters changed during context authentication")
            }
            Self::PqcValueRequiresPublicIdentity => {
                f.write_str("PQC value requires public identity")
            }
            Self::PqcVerificationCompletionUnproven => {
                f.write_str("PQC verification completion unproven")
            }
            Self::PqcVerificationInputChanged => f.write_str("PQC verification input changed"),
            Self::PqcVerificationParametersChanged => {
                f.write_str("PQC verification parameters changed")
            }
            Self::ExistingPqcPairHasNoCreationTemplates => {
                f.write_str("existing PQC pair has no creation templates")
            }
            Self::ExistingPqcPairHasNoGenerationRequest => {
                f.write_str("existing PQC pair has no generation request")
            }


            Self::SinglePartPqcSignatureRequiresOneInput => {
                f.write_str("single-part PQC signature requires one input")
            }
            Self::SinglePartPqcVerificationRequiresOneInput => {
                f.write_str("single-part PQC verification requires one input")
            }
        }
    }
}
