// SPDX-License-Identifier: Apache-2.0
//! KeyEncapsulation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to key encapsulation.
#[doc = include_str!("../../../docs/diagnostics/rejection-key_encapsulation.md")]
pub enum KeyEncapsulationRejection {
    /// C_DecapsulateKey unavailable. [Detection, owner and recovery](#cause-CDecapsulateKeyUnavailable).
    CDecapsulateKeyUnavailable,
    /// C_EncapsulateKey unavailable. [Detection, owner and recovery](#cause-CEncapsulateKeyUnavailable).
    CEncapsulateKeyUnavailable,
    /// KEM ciphertext owner absent. [Detection, owner and recovery](#cause-KemCiphertextOwnerAbsent).
    KemCiphertextOwnerAbsent,
    /// KEM public publication pairing. [Detection, owner and recovery](#cause-KemPublicPublicationPairing).
    KemPublicPublicationPairing,
    /// ML-KEM SPKI DER. [Detection, owner and recovery](#cause-MlKemSpkiDer).
    MlKemSpkiDer,
    /// ML-KEM SPKI algorithm. [Detection, owner and recovery](#cause-MlKemSpkiAlgorithm).
    MlKemSpkiAlgorithm,
    /// ML-KEM SPKI encoding. [Detection, owner and recovery](#cause-MlKemSpkiEncoding).
    MlKemSpkiEncoding,
    /// ML-KEM SPKI length. [Detection, owner and recovery](#cause-MlKemSpkiLength).
    MlKemSpkiLength,
    /// ML-KEM SPKI parameters must be absent. [Detection, owner and recovery](#cause-MlKemSpkiParametersMustBeAbsent).
    MlKemSpkiParametersMustBeAbsent,
    /// ML-KEM SPKI unused bits. [Detection, owner and recovery](#cause-MlKemSpkiUnusedBits).
    MlKemSpkiUnusedBits,
    /// ML-KEM ciphertext length. [Detection, owner and recovery](#cause-MlKemCiphertextLength).
    MlKemCiphertextLength,
    /// ML-KEM ciphertext parameter mismatch. [Detection, owner and recovery](#cause-MlKemCiphertextParameterMismatch).
    MlKemCiphertextParameterMismatch,
    /// ML-KEM imported key family. [Detection, owner and recovery](#cause-MlKemImportedKeyFamily).
    MlKemImportedKeyFamily,
    /// ML-KEM input preparation changed. [Detection, owner and recovery](#cause-MlKemInputPreparationChanged).
    MlKemInputPreparationChanged,
    /// ML-KEM native graph overflow. [Detection, owner and recovery](#cause-MlKemNativeGraphOverflow).
    MlKemNativeGraphOverflow,
    /// ML-KEM native input or output capacity violation. [Detection, owner and recovery](#cause-MlKemNativeInputOrOutputCapacityViolation).
    MlKemNativeInputOrOutputCapacityViolation,
    /// ML-KEM noncanonical SPKI. [Detection, owner and recovery](#cause-MlKemNoncanonicalSpki).
    MlKemNoncanonicalSpki,
    /// ML-KEM pair observation budget. [Detection, owner and recovery](#cause-MlKemPairObservationBudget).
    MlKemPairObservationBudget,
    /// ML-KEM pair owner size. [Detection, owner and recovery](#cause-MlKemPairOwnerSize).
    MlKemPairOwnerSize,
    /// ML-KEM pair source storage. [Detection, owner and recovery](#cause-MlKemPairSourceStorage).
    MlKemPairSourceStorage,
    /// ML-KEM public allocation. [Detection, owner and recovery](#cause-MlKemPublicAllocation).
    MlKemPublicAllocation,
    /// ML-KEM public bit string. [Detection, owner and recovery](#cause-MlKemPublicBitString).
    MlKemPublicBitString,
    /// ML-KEM public coefficient encoding. [Detection, owner and recovery](#cause-MlKemPublicCoefficientEncoding).
    MlKemPublicCoefficientEncoding,
    /// ML-KEM public identity already observed. [Detection, owner and recovery](#cause-MlKemPublicIdentityAlreadyObserved).
    MlKemPublicIdentityAlreadyObserved,
    /// ML-KEM public key length. [Detection, owner and recovery](#cause-MlKemPublicKeyLength).
    MlKemPublicKeyLength,
    /// ML-KEM public observation incomplete. [Detection, owner and recovery](#cause-MlKemPublicObservationIncomplete).
    MlKemPublicObservationIncomplete,
    /// ML-KEM requires selected3.2 interface. [Detection, owner and recovery](#cause-MlKemRequiresSelected32Interface).
    MlKemRequiresSelected32Interface,
    /// ML-KEM returned base handle. [Detection, owner and recovery](#cause-MlKemReturnedBaseHandle).
    MlKemReturnedBaseHandle,
    /// ML-KEM selection ID allocation. [Detection, owner and recovery](#cause-MlKemSelectionIdAllocation).
    MlKemSelectionIdAllocation,
    /// ML-KEM value requires public identity. [Detection, owner and recovery](#cause-MlKemValueRequiresPublicIdentity).
    MlKemValueRequiresPublicIdentity,
    /// Existing ML-KEM pair has no creation templates. [Detection, owner and recovery](#cause-ExistingMlKemPairHasNoCreationTemplates).
    ExistingMlKemPairHasNoCreationTemplates,
    /// Existing ML-KEM pair has no generation request. [Detection, owner and recovery](#cause-ExistingMlKemPairHasNoGenerationRequest).
    ExistingMlKemPairHasNoGenerationRequest,

}

impl std::fmt::Display for KeyEncapsulationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {

            Self::CDecapsulateKeyUnavailable => f.write_str("C_DecapsulateKey unavailable"),
            Self::CEncapsulateKeyUnavailable => f.write_str("C_EncapsulateKey unavailable"),
            Self::KemCiphertextOwnerAbsent => f.write_str("KEM ciphertext owner absent"),
            Self::KemPublicPublicationPairing => f.write_str("KEM public publication pairing"),
            Self::MlKemSpkiDer => f.write_str("ML-KEM SPKI DER"),
            Self::MlKemSpkiAlgorithm => f.write_str("ML-KEM SPKI algorithm"),
            Self::MlKemSpkiEncoding => f.write_str("ML-KEM SPKI encoding"),
            Self::MlKemSpkiLength => f.write_str("ML-KEM SPKI length"),
            Self::MlKemSpkiParametersMustBeAbsent => {
                f.write_str("ML-KEM SPKI parameters must be absent")
            }
            Self::MlKemSpkiUnusedBits => f.write_str("ML-KEM SPKI unused bits"),
            Self::MlKemCiphertextLength => f.write_str("ML-KEM ciphertext length"),
            Self::MlKemCiphertextParameterMismatch => {
                f.write_str("ML-KEM ciphertext parameter mismatch")
            }
            Self::MlKemImportedKeyFamily => f.write_str("ML-KEM imported key family"),
            Self::MlKemInputPreparationChanged => f.write_str("ML-KEM input preparation changed"),
            Self::MlKemNativeGraphOverflow => f.write_str("ML-KEM native graph overflow"),
            Self::MlKemNativeInputOrOutputCapacityViolation => {
                f.write_str("ML-KEM native input or output capacity violation")
            }
            Self::MlKemNoncanonicalSpki => f.write_str("ML-KEM noncanonical SPKI"),
            Self::MlKemPairObservationBudget => f.write_str("ML-KEM pair observation budget"),
            Self::MlKemPairOwnerSize => f.write_str("ML-KEM pair owner size"),
            Self::MlKemPairSourceStorage => f.write_str("ML-KEM pair source storage"),
            Self::MlKemPublicAllocation => f.write_str("ML-KEM public allocation"),
            Self::MlKemPublicBitString => f.write_str("ML-KEM public bit string"),
            Self::MlKemPublicCoefficientEncoding => {
                f.write_str("ML-KEM public coefficient encoding")
            }
            Self::MlKemPublicIdentityAlreadyObserved => {
                f.write_str("ML-KEM public identity already observed")
            }
            Self::MlKemPublicKeyLength => f.write_str("ML-KEM public key length"),
            Self::MlKemPublicObservationIncomplete => {
                f.write_str("ML-KEM public observation incomplete")
            }
            Self::MlKemRequiresSelected32Interface => {
                f.write_str("ML-KEM requires selected3.2 interface")
            }
            Self::MlKemReturnedBaseHandle => f.write_str("ML-KEM returned base handle"),
            Self::MlKemSelectionIdAllocation => f.write_str("ML-KEM selection ID allocation"),
            Self::MlKemValueRequiresPublicIdentity => {
                f.write_str("ML-KEM value requires public identity")
            }
            Self::ExistingMlKemPairHasNoCreationTemplates => {
                f.write_str("existing ML-KEM pair has no creation templates")
            }
            Self::ExistingMlKemPairHasNoGenerationRequest => {
                f.write_str("existing ML-KEM pair has no generation request")
            }
        }
    }
}
