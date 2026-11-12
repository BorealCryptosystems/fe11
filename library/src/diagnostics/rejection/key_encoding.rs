// SPDX-License-Identifier: Apache-2.0
//! KeyEncoding causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to key encoding.
#[doc = include_str!("../../../docs/diagnostics/rejection-key_encoding.md")]
pub enum KeyEncodingRejection {
    /// EC curve encoding. [Detection, owner and recovery](#cause-EcCurveEncoding).
    EcCurveEncoding,
    /// EC curve outside catalogue. [Detection, owner and recovery](#cause-EcCurveOutsideCatalogue).
    EcCurveOutsideCatalogue,
    /// EC named curve required. [Detection, owner and recovery](#cause-EcNamedCurveRequired).
    EcNamedCurveRequired,
    /// EC parameters. [Detection, owner and recovery](#cause-EcParameters).
    EcParameters,
    /// EC public encoding. [Detection, owner and recovery](#cause-EcPublicEncoding).
    EcPublicEncoding,
    /// Ed25519 public width. [Detection, owner and recovery](#cause-Ed25519PublicWidth).
    Ed25519PublicWidth,
    /// Ed448 public width. [Detection, owner and recovery](#cause-Ed448PublicWidth).
    Ed448PublicWidth,
    /// Edwards parameters must be absent. [Detection, owner and recovery](#cause-EdwardsParametersMustBeAbsent).
    EdwardsParametersMustBeAbsent,
    /// RSA NULL parameters required. [Detection, owner and recovery](#cause-RsaNullParametersRequired).
    RsaNullParametersRequired,
    /// RSA SPKI DER. [Detection, owner and recovery](#cause-RsaSpkiDer).
    RsaSpkiDer,
    /// RSA SPKI algorithm. [Detection, owner and recovery](#cause-RsaSpkiAlgorithm).
    RsaSpkiAlgorithm,
    /// RSA SPKI encoding. [Detection, owner and recovery](#cause-RsaSpkiEncoding).
    RsaSpkiEncoding,
    /// RSA exponent encoding. [Detection, owner and recovery](#cause-RsaExponentEncoding).
    RsaExponentEncoding,
    /// RSA modulus encoding. [Detection, owner and recovery](#cause-RsaModulusEncoding).
    RsaModulusEncoding,
    /// RSA parameters. [Detection, owner and recovery](#cause-RsaParameters).
    RsaParameters,
    /// RSA public DER. [Detection, owner and recovery](#cause-RsaPublicDer).
    RsaPublicDer,
    /// RSA public encoding. [Detection, owner and recovery](#cause-RsaPublicEncoding).
    RsaPublicEncoding,
    /// RSA unused bits. [Detection, owner and recovery](#cause-RsaUnusedBits).
    RsaUnusedBits,
    /// SPKI DER. [Detection, owner and recovery](#cause-SpkiDer).
    SpkiDer,
    /// SPKI encoding. [Detection, owner and recovery](#cause-SpkiEncoding).
    SpkiEncoding,
    /// SPKI unused bits. [Detection, owner and recovery](#cause-SpkiUnusedBits).
    SpkiUnusedBits,
    /// Curve SPKI algorithm. [Detection, owner and recovery](#cause-CurveSpkiAlgorithm).
    CurveSpkiAlgorithm,
    /// Key evidence allocation. [Detection, owner and recovery](#cause-KeyEvidenceAllocation).
    KeyEvidenceAllocation,
    /// Key evidence completion phase. [Detection, owner and recovery](#cause-KeyEvidenceCompletionPhase).
    KeyEvidenceCompletionPhase,
    /// Key evidence identity absent. [Detection, owner and recovery](#cause-KeyEvidenceIdentityAbsent).
    KeyEvidenceIdentityAbsent,
    /// Key evidence incomplete. [Detection, owner and recovery](#cause-KeyEvidenceIncomplete).
    KeyEvidenceIncomplete,
    /// Key evidence mechanism recipe absent. [Detection, owner and recovery](#cause-KeyEvidenceMechanismRecipeAbsent).
    KeyEvidenceMechanismRecipeAbsent,
    /// Key evidence phase. [Detection, owner and recovery](#cause-KeyEvidencePhase).
    KeyEvidencePhase,
    /// Key evidence stopped. [Detection, owner and recovery](#cause-KeyEvidenceStopped).
    KeyEvidenceStopped,
    /// Key evidence storage size. [Detection, owner and recovery](#cause-KeyEvidenceStorageSize).
    KeyEvidenceStorageSize,
    /// Multi-prime RSA unsupported. [Detection, owner and recovery](#cause-MultiPrimeRsaUnsupported).
    MultiPrimeRsaUnsupported,
    /// Noncanonical RSA SPKI. [Detection, owner and recovery](#cause-NoncanonicalRsaSpki).
    NoncanonicalRsaSpki,
    /// Noncanonical RSA public key. [Detection, owner and recovery](#cause-NoncanonicalRsaPublicKey).
    NoncanonicalRsaPublicKey,
    /// Noncanonical SPKI. [Detection, owner and recovery](#cause-NoncanonicalSpki).
    NoncanonicalSpki,
    /// Private EC DER. [Detection, owner and recovery](#cause-PrivateEcDer).
    PrivateEcDer,
    /// Private EC algorithm. [Detection, owner and recovery](#cause-PrivateEcAlgorithm).
    PrivateEcAlgorithm,
    /// Private EC named curve absent. [Detection, owner and recovery](#cause-PrivateEcNamedCurveAbsent).
    PrivateEcNamedCurveAbsent,
    /// Private EC parameters. [Detection, owner and recovery](#cause-PrivateEcParameters).
    PrivateEcParameters,
    /// Private EC version. [Detection, owner and recovery](#cause-PrivateEcVersion).
    PrivateEcVersion,
    /// Private Edwards algorithm. [Detection, owner and recovery](#cause-PrivateEdwardsAlgorithm).
    PrivateEdwardsAlgorithm,
    /// Private Edwards nested octet string. [Detection, owner and recovery](#cause-PrivateEdwardsNestedOctetString).
    PrivateEdwardsNestedOctetString,
    /// Private Edwards parameters. [Detection, owner and recovery](#cause-PrivateEdwardsParameters).
    PrivateEdwardsParameters,
    /// Private Edwards seed length. [Detection, owner and recovery](#cause-PrivateEdwardsSeedLength).
    PrivateEdwardsSeedLength,
    /// Private PKCS8 DER. [Detection, owner and recovery](#cause-PrivatePkcs8Der).
    PrivatePkcs8Der,
    /// Private PKCS8 size. [Detection, owner and recovery](#cause-PrivatePkcs8Size).
    PrivatePkcs8Size,
    /// Private PKCS8 version. [Detection, owner and recovery](#cause-PrivatePkcs8Version).
    PrivatePkcs8Version,
    /// Private RSA DER. [Detection, owner and recovery](#cause-PrivateRsaDer).
    PrivateRsaDer,
    /// Private RSA parameters. [Detection, owner and recovery](#cause-PrivateRsaParameters).
    PrivateRsaParameters,
    /// Private RSA parameters absent. [Detection, owner and recovery](#cause-PrivateRsaParametersAbsent).
    PrivateRsaParametersAbsent,
    /// Private RSA profile. [Detection, owner and recovery](#cause-PrivateRsaProfile).
    PrivateRsaProfile,
    /// Private input allocation size. [Detection, owner and recovery](#cause-PrivateInputAllocationSize).
    PrivateInputAllocationSize,
    /// Private input already charged. [Detection, owner and recovery](#cause-PrivateInputAlreadyCharged).
    PrivateInputAlreadyCharged,
    /// Private input size overflow. [Detection, owner and recovery](#cause-PrivateInputSizeOverflow).
    PrivateInputSizeOverflow,
    /// Public DER allocation. [Detection, owner and recovery](#cause-PublicDerAllocation).
    PublicDerAllocation,
    /// Public DER encoding. [Detection, owner and recovery](#cause-PublicDerEncoding).
    PublicDerEncoding,
    /// Public DER length. [Detection, owner and recovery](#cause-PublicDerLength).
    PublicDerLength,
    /// Public DER width. [Detection, owner and recovery](#cause-PublicDerWidth).
    PublicDerWidth,
    /// Public import mechanism recipe absent. [Detection, owner and recovery](#cause-PublicImportMechanismRecipeAbsent).
    PublicImportMechanismRecipeAbsent,
    /// Public import metadata length. [Detection, owner and recovery](#cause-PublicImportMetadataLength).
    PublicImportMetadataLength,
    /// Public import observation allocation. [Detection, owner and recovery](#cause-PublicImportObservationAllocation).
    PublicImportObservationAllocation,
    /// Public import observation completion phase. [Detection, owner and recovery](#cause-PublicImportObservationCompletionPhase).
    PublicImportObservationCompletionPhase,
    /// Public import observation fields absent. [Detection, owner and recovery](#cause-PublicImportObservationFieldsAbsent).
    PublicImportObservationFieldsAbsent,
    /// Public import observation incomplete. [Detection, owner and recovery](#cause-PublicImportObservationIncomplete).
    PublicImportObservationIncomplete,
    /// Public import observation phase. [Detection, owner and recovery](#cause-PublicImportObservationPhase).
    PublicImportObservationPhase,
    /// Public import observation stopped. [Detection, owner and recovery](#cause-PublicImportObservationStopped).
    PublicImportObservationStopped,
    /// Public import observation storage size. [Detection, owner and recovery](#cause-PublicImportObservationStorageSize).
    PublicImportObservationStorageSize,
    /// Public publication preparation pairing. [Detection, owner and recovery](#cause-PublicPublicationPreparationPairing).
    PublicPublicationPreparationPairing,
    /// Unsigned integer bit length. [Detection, owner and recovery](#cause-UnsignedIntegerBitLength).
    UnsignedIntegerBitLength,


}

impl std::fmt::Display for KeyEncodingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::EcCurveEncoding => f.write_str("EC curve encoding"),
            Self::EcCurveOutsideCatalogue => f.write_str("EC curve outside catalogue"),
            Self::EcNamedCurveRequired => f.write_str("EC named curve required"),
            Self::EcParameters => f.write_str("EC parameters"),
            Self::EcPublicEncoding => f.write_str("EC public encoding"),
            Self::Ed25519PublicWidth => f.write_str("Ed25519 public width"),
            Self::Ed448PublicWidth => f.write_str("Ed448 public width"),
            Self::EdwardsParametersMustBeAbsent => f.write_str("Edwards parameters must be absent"),
            Self::RsaNullParametersRequired => f.write_str("RSA NULL parameters required"),
            Self::RsaSpkiDer => f.write_str("RSA SPKI DER"),
            Self::RsaSpkiAlgorithm => f.write_str("RSA SPKI algorithm"),
            Self::RsaSpkiEncoding => f.write_str("RSA SPKI encoding"),
            Self::RsaExponentEncoding => f.write_str("RSA exponent encoding"),
            Self::RsaModulusEncoding => f.write_str("RSA modulus encoding"),
            Self::RsaParameters => f.write_str("RSA parameters"),
            Self::RsaPublicDer => f.write_str("RSA public DER"),
            Self::RsaPublicEncoding => f.write_str("RSA public encoding"),
            Self::RsaUnusedBits => f.write_str("RSA unused bits"),
            Self::SpkiDer => f.write_str("SPKI DER"),
            Self::SpkiEncoding => f.write_str("SPKI encoding"),
            Self::SpkiUnusedBits => f.write_str("SPKI unused bits"),
            Self::CurveSpkiAlgorithm => f.write_str("curve SPKI algorithm"),
            Self::KeyEvidenceAllocation => f.write_str("key evidence allocation"),
            Self::KeyEvidenceCompletionPhase => f.write_str("key evidence completion phase"),
            Self::KeyEvidenceIdentityAbsent => f.write_str("key evidence identity absent"),
            Self::KeyEvidenceIncomplete => f.write_str("key evidence incomplete"),
            Self::KeyEvidenceMechanismRecipeAbsent => {
                f.write_str("key evidence mechanism recipe absent")
            }
            Self::KeyEvidencePhase => f.write_str("key evidence phase"),
            Self::KeyEvidenceStopped => f.write_str("key evidence stopped"),
            Self::KeyEvidenceStorageSize => f.write_str("key evidence storage size"),
            Self::MultiPrimeRsaUnsupported => f.write_str("multi-prime RSA unsupported"),
            Self::NoncanonicalRsaSpki => f.write_str("noncanonical RSA SPKI"),
            Self::NoncanonicalRsaPublicKey => f.write_str("noncanonical RSA public key"),
            Self::NoncanonicalSpki => f.write_str("noncanonical SPKI"),
            Self::PrivateEcDer => f.write_str("private EC DER"),
            Self::PrivateEcAlgorithm => f.write_str("private EC algorithm"),
            Self::PrivateEcNamedCurveAbsent => f.write_str("private EC named curve absent"),
            Self::PrivateEcParameters => f.write_str("private EC parameters"),
            Self::PrivateEcVersion => f.write_str("private EC version"),
            Self::PrivateEdwardsAlgorithm => f.write_str("private Edwards algorithm"),
            Self::PrivateEdwardsNestedOctetString => {
                f.write_str("private Edwards nested octet string")
            }
            Self::PrivateEdwardsParameters => f.write_str("private Edwards parameters"),
            Self::PrivateEdwardsSeedLength => f.write_str("private Edwards seed length"),
            Self::PrivatePkcs8Der => f.write_str("private PKCS8 DER"),
            Self::PrivatePkcs8Size => f.write_str("private PKCS8 size"),
            Self::PrivatePkcs8Version => f.write_str("private PKCS8 version"),
            Self::PrivateRsaDer => f.write_str("private RSA DER"),
            Self::PrivateRsaParameters => f.write_str("private RSA parameters"),
            Self::PrivateRsaParametersAbsent => f.write_str("private RSA parameters absent"),
            Self::PrivateRsaProfile => f.write_str("private RSA profile"),
            Self::PrivateInputAllocationSize => f.write_str("private input allocation size"),
            Self::PrivateInputAlreadyCharged => f.write_str("private input already charged"),
            Self::PrivateInputSizeOverflow => f.write_str("private input size overflow"),
            Self::PublicDerAllocation => f.write_str("public DER allocation"),
            Self::PublicDerEncoding => f.write_str("public DER encoding"),
            Self::PublicDerLength => f.write_str("public DER length"),
            Self::PublicDerWidth => f.write_str("public DER width"),
            Self::PublicImportMechanismRecipeAbsent => {
                f.write_str("public import mechanism recipe absent")
            }
            Self::PublicImportMetadataLength => f.write_str("public import metadata length"),
            Self::PublicImportObservationAllocation => {
                f.write_str("public import observation allocation")
            }
            Self::PublicImportObservationCompletionPhase => {
                f.write_str("public import observation completion phase")
            }
            Self::PublicImportObservationFieldsAbsent => {
                f.write_str("public import observation fields absent")
            }
            Self::PublicImportObservationIncomplete => {
                f.write_str("public import observation incomplete")
            }
            Self::PublicImportObservationPhase => f.write_str("public import observation phase"),
            Self::PublicImportObservationStopped => {
                f.write_str("public import observation stopped")
            }
            Self::PublicImportObservationStorageSize => {
                f.write_str("public import observation storage size")
            }
            Self::PublicPublicationPreparationPairing => {
                f.write_str("public publication preparation pairing")
            }
            Self::UnsignedIntegerBitLength => f.write_str("unsigned integer bit length"),
        }
    }
}
