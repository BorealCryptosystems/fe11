// SPDX-License-Identifier: Apache-2.0
//! Public KeyEncodingRejection values retain identity through category conversion.
use fe11::{Error, KeyEncodingRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        KeyEncodingRejection::EcCurveEncoding,
        KeyEncodingRejection::EcCurveOutsideCatalogue,
        KeyEncodingRejection::EcNamedCurveRequired,
        KeyEncodingRejection::EcParameters,
        KeyEncodingRejection::EcPublicEncoding,
        KeyEncodingRejection::Ed25519PublicWidth,
        KeyEncodingRejection::Ed448PublicWidth,
        KeyEncodingRejection::EdwardsParametersMustBeAbsent,
        KeyEncodingRejection::RsaNullParametersRequired,
        KeyEncodingRejection::RsaSpkiDer,
        KeyEncodingRejection::RsaSpkiAlgorithm,
        KeyEncodingRejection::RsaSpkiEncoding,
        KeyEncodingRejection::RsaExponentEncoding,
        KeyEncodingRejection::RsaModulusEncoding,
        KeyEncodingRejection::RsaParameters,
        KeyEncodingRejection::RsaPublicDer,
        KeyEncodingRejection::RsaPublicEncoding,
        KeyEncodingRejection::RsaUnusedBits,
        KeyEncodingRejection::SpkiDer,
        KeyEncodingRejection::SpkiEncoding,
        KeyEncodingRejection::SpkiUnusedBits,
        KeyEncodingRejection::CurveSpkiAlgorithm,
        KeyEncodingRejection::KeyEvidenceAllocation,
        KeyEncodingRejection::KeyEvidenceCompletionPhase,
        KeyEncodingRejection::KeyEvidenceIdentityAbsent,
        KeyEncodingRejection::KeyEvidenceIncomplete,
        KeyEncodingRejection::KeyEvidenceMechanismRecipeAbsent,
        KeyEncodingRejection::KeyEvidencePhase,
        KeyEncodingRejection::KeyEvidenceStopped,
        KeyEncodingRejection::KeyEvidenceStorageSize,
        KeyEncodingRejection::MultiPrimeRsaUnsupported,
        KeyEncodingRejection::NoncanonicalRsaSpki,
        KeyEncodingRejection::NoncanonicalRsaPublicKey,
        KeyEncodingRejection::NoncanonicalSpki,
        KeyEncodingRejection::PrivateEcDer,
        KeyEncodingRejection::PrivateEcAlgorithm,
        KeyEncodingRejection::PrivateEcNamedCurveAbsent,
        KeyEncodingRejection::PrivateEcParameters,
        KeyEncodingRejection::PrivateEcVersion,
        KeyEncodingRejection::PrivateEdwardsAlgorithm,
        KeyEncodingRejection::PrivateEdwardsNestedOctetString,
        KeyEncodingRejection::PrivateEdwardsParameters,
        KeyEncodingRejection::PrivateEdwardsSeedLength,
        KeyEncodingRejection::PrivatePkcs8Der,
        KeyEncodingRejection::PrivatePkcs8Size,
        KeyEncodingRejection::PrivatePkcs8Version,
        KeyEncodingRejection::PrivateRsaDer,
        KeyEncodingRejection::PrivateRsaParameters,
        KeyEncodingRejection::PrivateRsaParametersAbsent,
        KeyEncodingRejection::PrivateRsaProfile,
        KeyEncodingRejection::PrivateInputAllocationSize,
        KeyEncodingRejection::PrivateInputAlreadyCharged,
        KeyEncodingRejection::PrivateInputSizeOverflow,
        KeyEncodingRejection::PublicDerAllocation,
        KeyEncodingRejection::PublicDerEncoding,
        KeyEncodingRejection::PublicDerLength,
        KeyEncodingRejection::PublicDerWidth,
        KeyEncodingRejection::PublicImportMechanismRecipeAbsent,
        KeyEncodingRejection::PublicImportMetadataLength,
        KeyEncodingRejection::PublicImportObservationAllocation,
        KeyEncodingRejection::PublicImportObservationCompletionPhase,
        KeyEncodingRejection::PublicImportObservationFieldsAbsent,
        KeyEncodingRejection::PublicImportObservationIncomplete,
        KeyEncodingRejection::PublicImportObservationPhase,
        KeyEncodingRejection::PublicImportObservationStopped,
        KeyEncodingRejection::PublicImportObservationStorageSize,
        KeyEncodingRejection::PublicPublicationPreparationPairing,
        KeyEncodingRejection::UnsignedIntegerBitLength,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::KeyEncoding(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::KeyEncoding(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
