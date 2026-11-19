// SPDX-License-Identifier: Apache-2.0
//! Public KeyTransportRejection values retain identity through category conversion.
use fe11::{Error, KeyTransportRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        KeyTransportRejection::AesKekAlgorithm,
        KeyTransportRejection::AesKekMaterialLength,
        KeyTransportRejection::AesKekMechanismReportAbsent,
        KeyTransportRejection::CDecryptUnavailable,
        KeyTransportRejection::CDecryptInitUnavailable,
        KeyTransportRejection::CEncryptUnavailable,
        KeyTransportRejection::CEncryptInitUnavailable,
        KeyTransportRejection::CUnwrapKeyUnavailable,
        KeyTransportRejection::CUnwrapKeyAuthenticatedUnavailableInSelectedInterface,
        KeyTransportRejection::CWrapKeyUnavailable,
        KeyTransportRejection::CWrapKeyAuthenticatedUnavailableInSelectedInterface,
        KeyTransportRejection::GcmSelectionSize,
        KeyTransportRejection::MgfIdentifierConversion,
        KeyTransportRejection::OaepMgfIdentifierWidth,
        KeyTransportRejection::OaepHashIdentifierWidth,
        KeyTransportRejection::OaepInputChangedDuringContextAuthentication,
        KeyTransportRejection::OaepInputDescriptorChanged,
        KeyTransportRejection::OaepLabelAllocation,
        KeyTransportRejection::OaepPlaintextAllocation,
        KeyTransportRejection::OaepStorageAccounting,
        KeyTransportRejection::RsaKekSpkiSize,
        KeyTransportRejection::RsaCiphertextAllocation,
        KeyTransportRejection::RsaCiphertextCapacity,
        KeyTransportRejection::RsaCiphertextLength,
        KeyTransportRejection::RsaImportedPrivateProtection,
        KeyTransportRejection::RsaMechanismReportAbsent,
        KeyTransportRejection::RsaPrivateMaterialFamily,
        KeyTransportRejection::RsaPrivateMechanismReportAbsent,
        KeyTransportRejection::RsaPublicPublicationAbsent,
        KeyTransportRejection::RsaRestoredHistoryReportAbsent,
        KeyTransportRejection::RsaRestoredMechanismReportAbsent,
        KeyTransportRejection::AuthenticatedUnwrapParameters,
        KeyTransportRejection::HashIdentifierConversion,
        KeyTransportRejection::ImportedKekHistoryReportAbsent,
        KeyTransportRejection::ImportedSymmetricHistoryReportAbsent,
        KeyTransportRejection::KeyMechanismReportAbsent,
        KeyTransportRejection::NativeKekCreationUnavailable,
        KeyTransportRejection::NativeIntroductionUnavailable,
        KeyTransportRejection::NativePlaintextLength,
        KeyTransportRejection::PrivateTemplateStorageAllocation,
        KeyTransportRejection::PrivateTemplateStorageSize,
        KeyTransportRejection::RestorationAlreadyConsumed,
        KeyTransportRejection::RestorationEvidenceFamilyMismatch,
        KeyTransportRejection::RestoredHistoryReportAbsent,
        KeyTransportRejection::TransportAttributeCountOverflow,
        KeyTransportRejection::TransportDuplicateTemplateField,
        KeyTransportRejection::TransportHandleBinding,
        KeyTransportRejection::TransportMixedPrivateRepresentations,
        KeyTransportRejection::TransportPrivateTemplateField,
        KeyTransportRejection::TransportPublicTemplateField,
        KeyTransportRejection::TransportSecretLength,
        KeyTransportRejection::UnwrapReturnedKekHandle,
        KeyTransportRejection::UnwrappingInputsChanged,
        KeyTransportRejection::UnwrappingStorageSize,
        KeyTransportRejection::WrappedOutputExceedsCapacity,
        KeyTransportRejection::WrappingParametersChanged,
        KeyTransportRejection::WrappingSizeRepresentation,
        KeyTransportRejection::WrappingStorageSize,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::KeyTransport(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::KeyTransport(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
