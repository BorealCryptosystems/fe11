// SPDX-License-Identifier: Apache-2.0
//! Public NativeDerivationRejection values retain identity through category conversion.
use fe11::{Error, NativeDerivationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeDerivationRejection::CDeriveKeyUnavailable,
        NativeDerivationRejection::IkeParameterAccounting,
        NativeDerivationRejection::KeaCreationDiagnosticsAbsent,
        NativeDerivationRejection::KeaCreationPhase,
        NativeDerivationRejection::KeaCreationScope,
        NativeDerivationRejection::KeaNativeInputMutation,
        NativeDerivationRejection::KeaOutputAliasesSource,
        NativeDerivationRejection::KeaParameterAccounting,
        NativeDerivationRejection::KeaSharedRandomLength,
        NativeDerivationRejection::Sp800IvStorageChanged,
        NativeDerivationRejection::Sp800ArrayStorageOverflow,
        NativeDerivationRejection::Sp800NativeInputMutation,
        NativeDerivationRejection::Sp800OutputAliasesSource,
        NativeDerivationRejection::Sp800StorageOverflow,
        NativeDerivationRejection::Sp800TemplateCountChanged,
        NativeDerivationRejection::TlsPrfFrameAccounting,
        NativeDerivationRejection::TlsPrfNativeInputMutation,
        NativeDerivationRejection::TlsPrfOutputLengthChanged,
        NativeDerivationRejection::TlsPrfSourcePermissionAbsent,
        NativeDerivationRejection::TlsPrfStorageAccounting,
        NativeDerivationRejection::TlsContextStorageChanged,
        NativeDerivationRejection::TlsMasterStorageChanged,
        NativeDerivationRejection::TlsParameterAccounting,
        NativeDerivationRejection::DerivationFrameAccounting,
        NativeDerivationRejection::DerivationInfoStoragePresence,
        NativeDerivationRejection::DerivationNativeInputChanged,
        NativeDerivationRejection::DerivationParameterOwnershipChanged,
        NativeDerivationRejection::DerivationParameterStorageAccounting,
        NativeDerivationRejection::DerivationScalarAbiWidth,
        NativeDerivationRejection::DerivationStorageVariantChanged,
        NativeDerivationRejection::DeriveReturnedBaseHandle,
        NativeDerivationRejection::DeriveReturnedSecondarySourceHandle,
        NativeDerivationRejection::KeyMaterialIvStorage,
        NativeDerivationRejection::KeyMaterialIvWidth,
        NativeDerivationRejection::KeyMaterialNativeInputMutation,
        NativeDerivationRejection::KeyMaterialOutputAliasesSource,
        NativeDerivationRejection::KeyMaterialRandomStorage,
        NativeDerivationRejection::KeyMaterialStorage,
        NativeDerivationRejection::MessagingParameterAccounting,
        NativeDerivationRejection::MissingDerivationDataStorage,
        NativeDerivationRejection::MissingDerivationInputStorage,
        NativeDerivationRejection::MissingDerivationSaltStorage,
        NativeDerivationRejection::MissingKeyMaterialOutput,
        NativeDerivationRejection::OwnedInputLengthOverflow,
        NativeDerivationRejection::PreparedInputLengthChanged,
        NativeDerivationRejection::TwoPairAgreementStorageAccounting,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeDerivation(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeDerivation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
