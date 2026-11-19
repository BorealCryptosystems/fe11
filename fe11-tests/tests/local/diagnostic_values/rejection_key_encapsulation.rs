// SPDX-License-Identifier: Apache-2.0
//! Public KeyEncapsulationRejection values retain identity through category conversion.
use fe11::{Error, KeyEncapsulationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        KeyEncapsulationRejection::CDecapsulateKeyUnavailable,
        KeyEncapsulationRejection::CEncapsulateKeyUnavailable,
        KeyEncapsulationRejection::KemCiphertextOwnerAbsent,
        KeyEncapsulationRejection::KemPublicPublicationPairing,
        KeyEncapsulationRejection::MlKemSpkiDer,
        KeyEncapsulationRejection::MlKemSpkiAlgorithm,
        KeyEncapsulationRejection::MlKemSpkiEncoding,
        KeyEncapsulationRejection::MlKemSpkiLength,
        KeyEncapsulationRejection::MlKemSpkiParametersMustBeAbsent,
        KeyEncapsulationRejection::MlKemSpkiUnusedBits,
        KeyEncapsulationRejection::MlKemCiphertextLength,
        KeyEncapsulationRejection::MlKemCiphertextParameterMismatch,
        KeyEncapsulationRejection::MlKemImportedKeyFamily,
        KeyEncapsulationRejection::MlKemInputPreparationChanged,
        KeyEncapsulationRejection::MlKemNativeGraphOverflow,
        KeyEncapsulationRejection::MlKemNativeInputOrOutputCapacityViolation,
        KeyEncapsulationRejection::MlKemNoncanonicalSpki,
        KeyEncapsulationRejection::MlKemPairObservationBudget,
        KeyEncapsulationRejection::MlKemPairOwnerSize,
        KeyEncapsulationRejection::MlKemPairSourceStorage,
        KeyEncapsulationRejection::MlKemPublicAllocation,
        KeyEncapsulationRejection::MlKemPublicBitString,
        KeyEncapsulationRejection::MlKemPublicCoefficientEncoding,
        KeyEncapsulationRejection::MlKemPublicIdentityAlreadyObserved,
        KeyEncapsulationRejection::MlKemPublicKeyLength,
        KeyEncapsulationRejection::MlKemPublicObservationIncomplete,
        KeyEncapsulationRejection::MlKemRequiresSelected32Interface,
        KeyEncapsulationRejection::MlKemReturnedBaseHandle,
        KeyEncapsulationRejection::MlKemSelectionIdAllocation,
        KeyEncapsulationRejection::MlKemValueRequiresPublicIdentity,
        KeyEncapsulationRejection::ExistingMlKemPairHasNoCreationTemplates,
        KeyEncapsulationRejection::ExistingMlKemPairHasNoGenerationRequest,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::KeyEncapsulation(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::KeyEncapsulation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
