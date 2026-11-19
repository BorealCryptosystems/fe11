// SPDX-License-Identifier: Apache-2.0
//! Public DerivedObjectCreationRejection values retain identity through category conversion.
use fe11::{DerivedObjectCreationRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        DerivedObjectCreationRejection::KeaDiagnosticAccounting,
        DerivedObjectCreationRejection::KeaObservationPreparationAbsent,
        DerivedObjectCreationRejection::KeaObservationRegistryAbsent,
        DerivedObjectCreationRejection::KeaOutputAbsent,
        DerivedObjectCreationRejection::KeaPublicationPhase,
        DerivedObjectCreationRejection::KeaRandomDiagnosticAbsent,
        DerivedObjectCreationRejection::KeaRequestAccounting,
        DerivedObjectCreationRejection::Sp800AllocatorCapacity,
        DerivedObjectCreationRejection::Sp800ArrayAllocation,
        DerivedObjectCreationRejection::Sp800MissingTemplateStorage,
        DerivedObjectCreationRejection::Sp800OutputKind,
        DerivedObjectCreationRejection::Sp800PrimaryOutputRequired,
        DerivedObjectCreationRejection::Sp800RequestAccounting,
        DerivedObjectCreationRejection::Sp800ResultAccounting,
        DerivedObjectCreationRejection::Sp800SourceCountOverflow,
        DerivedObjectCreationRejection::Sp800TemplateAccounting,
        DerivedObjectCreationRejection::BaseDerivationSnapshotAbsent,
        DerivedObjectCreationRejection::DerivationRequestStorageAccounting,
        DerivedObjectCreationRejection::DerivedOutputKind,
        DerivedObjectCreationRejection::InternalDerivationSourceComposition,
        DerivedObjectCreationRejection::KeyTransportRequestStorageAccounting,
        DerivedObjectCreationRejection::MutatingKeyTransportRequiresARetainedKey,
        DerivedObjectCreationRejection::SecondaryDerivationSnapshotAbsent,
        DerivedObjectCreationRejection::SecondaryTransportSnapshotAbsent,
        DerivedObjectCreationRejection::TransportObjectAbsent,
        DerivedObjectCreationRejection::TransportOutputKind,
        DerivedObjectCreationRejection::UnchangingKeaPreparationWasInvalidated,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::DerivedObjectCreation(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::DerivedObjectCreation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
