// SPDX-License-Identifier: Apache-2.0
//! Public ObjectObservationRejection values retain identity through category conversion.
use fe11::{Error, ObjectObservationRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectObservationRejection::CDestroyObjectUnavailable,
        ObjectObservationRejection::RsaCreationReservationAbsent,
        ObjectObservationRejection::RsaDiagnosticAccounting,
        ObjectObservationRejection::RsaGenerationCompletionUnknown,
        ObjectObservationRejection::RsaGenerationDiagnosticAbsent,
        ObjectObservationRejection::RsaGenerationDispatchPhase,
        ObjectObservationRejection::RsaGenerationResultKind,
        ObjectObservationRejection::RsaGenerationReturnPhase,
        ObjectObservationRejection::RsaNativeEffectIsNotAStorageRequest,
        ObjectObservationRejection::RsaObjectActivationPhase,
        ObjectObservationRejection::RsaObjectAggregateAccounting,
        ObjectObservationRejection::RsaObjectCandidateKind,
        ObjectObservationRejection::RsaObjectContinuationChanged,
        ObjectObservationRejection::RsaObjectGraphSize,
        ObjectObservationRejection::RsaObjectNeedAbsent,
        ObjectObservationRejection::RsaObjectOperationStopped,
        ObjectObservationRejection::RsaObjectOwnerAbsent,
        ObjectObservationRejection::RsaObjectPossessionAbsent,
        ObjectObservationRejection::RsaObjectPublicationPhase,
        ObjectObservationRejection::RsaObjectResultIncomplete,
        ObjectObservationRejection::RsaObjectResultKind,
        ObjectObservationRejection::RsaObjectSearchRequest,
        ObjectObservationRejection::RsaObjectTransition,
        ObjectObservationRejection::RsaPairCandidateKind,
        ObjectObservationRejection::RsaPairCompletionPhase,
        ObjectObservationRejection::RsaPairContinuationChanged,
        ObjectObservationRejection::RsaPairObservationIncomplete,
        ObjectObservationRejection::RsaPairObservationStopped,
        ObjectObservationRejection::RsaPairObservationStorage,
        ObjectObservationRejection::RsaPairPreparationAbsent,
        ObjectObservationRejection::RsaPrivateSnapshotPreparationAbsent,
        ObjectObservationRejection::RsaPropertyPreparationAbsent,
        ObjectObservationRejection::RsaPublicEncodingAbsent,
        ObjectObservationRejection::RsaPublicationPreparationAbsent,
        ObjectObservationRejection::RsaSelectionPreparationAbsent,
        ObjectObservationRejection::RsaSelectionResultKind,
        ObjectObservationRejection::ForeignOrStaleObject,
        ObjectObservationRejection::ObjectContextOrClass,
        ObjectObservationRejection::PublicAttributeSelectionSizeOverflow,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::ObjectObservation(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::ObjectObservation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
