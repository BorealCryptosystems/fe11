// SPDX-License-Identifier: Apache-2.0
//! Public AttributePreparationRejection values retain identity through category conversion.
use fe11::{AttributePreparationRejection, Error, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        AttributePreparationRejection::AttributeAbsentFromAdmissionSnapshot,
        AttributePreparationRejection::AttributeAlignmentSize,
        AttributePreparationRejection::AttributeAllocation,
        AttributePreparationRejection::AttributeContinuationPhase,
        AttributePreparationRejection::AttributeContinuationPreparationChanged,
        AttributePreparationRejection::AttributeExportFieldMissing,
        AttributePreparationRejection::AttributeExportLengthChanged,
        AttributePreparationRejection::AttributeExportSourceAbsent,
        AttributePreparationRejection::AttributeFinalLength,
        AttributePreparationRejection::AttributeNativeDescriptorOrCapacityChanged,
        AttributePreparationRejection::AttributeObservationAccessOwner,
        AttributePreparationRejection::AttributeObservationOutputKind,
        AttributePreparationRejection::AttributeObservationStorageSize,
        AttributePreparationRejection::AttributePreparationKindChanged,
        AttributePreparationRejection::AttributeProjectionCount,
        AttributePreparationRejection::AttributeProjectionCreditAbsent,
        AttributePreparationRejection::AttributeProjectionLengthChanged,
        AttributePreparationRejection::AttributeResidentStorageSize,
        AttributePreparationRejection::AttributeSourceChanged,
        AttributePreparationRejection::AttributeTotal,
        AttributePreparationRejection::AttributeTotalBudget,
        AttributePreparationRejection::AttributeTotalOverflow,
        AttributePreparationRejection::ClassObservationStorageSize,
        AttributePreparationRejection::EmptyPreciseObservation,
        AttributePreparationRejection::FingerprintCompletedStorageMissing,
        AttributePreparationRejection::FingerprintFieldIndex,
        AttributePreparationRejection::FingerprintFieldMissing,
        AttributePreparationRejection::FingerprintObservationIncomplete,
        AttributePreparationRejection::FingerprintRequiresBorrowedResult,
        AttributePreparationRejection::KeyTypeIntegerEncoding,
        AttributePreparationRejection::KeyTypeMismatch,
        AttributePreparationRejection::MechanismAttributeWidth,
        AttributePreparationRejection::MechanismObservationField,
        AttributePreparationRejection::MechanismObservationStorageAbsent,
        AttributePreparationRejection::MechanismProjectionCapacity,
        AttributePreparationRejection::MechanismProjectionLengthChanged,
        AttributePreparationRejection::MechanismProjectionSourceAbsent,
        AttributePreparationRejection::MechanismProjectionWidth,
        AttributePreparationRejection::MechanismTemplateAllocation,
        AttributePreparationRejection::MutationClassIdentityChanged,
        AttributePreparationRejection::MutationClassObservationBudget,
        AttributePreparationRejection::MutationClassObservationUnavailableOrMalformed,
        AttributePreparationRejection::PreciseAttributeObservationCardinality,
        AttributePreparationRejection::ReferenceTemplateBytesAllocation,
        AttributePreparationRejection::ReferenceTemplateFieldsAllocation,
        AttributePreparationRejection::ReferenceTemplateIntegerWidth,
        AttributePreparationRejection::RequiredAttributeUnavailable,
        AttributePreparationRejection::TemplateAllocationSize,
        AttributePreparationRejection::TemplateByteAllocation,
        AttributePreparationRejection::TemplateByteLengthConversion,
        AttributePreparationRejection::TemplateDescriptorAllocation,
        AttributePreparationRejection::TemplateFieldAllocation,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(
            matches!(category, RejectionReason::AttributePreparation(actual) if actual == value)
        );
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::AttributePreparation(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
