// SPDX-License-Identifier: Apache-2.0
//! AttributePreparation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to attribute preparation.
#[doc = include_str!("../../../docs/diagnostics/rejection-attribute_preparation.md")]
pub enum AttributePreparationRejection {
    /// Attribute absent from admission snapshot. [Detection, owner and recovery](#cause-AttributeAbsentFromAdmissionSnapshot).
    AttributeAbsentFromAdmissionSnapshot,
    /// Attribute alignment size. [Detection, owner and recovery](#cause-AttributeAlignmentSize).
    AttributeAlignmentSize,
    /// Attribute allocation. [Detection, owner and recovery](#cause-AttributeAllocation).
    AttributeAllocation,
    /// Attribute continuation phase. [Detection, owner and recovery](#cause-AttributeContinuationPhase).
    AttributeContinuationPhase,
    /// Attribute continuation preparation changed. [Detection, owner and recovery](#cause-AttributeContinuationPreparationChanged).
    AttributeContinuationPreparationChanged,
    /// Attribute export field missing. [Detection, owner and recovery](#cause-AttributeExportFieldMissing).
    AttributeExportFieldMissing,
    /// Attribute export length changed. [Detection, owner and recovery](#cause-AttributeExportLengthChanged).
    AttributeExportLengthChanged,
    /// Attribute export source absent. [Detection, owner and recovery](#cause-AttributeExportSourceAbsent).
    AttributeExportSourceAbsent,
    /// Attribute final length. [Detection, owner and recovery](#cause-AttributeFinalLength).
    AttributeFinalLength,
    /// Attribute native descriptor or capacity changed. [Detection, owner and recovery](#cause-AttributeNativeDescriptorOrCapacityChanged).
    AttributeNativeDescriptorOrCapacityChanged,
    /// Attribute observation access owner. [Detection, owner and recovery](#cause-AttributeObservationAccessOwner).
    AttributeObservationAccessOwner,
    /// Attribute observation output kind. [Detection, owner and recovery](#cause-AttributeObservationOutputKind).
    AttributeObservationOutputKind,
    /// Attribute observation storage size. [Detection, owner and recovery](#cause-AttributeObservationStorageSize).
    AttributeObservationStorageSize,
    /// Attribute preparation kind changed. [Detection, owner and recovery](#cause-AttributePreparationKindChanged).
    AttributePreparationKindChanged,
    /// Attribute projection count. [Detection, owner and recovery](#cause-AttributeProjectionCount).
    AttributeProjectionCount,
    /// Attribute projection credit absent. [Detection, owner and recovery](#cause-AttributeProjectionCreditAbsent).
    AttributeProjectionCreditAbsent,
    /// Attribute projection length changed. [Detection, owner and recovery](#cause-AttributeProjectionLengthChanged).
    AttributeProjectionLengthChanged,
    /// Attribute resident storage size. [Detection, owner and recovery](#cause-AttributeResidentStorageSize).
    AttributeResidentStorageSize,
    /// Attribute source changed. [Detection, owner and recovery](#cause-AttributeSourceChanged).
    AttributeSourceChanged,
    /// Attribute total. [Detection, owner and recovery](#cause-AttributeTotal).
    AttributeTotal,
    /// Attribute total budget. [Detection, owner and recovery](#cause-AttributeTotalBudget).
    AttributeTotalBudget,
    /// Attribute total overflow. [Detection, owner and recovery](#cause-AttributeTotalOverflow).
    AttributeTotalOverflow,
    /// Class observation storage size. [Detection, owner and recovery](#cause-ClassObservationStorageSize).
    ClassObservationStorageSize,
    /// Empty precise observation. [Detection, owner and recovery](#cause-EmptyPreciseObservation).
    EmptyPreciseObservation,
    /// Fingerprint completed storage missing. [Detection, owner and recovery](#cause-FingerprintCompletedStorageMissing).
    FingerprintCompletedStorageMissing,
    /// Fingerprint field index. [Detection, owner and recovery](#cause-FingerprintFieldIndex).
    FingerprintFieldIndex,
    /// Fingerprint field missing. [Detection, owner and recovery](#cause-FingerprintFieldMissing).
    FingerprintFieldMissing,
    /// Fingerprint observation incomplete. [Detection, owner and recovery](#cause-FingerprintObservationIncomplete).
    FingerprintObservationIncomplete,
    /// Fingerprint requires borrowed result. [Detection, owner and recovery](#cause-FingerprintRequiresBorrowedResult).
    FingerprintRequiresBorrowedResult,
    /// Key type integer encoding. [Detection, owner and recovery](#cause-KeyTypeIntegerEncoding).
    KeyTypeIntegerEncoding,
    /// Key type mismatch. [Detection, owner and recovery](#cause-KeyTypeMismatch).
    KeyTypeMismatch,
    /// Mechanism attribute width. [Detection, owner and recovery](#cause-MechanismAttributeWidth).
    MechanismAttributeWidth,
    /// Mechanism observation field. [Detection, owner and recovery](#cause-MechanismObservationField).
    MechanismObservationField,
    /// Mechanism observation storage absent. [Detection, owner and recovery](#cause-MechanismObservationStorageAbsent).
    MechanismObservationStorageAbsent,
    /// Mechanism projection capacity. [Detection, owner and recovery](#cause-MechanismProjectionCapacity).
    MechanismProjectionCapacity,
    /// Mechanism projection length changed. [Detection, owner and recovery](#cause-MechanismProjectionLengthChanged).
    MechanismProjectionLengthChanged,
    /// Mechanism projection source absent. [Detection, owner and recovery](#cause-MechanismProjectionSourceAbsent).
    MechanismProjectionSourceAbsent,
    /// Mechanism projection width. [Detection, owner and recovery](#cause-MechanismProjectionWidth).
    MechanismProjectionWidth,
    /// Mechanism template allocation. [Detection, owner and recovery](#cause-MechanismTemplateAllocation).
    MechanismTemplateAllocation,
    /// Mutation class identity changed. [Detection, owner and recovery](#cause-MutationClassIdentityChanged).
    MutationClassIdentityChanged,
    /// Mutation class observation budget. [Detection, owner and recovery](#cause-MutationClassObservationBudget).
    MutationClassObservationBudget,
    /// Mutation class observation unavailable or malformed. [Detection, owner and recovery](#cause-MutationClassObservationUnavailableOrMalformed).
    MutationClassObservationUnavailableOrMalformed,
    /// Precise attribute observation cardinality. [Detection, owner and recovery](#cause-PreciseAttributeObservationCardinality).
    PreciseAttributeObservationCardinality,
    /// Reference template bytes allocation. [Detection, owner and recovery](#cause-ReferenceTemplateBytesAllocation).
    ReferenceTemplateBytesAllocation,
    /// Reference template fields allocation. [Detection, owner and recovery](#cause-ReferenceTemplateFieldsAllocation).
    ReferenceTemplateFieldsAllocation,
    /// Reference template integer width. [Detection, owner and recovery](#cause-ReferenceTemplateIntegerWidth).
    ReferenceTemplateIntegerWidth,
    /// Required attribute unavailable. [Detection, owner and recovery](#cause-RequiredAttributeUnavailable).
    RequiredAttributeUnavailable,
    /// Template allocation size. [Detection, owner and recovery](#cause-TemplateAllocationSize).
    TemplateAllocationSize,
    /// Template byte allocation. [Detection, owner and recovery](#cause-TemplateByteAllocation).
    TemplateByteAllocation,
    /// Template byte length conversion. [Detection, owner and recovery](#cause-TemplateByteLengthConversion).
    TemplateByteLengthConversion,
    /// Template descriptor allocation. [Detection, owner and recovery](#cause-TemplateDescriptorAllocation).
    TemplateDescriptorAllocation,
    /// Template field allocation. [Detection, owner and recovery](#cause-TemplateFieldAllocation).
    TemplateFieldAllocation,


}

impl std::fmt::Display for AttributePreparationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AttributeAbsentFromAdmissionSnapshot => {
                f.write_str("attribute absent from admission snapshot")
            }
            Self::AttributeAlignmentSize => f.write_str("attribute alignment size"),
            Self::AttributeAllocation => f.write_str("attribute allocation"),
            Self::AttributeContinuationPhase => f.write_str("attribute continuation phase"),
            Self::AttributeContinuationPreparationChanged => {
                f.write_str("attribute continuation preparation changed")
            }
            Self::AttributeExportFieldMissing => f.write_str("attribute export field missing"),
            Self::AttributeExportLengthChanged => f.write_str("attribute export length changed"),
            Self::AttributeExportSourceAbsent => f.write_str("attribute export source absent"),
            Self::AttributeFinalLength => f.write_str("attribute final length"),
            Self::AttributeNativeDescriptorOrCapacityChanged => {
                f.write_str("attribute native descriptor or capacity changed")
            }
            Self::AttributeObservationAccessOwner => {
                f.write_str("attribute observation access owner")
            }
            Self::AttributeObservationOutputKind => {
                f.write_str("attribute observation output kind")
            }
            Self::AttributeObservationStorageSize => {
                f.write_str("attribute observation storage size")
            }
            Self::AttributePreparationKindChanged => {
                f.write_str("attribute preparation kind changed")
            }
            Self::AttributeProjectionCount => f.write_str("attribute projection count"),
            Self::AttributeProjectionCreditAbsent => {
                f.write_str("attribute projection credit absent")
            }
            Self::AttributeProjectionLengthChanged => {
                f.write_str("attribute projection length changed")
            }
            Self::AttributeResidentStorageSize => f.write_str("attribute resident storage size"),
            Self::AttributeSourceChanged => f.write_str("attribute source changed"),
            Self::AttributeTotal => f.write_str("attribute total"),
            Self::AttributeTotalBudget => f.write_str("attribute total budget"),
            Self::AttributeTotalOverflow => f.write_str("attribute total overflow"),
            Self::ClassObservationStorageSize => f.write_str("class observation storage size"),
            Self::EmptyPreciseObservation => f.write_str("empty precise observation"),
            Self::FingerprintCompletedStorageMissing => {
                f.write_str("fingerprint completed storage missing")
            }
            Self::FingerprintFieldIndex => f.write_str("fingerprint field index"),
            Self::FingerprintFieldMissing => f.write_str("fingerprint field missing"),
            Self::FingerprintObservationIncomplete => {
                f.write_str("fingerprint observation incomplete")
            }
            Self::FingerprintRequiresBorrowedResult => {
                f.write_str("fingerprint requires borrowed result")
            }
            Self::KeyTypeIntegerEncoding => f.write_str("key type integer encoding"),
            Self::KeyTypeMismatch => f.write_str("key type mismatch"),
            Self::MechanismAttributeWidth => f.write_str("mechanism attribute width"),
            Self::MechanismObservationField => f.write_str("mechanism observation field"),
            Self::MechanismObservationStorageAbsent => {
                f.write_str("mechanism observation storage absent")
            }
            Self::MechanismProjectionCapacity => f.write_str("mechanism projection capacity"),
            Self::MechanismProjectionLengthChanged => {
                f.write_str("mechanism projection length changed")
            }
            Self::MechanismProjectionSourceAbsent => {
                f.write_str("mechanism projection source absent")
            }
            Self::MechanismProjectionWidth => f.write_str("mechanism projection width"),
            Self::MechanismTemplateAllocation => f.write_str("mechanism template allocation"),
            Self::MutationClassIdentityChanged => f.write_str("mutation class identity changed"),
            Self::MutationClassObservationBudget => {
                f.write_str("mutation class observation budget")
            }
            Self::MutationClassObservationUnavailableOrMalformed => {
                f.write_str("mutation class observation unavailable or malformed")
            }
            Self::PreciseAttributeObservationCardinality => {
                f.write_str("precise attribute observation cardinality")
            }
            Self::ReferenceTemplateBytesAllocation => {
                f.write_str("reference template bytes allocation")
            }
            Self::ReferenceTemplateFieldsAllocation => {
                f.write_str("reference template fields allocation")
            }
            Self::ReferenceTemplateIntegerWidth => f.write_str("reference template integer width"),
            Self::RequiredAttributeUnavailable => f.write_str("required attribute unavailable"),
            Self::TemplateAllocationSize => f.write_str("template allocation size"),
            Self::TemplateByteAllocation => f.write_str("template byte allocation"),
            Self::TemplateByteLengthConversion => f.write_str("template byte length conversion"),
            Self::TemplateDescriptorAllocation => f.write_str("template descriptor allocation"),
            Self::TemplateFieldAllocation => f.write_str("template field allocation"),
        }
    }
}
