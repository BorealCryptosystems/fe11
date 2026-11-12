// SPDX-License-Identifier: Apache-2.0
//! DerivedObjectCreation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to derived object creation.
#[doc = include_str!("../../../docs/diagnostics/rejection-derived_object_creation.md")]
pub enum DerivedObjectCreationRejection {
    /// KEA diagnostic accounting. [Detection, owner and recovery](#cause-KeaDiagnosticAccounting).
    KeaDiagnosticAccounting,
    /// KEA observation preparation absent. [Detection, owner and recovery](#cause-KeaObservationPreparationAbsent).
    KeaObservationPreparationAbsent,
    /// KEA observation registry absent. [Detection, owner and recovery](#cause-KeaObservationRegistryAbsent).
    KeaObservationRegistryAbsent,
    /// KEA output absent. [Detection, owner and recovery](#cause-KeaOutputAbsent).
    KeaOutputAbsent,
    /// KEA publication phase. [Detection, owner and recovery](#cause-KeaPublicationPhase).
    KeaPublicationPhase,
    /// KEA random diagnostic absent. [Detection, owner and recovery](#cause-KeaRandomDiagnosticAbsent).
    KeaRandomDiagnosticAbsent,
    /// KEA request accounting. [Detection, owner and recovery](#cause-KeaRequestAccounting).
    KeaRequestAccounting,
    /// SP800 allocator capacity. [Detection, owner and recovery](#cause-Sp800AllocatorCapacity).
    Sp800AllocatorCapacity,
    /// SP800 array allocation. [Detection, owner and recovery](#cause-Sp800ArrayAllocation).
    Sp800ArrayAllocation,
    /// SP800 missing template storage. [Detection, owner and recovery](#cause-Sp800MissingTemplateStorage).
    Sp800MissingTemplateStorage,
    /// SP800 output kind. [Detection, owner and recovery](#cause-Sp800OutputKind).
    Sp800OutputKind,
    /// SP800 primary output required. [Detection, owner and recovery](#cause-Sp800PrimaryOutputRequired).
    Sp800PrimaryOutputRequired,
    /// SP800 request accounting. [Detection, owner and recovery](#cause-Sp800RequestAccounting).
    Sp800RequestAccounting,
    /// SP800 result accounting. [Detection, owner and recovery](#cause-Sp800ResultAccounting).
    Sp800ResultAccounting,
    /// SP800 source count overflow. [Detection, owner and recovery](#cause-Sp800SourceCountOverflow).
    Sp800SourceCountOverflow,
    /// SP800 template accounting. [Detection, owner and recovery](#cause-Sp800TemplateAccounting).
    Sp800TemplateAccounting,
    /// Base derivation snapshot absent. [Detection, owner and recovery](#cause-BaseDerivationSnapshotAbsent).
    BaseDerivationSnapshotAbsent,
    /// Derivation request storage accounting. [Detection, owner and recovery](#cause-DerivationRequestStorageAccounting).
    DerivationRequestStorageAccounting,
    /// Derived output kind. [Detection, owner and recovery](#cause-DerivedOutputKind).
    DerivedOutputKind,
    /// Internal derivation source composition. [Detection, owner and recovery](#cause-InternalDerivationSourceComposition).
    InternalDerivationSourceComposition,
    /// Key transport request storage accounting. [Detection, owner and recovery](#cause-KeyTransportRequestStorageAccounting).
    KeyTransportRequestStorageAccounting,
    /// Mutating key transport requires a retained key. [Detection, owner and recovery](#cause-MutatingKeyTransportRequiresARetainedKey).
    MutatingKeyTransportRequiresARetainedKey,
    /// Secondary derivation snapshot absent. [Detection, owner and recovery](#cause-SecondaryDerivationSnapshotAbsent).
    SecondaryDerivationSnapshotAbsent,
    /// Secondary transport snapshot absent. [Detection, owner and recovery](#cause-SecondaryTransportSnapshotAbsent).
    SecondaryTransportSnapshotAbsent,
    /// Transport object absent. [Detection, owner and recovery](#cause-TransportObjectAbsent).
    TransportObjectAbsent,
    /// Transport output kind. [Detection, owner and recovery](#cause-TransportOutputKind).
    TransportOutputKind,
    /// Unchanging KEA preparation was invalidated. [Detection, owner and recovery](#cause-UnchangingKeaPreparationWasInvalidated).
    UnchangingKeaPreparationWasInvalidated,
}

impl std::fmt::Display for DerivedObjectCreationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeaDiagnosticAccounting => f.write_str("KEA diagnostic accounting"),
            Self::KeaObservationPreparationAbsent => {
                f.write_str("KEA observation preparation absent")
            }
            Self::KeaObservationRegistryAbsent => f.write_str("KEA observation registry absent"),
            Self::KeaOutputAbsent => f.write_str("KEA output absent"),
            Self::KeaPublicationPhase => f.write_str("KEA publication phase"),
            Self::KeaRandomDiagnosticAbsent => f.write_str("KEA random diagnostic absent"),
            Self::KeaRequestAccounting => f.write_str("KEA request accounting"),
            Self::Sp800AllocatorCapacity => f.write_str("SP800 allocator capacity"),
            Self::Sp800ArrayAllocation => f.write_str("SP800 array allocation"),
            Self::Sp800MissingTemplateStorage => f.write_str("SP800 missing template storage"),
            Self::Sp800OutputKind => f.write_str("SP800 output kind"),
            Self::Sp800PrimaryOutputRequired => f.write_str("SP800 primary output required"),
            Self::Sp800RequestAccounting => f.write_str("SP800 request accounting"),
            Self::Sp800ResultAccounting => f.write_str("SP800 result accounting"),
            Self::Sp800SourceCountOverflow => f.write_str("SP800 source count overflow"),
            Self::Sp800TemplateAccounting => f.write_str("SP800 template accounting"),
            Self::BaseDerivationSnapshotAbsent => f.write_str("base derivation snapshot absent"),
            Self::DerivationRequestStorageAccounting => {
                f.write_str("derivation request storage accounting")
            }
            Self::DerivedOutputKind => f.write_str("derived output kind"),
            Self::InternalDerivationSourceComposition => {
                f.write_str("internal derivation source composition")
            }
            Self::KeyTransportRequestStorageAccounting => {
                f.write_str("key transport request storage accounting")
            }
            Self::MutatingKeyTransportRequiresARetainedKey => {
                f.write_str("mutating key transport requires a retained key")
            }
            Self::SecondaryDerivationSnapshotAbsent => {
                f.write_str("secondary derivation snapshot absent")
            }
            Self::SecondaryTransportSnapshotAbsent => {
                f.write_str("secondary transport snapshot absent")
            }
            Self::TransportObjectAbsent => f.write_str("transport object absent"),
            Self::TransportOutputKind => f.write_str("transport output kind"),
            Self::UnchangingKeaPreparationWasInvalidated => {
                f.write_str("unchanging KEA preparation was invalidated")
            }
        }
    }
}
