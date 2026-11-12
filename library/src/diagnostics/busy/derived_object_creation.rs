// SPDX-License-Identifier: Apache-2.0
//! DerivedObjectCreation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to derived object creation.
#[doc = include_str!("../../../docs/diagnostics/busy-derived_object_creation.md")]
pub enum DerivedObjectCreationBusy {
    /// KEA creation plan changed. [Detection, owner and recovery](#cause-KeaCreationPlanChanged).
    KeaCreationPlanChanged,
    /// SP800 creation plan changed. [Detection, owner and recovery](#cause-Sp800CreationPlanChanged).
    Sp800CreationPlanChanged,
    /// Derivation creation plan changed. [Detection, owner and recovery](#cause-DerivationCreationPlanChanged).
    DerivationCreationPlanChanged,
    /// Key transport creation plan changed. [Detection, owner and recovery](#cause-KeyTransportCreationPlanChanged).
    KeyTransportCreationPlanChanged,
}

impl std::fmt::Display for DerivedObjectCreationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeaCreationPlanChanged => f.write_str("KEA creation plan changed"),
            Self::Sp800CreationPlanChanged => f.write_str("SP800 creation plan changed"),
            Self::DerivationCreationPlanChanged => f.write_str("derivation creation plan changed"),
            Self::KeyTransportCreationPlanChanged => {
                f.write_str("key transport creation plan changed")
            }
        }
    }
}
