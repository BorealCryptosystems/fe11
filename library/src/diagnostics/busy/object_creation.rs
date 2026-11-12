// SPDX-License-Identifier: Apache-2.0
//! ObjectCreation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object creation.
#[doc = include_str!("../../../docs/diagnostics/busy-object_creation.md")]
pub enum ObjectCreationBusy {
    /// Generation creation plan changed. [Detection, owner and recovery](#cause-GenerationCreationPlanChanged).
    GenerationCreationPlanChanged,
    /// Key material creation plan changed. [Detection, owner and recovery](#cause-KeyMaterialCreationPlanChanged).
    KeyMaterialCreationPlanChanged,
    /// Native object creation plan changed. [Detection, owner and recovery](#cause-NativeObjectCreationPlanChanged).
    NativeObjectCreationPlanChanged,
    /// Private import creation plan changed. [Detection, owner and recovery](#cause-PrivateImportCreationPlanChanged).
    PrivateImportCreationPlanChanged,
    /// Public import creation plan changed. [Detection, owner and recovery](#cause-PublicImportCreationPlanChanged).
    PublicImportCreationPlanChanged,
    /// Typed object creation plan changed. [Detection, owner and recovery](#cause-TypedObjectCreationPlanChanged).
    TypedObjectCreationPlanChanged,
    /// Unknown creator session closing. [Detection, owner and recovery](#cause-UnknownCreatorSessionClosing).
    UnknownCreatorSessionClosing,
}

impl std::fmt::Display for ObjectCreationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenerationCreationPlanChanged => f.write_str("generation creation plan changed"),
            Self::KeyMaterialCreationPlanChanged => {
                f.write_str("key material creation plan changed")
            }
            Self::NativeObjectCreationPlanChanged => {
                f.write_str("native object creation plan changed")
            }
            Self::PrivateImportCreationPlanChanged => {
                f.write_str("private import creation plan changed")
            }
            Self::PublicImportCreationPlanChanged => {
                f.write_str("public import creation plan changed")
            }
            Self::TypedObjectCreationPlanChanged => {
                f.write_str("typed object creation plan changed")
            }
            Self::UnknownCreatorSessionClosing => f.write_str("unknown creator session closing"),
        }
    }
}
