// SPDX-License-Identifier: Apache-2.0
//! ObjectCopy causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object copy.
#[doc = include_str!("../../../docs/diagnostics/busy-object_copy.md")]
pub enum ObjectCopyBusy {
    /// Copy creation plan changed. [Detection, owner and recovery](#cause-CopyCreationPlanChanged).
    CopyCreationPlanChanged,
}

impl std::fmt::Display for ObjectCopyBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CopyCreationPlanChanged => f.write_str("copy creation plan changed"),
        }
    }
}
