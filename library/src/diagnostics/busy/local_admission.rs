// SPDX-License-Identifier: Apache-2.0
//! LocalAdmission causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to local admission.
#[doc = include_str!("../../../docs/diagnostics/busy-local_admission.md")]
pub enum LocalAdmissionBusy {
    /// Module activity. [Detection, owner and recovery](#cause-ModuleActivity).
    ModuleActivity,
    /// Module draining. [Detection, owner and recovery](#cause-ModuleDraining).
    ModuleDraining,
}

impl std::fmt::Display for LocalAdmissionBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleActivity => f.write_str("module activity"),
            Self::ModuleDraining => f.write_str("module draining"),
        }
    }
}
