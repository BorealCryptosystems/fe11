// SPDX-License-Identifier: Apache-2.0
//! KeyAdmission causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to key admission.
#[doc = include_str!("../../../docs/diagnostics/busy-key_admission.md")]
pub enum KeyAdmissionBusy {
    /// Initial creation plan changed. [Detection, owner and recovery](#cause-InitialCreationPlanChanged).
    InitialCreationPlanChanged,


}

impl std::fmt::Display for KeyAdmissionBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::InitialCreationPlanChanged => f.write_str("initial creation plan changed"),
        }
    }
}
