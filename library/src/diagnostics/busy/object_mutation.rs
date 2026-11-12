// SPDX-License-Identifier: Apache-2.0
//! ObjectMutation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object mutation.
#[doc = include_str!("../../../docs/diagnostics/busy-object_mutation.md")]
pub enum ObjectMutationBusy {
    /// Content creation plan changed. [Detection, owner and recovery](#cause-ContentCreationPlanChanged).
    ContentCreationPlanChanged,
    /// Label mutation plan changed. [Detection, owner and recovery](#cause-LabelMutationPlanChanged).
    LabelMutationPlanChanged,
    /// Object activity. [Detection, owner and recovery](#cause-ObjectActivity).
    ObjectActivity,
    /// Object selection. [Detection, owner and recovery](#cause-ObjectSelection).
    ObjectSelection,
    /// Token inventory. [Detection, owner and recovery](#cause-TokenInventory).
    TokenInventory,
    /// Token mutation. [Detection, owner and recovery](#cause-TokenMutation).
    TokenMutation,
}

impl std::fmt::Display for ObjectMutationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ContentCreationPlanChanged => f.write_str("content creation plan changed"),
            Self::LabelMutationPlanChanged => f.write_str("label mutation plan changed"),
            Self::ObjectActivity => f.write_str("object activity"),
            Self::ObjectSelection => f.write_str("object selection"),
            Self::TokenInventory => f.write_str("token inventory"),
            Self::TokenMutation => f.write_str("token mutation"),
        }
    }
}
