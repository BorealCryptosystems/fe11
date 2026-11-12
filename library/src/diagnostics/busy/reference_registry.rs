// SPDX-License-Identifier: Apache-2.0
//! ReferenceRegistry causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to reference registry.
#[doc = include_str!("../../../docs/diagnostics/busy-reference_registry.md")]
pub enum ReferenceRegistryBusy {
    /// Object mutation. [Detection, owner and recovery](#cause-ObjectMutation).
    ObjectMutation,
    /// Reference quota exceeded. [Detection, owner and recovery](#cause-ReferenceQuotaExceeded).
    ReferenceQuotaExceeded,
}

impl std::fmt::Display for ReferenceRegistryBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObjectMutation => f.write_str("object mutation"),
            Self::ReferenceQuotaExceeded => f.write_str("reference quota exceeded"),
        }
    }
}
