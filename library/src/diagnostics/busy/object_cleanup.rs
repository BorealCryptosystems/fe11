// SPDX-License-Identifier: Apache-2.0
//! ObjectCleanup causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object cleanup.
#[doc = include_str!("../../../docs/diagnostics/busy-object_cleanup.md")]
pub enum ObjectCleanupBusy {
    /// Creator mutation. [Detection, owner and recovery](#cause-CreatorMutation).
    CreatorMutation,
    /// Object catalogue. [Detection, owner and recovery](#cause-ObjectCatalogue).
    ObjectCatalogue,
}

impl std::fmt::Display for ObjectCleanupBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreatorMutation => f.write_str("creator mutation"),
            Self::ObjectCatalogue => f.write_str("object catalogue"),
        }
    }
}
