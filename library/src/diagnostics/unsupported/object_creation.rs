// SPDX-License-Identifier: Apache-2.0
//! ObjectCreation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object creation.
#[doc = include_str!("../../../docs/diagnostics/unsupported-object_creation.md")]
pub enum ObjectCreationUnsupported {
    /// Creation class requires an extension contract. [Detection, owner and recovery](#cause-CreationClassRequiresAnExtensionContract).
    CreationClassRequiresAnExtensionContract,
}

impl std::fmt::Display for ObjectCreationUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreationClassRequiresAnExtensionContract => {
                f.write_str("creation class requires an extension contract")
            }
        }
    }
}
