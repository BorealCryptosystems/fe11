// SPDX-License-Identifier: Apache-2.0
//! ObjectPublication causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to object publication.
#[doc = include_str!("../../../docs/diagnostics/busy-object_publication.md")]
pub enum ObjectPublicationBusy {
    /// Mutation cleanup awaits native completion. [Detection, owner and recovery](#cause-MutationCleanupAwaitsNativeCompletion).
    MutationCleanupAwaitsNativeCompletion,
}

impl std::fmt::Display for ObjectPublicationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MutationCleanupAwaitsNativeCompletion => {
                f.write_str("mutation cleanup awaits native completion")
            }
        }
    }
}
