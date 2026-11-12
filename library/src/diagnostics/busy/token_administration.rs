// SPDX-License-Identifier: Apache-2.0
//! TokenAdministration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to token administration.
#[doc = include_str!("../../../docs/diagnostics/busy-token_administration.md")]
pub enum TokenAdministrationBusy {
    /// Token registry changed. [Detection, owner and recovery](#cause-TokenRegistryChanged).
    TokenRegistryChanged,
}

impl std::fmt::Display for TokenAdministrationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenRegistryChanged => f.write_str("token registry changed"),
        }
    }
}
