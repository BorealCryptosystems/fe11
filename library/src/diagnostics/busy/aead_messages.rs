// SPDX-License-Identifier: Apache-2.0
//! AeadMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to aead messages.
#[doc = include_str!("../../../docs/diagnostics/busy-aead_messages.md")]
pub enum AeadMessagesBusy {
    /// AEAD control changed. [Detection, owner and recovery](#cause-AeadControlChanged).
    AeadControlChanged,
}

impl std::fmt::Display for AeadMessagesBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadControlChanged => f.write_str("AEAD control changed"),
        }
    }
}
