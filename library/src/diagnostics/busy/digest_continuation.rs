// SPDX-License-Identifier: Apache-2.0
//! DigestContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to digest continuation.
#[doc = include_str!("../../../docs/diagnostics/busy-digest_continuation.md")]
pub enum DigestContinuationBusy {
    /// Digest control in progress. [Detection, owner and recovery](#cause-DigestControlInProgress).
    DigestControlInProgress,
}

impl std::fmt::Display for DigestContinuationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestControlInProgress => f.write_str("digest control in progress"),
        }
    }
}
