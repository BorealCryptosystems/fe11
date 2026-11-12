// SPDX-License-Identifier: Apache-2.0
//! AeadMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to aead messages.
#[doc = include_str!("../../../docs/diagnostics/unsupported-aead_messages.md")]
pub enum AeadMessagesUnsupported {
    /// Declared GCM message state capture. [Detection, owner and recovery](#cause-DeclaredGcmMessageStateCapture).
    DeclaredGcmMessageStateCapture,
}

impl std::fmt::Display for AeadMessagesUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeclaredGcmMessageStateCapture => {
                f.write_str("declared GCM message state capture")
            }
        }
    }
}
