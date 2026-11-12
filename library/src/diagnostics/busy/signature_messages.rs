// SPDX-License-Identifier: Apache-2.0
//! SignatureMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to signature messages.
#[doc = include_str!("../../../docs/diagnostics/busy-signature_messages.md")]
pub enum SignatureMessagesBusy {
    /// Message signature control changed. [Detection, owner and recovery](#cause-MessageSignatureControlChanged).
    MessageSignatureControlChanged,
}

impl std::fmt::Display for SignatureMessagesBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageSignatureControlChanged => {
                f.write_str("message signature control changed")
            }
        }
    }
}
