// SPDX-License-Identifier: Apache-2.0
//! SignatureContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to signature continuation.
#[doc = include_str!("../../../docs/diagnostics/busy-signature_continuation.md")]
pub enum SignatureContinuationBusy {
    /// Signature Init dispatch credit. [Detection, owner and recovery](#cause-SignatureInitDispatchCredit).
    SignatureInitDispatchCredit,
    /// Signature control in progress. [Detection, owner and recovery](#cause-SignatureControlInProgress).
    SignatureControlInProgress,
    /// Signature revocation capacity changed. [Detection, owner and recovery](#cause-SignatureRevocationCapacityChanged).
    SignatureRevocationCapacityChanged,
}

impl std::fmt::Display for SignatureContinuationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInitDispatchCredit => f.write_str("signature Init dispatch credit"),
            Self::SignatureControlInProgress => f.write_str("signature control in progress"),
            Self::SignatureRevocationCapacityChanged => {
                f.write_str("signature revocation capacity changed")
            }
        }
    }
}
