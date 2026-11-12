// SPDX-License-Identifier: Apache-2.0
//! SignatureContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to signature continuation.
#[doc = include_str!("../../../docs/diagnostics/unsupported-signature_continuation.md")]
pub enum SignatureContinuationUnsupported {
    /// Signature function tuple. [Detection, owner and recovery](#cause-SignatureFunctionTuple).
    SignatureFunctionTuple,
}

impl std::fmt::Display for SignatureContinuationUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureFunctionTuple => f.write_str("signature function tuple"),
        }
    }
}
