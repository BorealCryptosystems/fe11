// SPDX-License-Identifier: Apache-2.0
//! CipherContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to cipher continuation.
#[doc = include_str!("../../../docs/diagnostics/unsupported-cipher_continuation.md")]
pub enum CipherContinuationUnsupported {
    /// CCM parameter layout unavailable in selected edition. [Detection, owner and recovery](#cause-CcmParameterLayoutUnavailableInSelectedEdition).
    CcmParameterLayoutUnavailableInSelectedEdition,
}

impl std::fmt::Display for CipherContinuationUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CcmParameterLayoutUnavailableInSelectedEdition => {
                f.write_str("CCM parameter layout unavailable in selected edition")
            }
        }
    }
}
