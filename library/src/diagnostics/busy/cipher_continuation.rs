// SPDX-License-Identifier: Apache-2.0
//! CipherContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to cipher continuation.
#[doc = include_str!("../../../docs/diagnostics/busy-cipher_continuation.md")]
pub enum CipherContinuationBusy {
    /// AEAD plaintext awaits successful Final. [Detection, owner and recovery](#cause-AeadPlaintextAwaitsSuccessfulFinal).
    AeadPlaintextAwaitsSuccessfulFinal,
    /// Cipher control changed. [Detection, owner and recovery](#cause-CipherControlChanged).
    CipherControlChanged,
    /// Cipher control in progress. [Detection, owner and recovery](#cause-CipherControlInProgress).
    CipherControlInProgress,
}

impl std::fmt::Display for CipherContinuationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadPlaintextAwaitsSuccessfulFinal => {
                f.write_str("AEAD plaintext awaits successful Final")
            }
            Self::CipherControlChanged => f.write_str("cipher control changed"),
            Self::CipherControlInProgress => f.write_str("cipher control in progress"),
        }
    }
}
