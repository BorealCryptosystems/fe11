// SPDX-License-Identifier: Apache-2.0
//! NativeDigest causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native digest.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_digest.md")]
pub enum NativeDigestRejection {
    /// Digest bit count ABI width. [Detection, owner and recovery](#cause-DigestBitCountAbiWidth).
    DigestBitCountAbiWidth,
    /// Digest output host width. [Detection, owner and recovery](#cause-DigestOutputHostWidth).
    DigestOutputHostWidth,
    /// Native digest output length. [Detection, owner and recovery](#cause-NativeDigestOutputLength).
    NativeDigestOutputLength,
}

impl std::fmt::Display for NativeDigestRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestBitCountAbiWidth => f.write_str("digest bit count ABI width"),
            Self::DigestOutputHostWidth => f.write_str("digest output host width"),
            Self::NativeDigestOutputLength => f.write_str("native digest output length"),
        }
    }
}
