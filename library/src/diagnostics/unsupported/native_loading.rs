// SPDX-License-Identifier: Apache-2.0
//! NativeLoading causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native loading.
#[doc = include_str!("../../../docs/diagnostics/unsupported-native_loading.md")]
pub enum NativeLoadingUnsupported {
    /// Current process loader platform. [Detection, owner and recovery](#cause-CurrentProcessLoaderPlatform).
    CurrentProcessLoaderPlatform,
    /// Native image identity platform. [Detection, owner and recovery](#cause-NativeImageIdentityPlatform).
    NativeImageIdentityPlatform,
}

impl std::fmt::Display for NativeLoadingUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentProcessLoaderPlatform => f.write_str("current process loader platform"),
            Self::NativeImageIdentityPlatform => f.write_str("native image identity platform"),
        }
    }
}
