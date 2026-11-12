// SPDX-License-Identifier: Apache-2.0
//! NativeLoading causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native loading.
#[doc = include_str!("../../../docs/diagnostics/busy-native_loading.md")]
pub enum NativeLoadingBusy {
    /// Different native generation or initializer active. [Detection, owner and recovery](#cause-DifferentNativeGenerationOrInitializerActive).
    DifferentNativeGenerationOrInitializerActive,
    /// Native image finalizing. [Detection, owner and recovery](#cause-NativeImageFinalizing).
    NativeImageFinalizing,
    /// Native image initialization attempt active. [Detection, owner and recovery](#cause-NativeImageInitializationAttemptActive).
    NativeImageInitializationAttemptActive,
    /// Native image initializing. [Detection, owner and recovery](#cause-NativeImageInitializing).
    NativeImageInitializing,
    /// Native initialization attempt active. [Detection, owner and recovery](#cause-NativeInitializationAttemptActive).
    NativeInitializationAttemptActive,
}

impl std::fmt::Display for NativeLoadingBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DifferentNativeGenerationOrInitializerActive => {
                f.write_str("different native generation or initializer active")
            }
            Self::NativeImageFinalizing => f.write_str("native image finalizing"),
            Self::NativeImageInitializationAttemptActive => {
                f.write_str("native image initialization attempt active")
            }
            Self::NativeImageInitializing => f.write_str("native image initializing"),
            Self::NativeInitializationAttemptActive => {
                f.write_str("native initialization attempt active")
            }
        }
    }
}
