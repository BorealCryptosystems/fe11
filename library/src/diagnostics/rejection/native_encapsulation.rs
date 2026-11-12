// SPDX-License-Identifier: Apache-2.0
//! NativeEncapsulation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native encapsulation.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_encapsulation.md")]
pub enum NativeEncapsulationRejection {
    /// KEM KDF ABI width. [Detection, owner and recovery](#cause-KemKdfAbiWidth).
    KemKdfAbiWidth,
}

impl std::fmt::Display for NativeEncapsulationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KemKdfAbiWidth => f.write_str("KEM KDF ABI width"),
        }
    }
}
