// SPDX-License-Identifier: Apache-2.0
//! NativeMac causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native mac.
#[doc = include_str!("../../../docs/diagnostics/unsupported-native_mac.md")]
pub enum NativeMacUnsupported {
    /// MAC has no general-length variant. [Detection, owner and recovery](#cause-MacHasNoGeneralLengthVariant).
    MacHasNoGeneralLengthVariant,
}

impl std::fmt::Display for NativeMacUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacHasNoGeneralLengthVariant => f.write_str("MAC has no general-length variant"),
        }
    }
}
