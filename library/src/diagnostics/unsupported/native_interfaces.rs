// SPDX-License-Identifier: Apache-2.0
//! NativeInterfaces causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native interfaces.
#[doc = include_str!("../../../docs/diagnostics/unsupported-native_interfaces.md")]
pub enum NativeInterfacesUnsupported {
    /// Function table version. [Detection, owner and recovery](#cause-FunctionTableVersion).
    FunctionTableVersion,
}

impl std::fmt::Display for NativeInterfacesUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionTableVersion => f.write_str("function table version"),
        }
    }
}
