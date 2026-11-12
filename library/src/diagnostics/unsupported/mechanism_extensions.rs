// SPDX-License-Identifier: Apache-2.0
//! MechanismExtensions causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to mechanism extensions.
#[doc = include_str!("../../../docs/diagnostics/unsupported-mechanism_extensions.md")]
pub enum MechanismExtensionsUnsupported {
    /// Extension native function tuple. [Detection, owner and recovery](#cause-ExtensionNativeFunctionTuple).
    ExtensionNativeFunctionTuple,
}

impl std::fmt::Display for MechanismExtensionsUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExtensionNativeFunctionTuple => f.write_str("extension native function tuple"),
        }
    }
}
