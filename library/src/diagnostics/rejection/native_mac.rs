// SPDX-License-Identifier: Apache-2.0
//! NativeMac causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native mac.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_mac.md")]
pub enum NativeMacRejection {
    /// MAC output length representation. [Detection, owner and recovery](#cause-MacOutputLengthRepresentation).
    MacOutputLengthRepresentation,
    /// MAC parameter native scalar width. [Detection, owner and recovery](#cause-MacParameterNativeScalarWidth).
    MacParameterNativeScalarWidth,
    /// Native MAC output length differs from selected parameters. [Detection, owner and recovery](#cause-NativeMacOutputLengthDiffersFromSelectedParameters).
    NativeMacOutputLengthDiffersFromSelectedParameters,
    /// Single-part MAC requires one input. [Detection, owner and recovery](#cause-SinglePartMacRequiresOneInput).
    SinglePartMacRequiresOneInput,
}

impl std::fmt::Display for NativeMacRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacOutputLengthRepresentation => f.write_str("MAC output length representation"),
            Self::MacParameterNativeScalarWidth => f.write_str("MAC parameter native scalar width"),
            Self::NativeMacOutputLengthDiffersFromSelectedParameters => {
                f.write_str("native MAC output length differs from selected parameters")
            }
            Self::SinglePartMacRequiresOneInput => {
                f.write_str("single-part MAC requires one input")
            }
        }
    }
}
