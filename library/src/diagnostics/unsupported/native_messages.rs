// SPDX-License-Identifier: Apache-2.0
//! NativeMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native messages.
#[doc = include_str!("../../../docs/diagnostics/unsupported-native_messages.md")]
pub enum NativeMessagesUnsupported {
    /// Message interface. [Detection, owner and recovery](#cause-MessageInterface).
    MessageInterface,
    /// Message signature function tuple. [Detection, owner and recovery](#cause-MessageSignatureFunctionTuple).
    MessageSignatureFunctionTuple,
}

impl std::fmt::Display for NativeMessagesUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MessageInterface => f.write_str("message interface"),
            Self::MessageSignatureFunctionTuple => f.write_str("message signature function tuple"),
        }
    }
}
