// SPDX-License-Identifier: Apache-2.0
//! NativeMessages causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native messages.
#[doc = include_str!("../../../docs/diagnostics/busy-native_messages.md")]
pub enum NativeMessagesBusy {
    /// Generic message control changed. [Detection, owner and recovery](#cause-GenericMessageControlChanged).
    GenericMessageControlChanged,
    /// Message destination revocation capacity changed. [Detection, owner and recovery](#cause-MessageDestinationRevocationCapacityChanged).
    MessageDestinationRevocationCapacityChanged,
}

impl std::fmt::Display for NativeMessagesBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenericMessageControlChanged => f.write_str("generic message control changed"),
            Self::MessageDestinationRevocationCapacityChanged => {
                f.write_str("message destination revocation capacity changed")
            }
        }
    }
}
