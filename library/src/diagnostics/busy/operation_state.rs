// SPDX-License-Identifier: Apache-2.0
//! OperationState causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation state.
#[doc = include_str!("../../../docs/diagnostics/busy-operation_state.md")]
pub enum OperationStateBusy {
    /// State capture transfer. [Detection, owner and recovery](#cause-StateCaptureTransfer).
    StateCaptureTransfer,
}

impl std::fmt::Display for OperationStateBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateCaptureTransfer => f.write_str("state capture transfer"),
        }
    }
}
