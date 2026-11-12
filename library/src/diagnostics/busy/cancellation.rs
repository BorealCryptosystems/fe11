// SPDX-License-Identifier: Apache-2.0
//! Cancellation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to cancellation.
#[doc = include_str!("../../../docs/diagnostics/busy-cancellation.md")]
pub enum CancellationBusy {
    /// Cancellation pending. [Detection, owner and recovery](#cause-CancellationPending).
    CancellationPending,
    /// Operation detachment control. [Detection, owner and recovery](#cause-OperationDetachmentControl).
    OperationDetachmentControl,
    /// Operation rejoin control. [Detection, owner and recovery](#cause-OperationRejoinControl).
    OperationRejoinControl,
    /// State restoration active. [Detection, owner and recovery](#cause-StateRestorationActive).
    StateRestorationActive,
}

impl std::fmt::Display for CancellationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CancellationPending => f.write_str("cancellation pending"),
            Self::OperationDetachmentControl => f.write_str("operation detachment control"),
            Self::OperationRejoinControl => f.write_str("operation rejoin control"),
            Self::StateRestorationActive => f.write_str("state restoration active"),
        }
    }
}
