// SPDX-License-Identifier: Apache-2.0
//! AsynchronousExecution causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to asynchronous execution.
#[doc = include_str!("../../../docs/diagnostics/busy-asynchronous_execution.md")]
pub enum AsynchronousExecutionBusy {
    /// Operation transfer active. [Detection, owner and recovery](#cause-OperationTransferActive).
    OperationTransferActive,
    /// Rejoin destination active. [Detection, owner and recovery](#cause-RejoinDestinationActive).
    RejoinDestinationActive,
}

impl std::fmt::Display for AsynchronousExecutionBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationTransferActive => f.write_str("operation transfer active"),
            Self::RejoinDestinationActive => f.write_str("rejoin destination active"),
        }
    }
}
