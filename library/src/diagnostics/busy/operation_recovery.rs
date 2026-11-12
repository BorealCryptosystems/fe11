// SPDX-License-Identifier: Apache-2.0
//! OperationRecovery causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation recovery.
#[doc = include_str!("../../../docs/diagnostics/busy-operation_recovery.md")]
pub enum OperationRecoveryBusy {
    /// Recovery control in progress. [Detection, owner and recovery](#cause-RecoveryControlInProgress).
    RecoveryControlInProgress,
}

impl std::fmt::Display for OperationRecoveryBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecoveryControlInProgress => f.write_str("recovery control in progress"),
        }
    }
}
