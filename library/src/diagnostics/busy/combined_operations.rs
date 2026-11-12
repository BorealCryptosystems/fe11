// SPDX-License-Identifier: Apache-2.0
//! CombinedOperations causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to combined operations.
#[doc = include_str!("../../../docs/diagnostics/busy-combined_operations.md")]
pub enum CombinedOperationsBusy {
    /// Recovery destination active. [Detection, owner and recovery](#cause-RecoveryDestinationActive).
    RecoveryDestinationActive,
}

impl std::fmt::Display for CombinedOperationsBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecoveryDestinationActive => f.write_str("recovery destination active"),
        }
    }
}
