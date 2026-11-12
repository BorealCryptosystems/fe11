// SPDX-License-Identifier: Apache-2.0
//! Diagnostics causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to diagnostics.
#[doc = include_str!("../../../docs/diagnostics/rejection-diagnostics.md")]
pub enum DiagnosticsRejection {
    /// Cleanup cause not used. [Detection, owner and recovery](#cause-CleanupCauseNotUsed).
    CleanupCauseNotUsed,
    /// Cleanup failure not used. [Detection, owner and recovery](#cause-CleanupFailureNotUsed).
    CleanupFailureNotUsed,
    /// Cleanup marker allocation. [Detection, owner and recovery](#cause-CleanupMarkerAllocation).
    CleanupMarkerAllocation,
    /// Cleanup marker not used. [Detection, owner and recovery](#cause-CleanupMarkerNotUsed).
    CleanupMarkerNotUsed,
    /// Cleanup not dispatched. [Detection, owner and recovery](#cause-CleanupNotDispatched).
    CleanupNotDispatched,
    /// Cleanup storage accounting. [Detection, owner and recovery](#cause-CleanupStorageAccounting).
    CleanupStorageAccounting,
    /// Completion diagnostic already consumed. [Detection, owner and recovery](#cause-CompletionDiagnosticAlreadyConsumed).
    CompletionDiagnosticAlreadyConsumed,
    /// Completion diagnostic not used. [Detection, owner and recovery](#cause-CompletionDiagnosticNotUsed).
    CompletionDiagnosticNotUsed,
    /// Completion storage already consumed. [Detection, owner and recovery](#cause-CompletionStorageAlreadyConsumed).
    CompletionStorageAlreadyConsumed,
    /// Primary failure not used. [Detection, owner and recovery](#cause-PrimaryFailureNotUsed).
    PrimaryFailureNotUsed,
    /// Secondary failure not used. [Detection, owner and recovery](#cause-SecondaryFailureNotUsed).
    SecondaryFailureNotUsed,
    /// Sequence cause not used. [Detection, owner and recovery](#cause-SequenceCauseNotUsed).
    SequenceCauseNotUsed,
}

impl std::fmt::Display for DiagnosticsRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CleanupCauseNotUsed => f.write_str("cleanup cause not used"),
            Self::CleanupFailureNotUsed => f.write_str("cleanup failure not used"),
            Self::CleanupMarkerAllocation => f.write_str("cleanup marker allocation"),
            Self::CleanupMarkerNotUsed => f.write_str("cleanup marker not used"),
            Self::CleanupNotDispatched => f.write_str("cleanup not dispatched"),
            Self::CleanupStorageAccounting => f.write_str("cleanup storage accounting"),
            Self::CompletionDiagnosticAlreadyConsumed => {
                f.write_str("completion diagnostic already consumed")
            }
            Self::CompletionDiagnosticNotUsed => f.write_str("completion diagnostic not used"),
            Self::CompletionStorageAlreadyConsumed => {
                f.write_str("completion storage already consumed")
            }
            Self::PrimaryFailureNotUsed => f.write_str("primary failure not used"),
            Self::SecondaryFailureNotUsed => f.write_str("secondary failure not used"),
            Self::SequenceCauseNotUsed => f.write_str("sequence cause not used"),
        }
    }
}
