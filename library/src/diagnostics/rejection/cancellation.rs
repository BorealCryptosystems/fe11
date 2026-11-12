// SPDX-License-Identifier: Apache-2.0
//! Cancellation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to cancellation.
#[doc = include_str!("../../../docs/diagnostics/rejection-cancellation.md")]
pub enum CancellationRejection {
    /// C_SessionCancel unavailable. [Detection, owner and recovery](#cause-CSessionCancelUnavailable).
    CSessionCancelUnavailable,
    /// Cancellation absent. [Detection, owner and recovery](#cause-CancellationAbsent).
    CancellationAbsent,
    /// Cancellation control absent. [Detection, owner and recovery](#cause-CancellationControlAbsent).
    CancellationControlAbsent,
    /// Cancellation flag category. [Detection, owner and recovery](#cause-CancellationFlagCategory).
    CancellationFlagCategory,
    /// Cancellation flag range. [Detection, owner and recovery](#cause-CancellationFlagRange).
    CancellationFlagRange,
    /// Cancellation not pending. [Detection, owner and recovery](#cause-CancellationNotPending).
    CancellationNotPending,
    /// Cancellation return unproven. [Detection, owner and recovery](#cause-CancellationReturnUnproven).
    CancellationReturnUnproven,
}

impl std::fmt::Display for CancellationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CSessionCancelUnavailable => f.write_str("C_SessionCancel unavailable"),
            Self::CancellationAbsent => f.write_str("cancellation absent"),
            Self::CancellationControlAbsent => f.write_str("cancellation control absent"),
            Self::CancellationFlagCategory => f.write_str("cancellation flag category"),
            Self::CancellationFlagRange => f.write_str("cancellation flag range"),
            Self::CancellationNotPending => f.write_str("cancellation not pending"),
            Self::CancellationReturnUnproven => f.write_str("cancellation return unproven"),
        }
    }
}
