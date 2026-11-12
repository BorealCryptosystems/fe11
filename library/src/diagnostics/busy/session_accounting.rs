// SPDX-License-Identifier: Apache-2.0
//! SessionAccounting causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to session accounting.
#[doc = include_str!("../../../docs/diagnostics/busy-session_accounting.md")]
pub enum SessionAccountingBusy {
    /// Session capacity. [Detection, owner and recovery](#cause-SessionCapacity).
    SessionCapacity,
    /// Session reservation or recovery active. [Detection, owner and recovery](#cause-SessionReservationOrRecoveryActive).
    SessionReservationOrRecoveryActive,
    /// Unpublished native session. [Detection, owner and recovery](#cause-UnpublishedNativeSession).
    UnpublishedNativeSession,
}

impl std::fmt::Display for SessionAccountingBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionCapacity => f.write_str("session capacity"),
            Self::SessionReservationOrRecoveryActive => {
                f.write_str("session reservation or recovery active")
            }
            Self::UnpublishedNativeSession => f.write_str("unpublished native session"),
        }
    }
}
