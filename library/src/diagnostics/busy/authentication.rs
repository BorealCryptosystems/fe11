// SPDX-License-Identifier: Apache-2.0
//! Authentication causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to authentication.
#[doc = include_str!("../../../docs/diagnostics/busy-authentication.md")]
pub enum AuthenticationBusy {
    /// Operation control in progress. [Detection, owner and recovery](#cause-OperationControlInProgress).
    OperationControlInProgress,
}

impl std::fmt::Display for AuthenticationBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OperationControlInProgress => f.write_str("operation control in progress"),
        }
    }
}
