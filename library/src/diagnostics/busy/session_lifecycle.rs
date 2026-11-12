// SPDX-License-Identifier: Apache-2.0
//! SessionLifecycle causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to session lifecycle.
#[doc = include_str!("../../../docs/diagnostics/busy-session_lifecycle.md")]
pub enum SessionLifecycleBusy {
    /// Object search active. [Detection, owner and recovery](#cause-ObjectSearchActive).
    ObjectSearchActive,
    /// Session lifecycle diagnostic. [Detection, owner and recovery](#cause-SessionLifecycleDiagnostic).
    SessionLifecycleDiagnostic,
    /// Session transition. [Detection, owner and recovery](#cause-SessionTransition).
    SessionTransition,
}

impl std::fmt::Display for SessionLifecycleBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ObjectSearchActive => f.write_str("object search active"),
            Self::SessionLifecycleDiagnostic => f.write_str("session lifecycle diagnostic"),
            Self::SessionTransition => f.write_str("session transition"),
        }
    }
}
