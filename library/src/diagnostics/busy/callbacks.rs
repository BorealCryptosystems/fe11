// SPDX-License-Identifier: Apache-2.0
//! Callbacks causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to callbacks.
#[doc = include_str!("../../../docs/diagnostics/busy-callbacks.md")]
pub enum CallbacksBusy {
    /// Notification registry capacity. [Detection, owner and recovery](#cause-NotificationRegistryCapacity).
    NotificationRegistryCapacity,
}

impl std::fmt::Display for CallbacksBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotificationRegistryCapacity => f.write_str("notification registry capacity"),
        }
    }
}
