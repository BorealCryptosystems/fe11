// SPDX-License-Identifier: Apache-2.0
//! Callbacks causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to callbacks.
#[doc = include_str!("../../../docs/diagnostics/rejection-callbacks.md")]
pub enum CallbacksRejection {
    /// Notification preparation consumed. [Detection, owner and recovery](#cause-NotificationPreparationConsumed).
    NotificationPreparationConsumed,
    /// Notification registry allocation. [Detection, owner and recovery](#cause-NotificationRegistryAllocation).
    NotificationRegistryAllocation,
    /// Notification registry count overflow. [Detection, owner and recovery](#cause-NotificationRegistryCountOverflow).
    NotificationRegistryCountOverflow,
    /// Notification registry storage overflow. [Detection, owner and recovery](#cause-NotificationRegistryStorageOverflow).
    NotificationRegistryStorageOverflow,
    /// Notification registry withdrawn. [Detection, owner and recovery](#cause-NotificationRegistryWithdrawn).
    NotificationRegistryWithdrawn,
    /// Notification retained storage overflow. [Detection, owner and recovery](#cause-NotificationRetainedStorageOverflow).
    NotificationRetainedStorageOverflow,
    /// Notification session binding. [Detection, owner and recovery](#cause-NotificationSessionBinding).
    NotificationSessionBinding,
}

impl std::fmt::Display for CallbacksRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotificationPreparationConsumed => {
                f.write_str("notification preparation consumed")
            }
            Self::NotificationRegistryAllocation => f.write_str("notification registry allocation"),
            Self::NotificationRegistryCountOverflow => {
                f.write_str("notification registry count overflow")
            }
            Self::NotificationRegistryStorageOverflow => {
                f.write_str("notification registry storage overflow")
            }
            Self::NotificationRegistryWithdrawn => f.write_str("notification registry withdrawn"),
            Self::NotificationRetainedStorageOverflow => {
                f.write_str("notification retained storage overflow")
            }
            Self::NotificationSessionBinding => f.write_str("notification session binding"),
        }
    }
}
