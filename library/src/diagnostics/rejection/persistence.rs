// SPDX-License-Identifier: Apache-2.0
//! Persistence causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to persistence.
#[doc = include_str!("../../../docs/diagnostics/rejection-persistence.md")]
pub enum PersistenceRejection {
    /// Asynchronous rejoin session mode. [Detection, owner and recovery](#cause-AsynchronousRejoinSessionMode).
    AsynchronousRejoinSessionMode,
    /// Captured module no longer owned. [Detection, owner and recovery](#cause-CapturedModuleNoLongerOwned).
    CapturedModuleNoLongerOwned,
    /// Captured native state absent. [Detection, owner and recovery](#cause-CapturedNativeStateAbsent).
    CapturedNativeStateAbsent,
    /// Detached record kind. [Detection, owner and recovery](#cause-DetachedRecordKind).
    DetachedRecordKind,
    /// Import native storage absent. [Detection, owner and recovery](#cause-ImportNativeStorageAbsent).
    ImportNativeStorageAbsent,
    /// Native message destination required. [Detection, owner and recovery](#cause-NativeMessageDestinationRequired).
    NativeMessageDestinationRequired,
    /// Unsupported authenticated record kind. [Detection, owner and recovery](#cause-UnsupportedAuthenticatedRecordKind).
    UnsupportedAuthenticatedRecordKind,
}

impl std::fmt::Display for PersistenceRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsynchronousRejoinSessionMode => f.write_str("asynchronous rejoin session mode"),
            Self::CapturedModuleNoLongerOwned => f.write_str("captured module no longer owned"),
            Self::CapturedNativeStateAbsent => f.write_str("captured native state absent"),
            Self::DetachedRecordKind => f.write_str("detached record kind"),
            Self::ImportNativeStorageAbsent => f.write_str("import native storage absent"),
            Self::NativeMessageDestinationRequired => {
                f.write_str("native message destination required")
            }
            Self::UnsupportedAuthenticatedRecordKind => {
                f.write_str("unsupported authenticated record kind")
            }
        }
    }
}
