// SPDX-License-Identifier: Apache-2.0
//! ModuleLifecycle causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to module lifecycle.
#[doc = include_str!("../../../docs/diagnostics/busy-module_lifecycle.md")]
pub enum ModuleLifecycleBusy {
    /// Advanced token activity. [Detection, owner and recovery](#cause-AdvancedTokenActivity).
    AdvancedTokenActivity,
    /// Asynchronous session requires explicit close. [Detection, owner and recovery](#cause-AsynchronousSessionRequiresExplicitClose).
    AsynchronousSessionRequiresExplicitClose,
    /// Module finalization completion unproven. [Detection, owner and recovery](#cause-ModuleFinalizationCompletionUnproven).
    ModuleFinalizationCompletionUnproven,
    /// Native call completion unproven. [Detection, owner and recovery](#cause-NativeCallCompletionUnproven).
    NativeCallCompletionUnproven,
    /// Native recovery call pending. [Detection, owner and recovery](#cause-NativeRecoveryCallPending).
    NativeRecoveryCallPending,
    /// Native session call pending. [Detection, owner and recovery](#cause-NativeSessionCallPending).
    NativeSessionCallPending,
    /// Native token call pending. [Detection, owner and recovery](#cause-NativeTokenCallPending).
    NativeTokenCallPending,
    /// Session activity. [Detection, owner and recovery](#cause-SessionActivity).
    SessionActivity,
    /// Session close completion unproven. [Detection, owner and recovery](#cause-SessionCloseCompletionUnproven).
    SessionCloseCompletionUnproven,
    /// Session close pending. [Detection, owner and recovery](#cause-SessionClosePending).
    SessionClosePending,
    /// Token activity. [Detection, owner and recovery](#cause-TokenActivity).
    TokenActivity,
    /// Token activity during context authentication. [Detection, owner and recovery](#cause-TokenActivityDuringContextAuthentication).
    TokenActivityDuringContextAuthentication,
    /// Token activity during session close. [Detection, owner and recovery](#cause-TokenActivityDuringSessionClose).
    TokenActivityDuringSessionClose,
    /// Token administration. [Detection, owner and recovery](#cause-TokenAdministration).
    TokenAdministration,
    /// Token draining. [Detection, owner and recovery](#cause-TokenDraining).
    TokenDraining,
    /// Usable session prevents recovery finalization. [Detection, owner and recovery](#cause-UsableSessionPreventsRecoveryFinalization).
    UsableSessionPreventsRecoveryFinalization,
}

impl std::fmt::Display for ModuleLifecycleBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdvancedTokenActivity => f.write_str("advanced token activity"),
            Self::AsynchronousSessionRequiresExplicitClose => {
                f.write_str("asynchronous session requires explicit close")
            }
            Self::ModuleFinalizationCompletionUnproven => {
                f.write_str("module finalization completion unproven")
            }
            Self::NativeCallCompletionUnproven => f.write_str("native call completion unproven"),
            Self::NativeRecoveryCallPending => f.write_str("native recovery call pending"),
            Self::NativeSessionCallPending => f.write_str("native session call pending"),
            Self::NativeTokenCallPending => f.write_str("native token call pending"),
            Self::SessionActivity => f.write_str("session activity"),
            Self::SessionCloseCompletionUnproven => {
                f.write_str("session close completion unproven")
            }
            Self::SessionClosePending => f.write_str("session close pending"),
            Self::TokenActivity => f.write_str("token activity"),
            Self::TokenActivityDuringContextAuthentication => {
                f.write_str("token activity during context authentication")
            }
            Self::TokenActivityDuringSessionClose => {
                f.write_str("token activity during session close")
            }
            Self::TokenAdministration => f.write_str("token administration"),
            Self::TokenDraining => f.write_str("token draining"),
            Self::UsableSessionPreventsRecoveryFinalization => {
                f.write_str("usable session prevents recovery finalization")
            }
        }
    }
}
