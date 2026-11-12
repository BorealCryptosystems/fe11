// SPDX-License-Identifier: Apache-2.0
//! ExternalExecution causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to external execution.
#[doc = include_str!("../../../docs/diagnostics/busy-external_execution.md")]
pub enum ExternalExecutionBusy {
    /// Foreign Join source claimed. [Detection, owner and recovery](#cause-ForeignJoinSourceClaimed).
    ForeignJoinSourceClaimed,
    /// Foreign callback active. [Detection, owner and recovery](#cause-ForeignCallbackActive).
    ForeignCallbackActive,
    /// Foreign callback active or closing. [Detection, owner and recovery](#cause-ForeignCallbackActiveOrClosing).
    ForeignCallbackActiveOrClosing,
    /// Foreign callback admission closed. [Detection, owner and recovery](#cause-ForeignCallbackAdmissionClosed).
    ForeignCallbackAdmissionClosed,
    /// Foreign collective close lacks termination contract. [Detection, owner and recovery](#cause-ForeignCollectiveCloseLacksTerminationContract).
    ForeignCollectiveCloseLacksTerminationContract,
    /// Foreign native execution unresolved. [Detection, owner and recovery](#cause-ForeignNativeExecutionUnresolved).
    ForeignNativeExecutionUnresolved,
    /// Foreign native work unresolved. [Detection, owner and recovery](#cause-ForeignNativeWorkUnresolved).
    ForeignNativeWorkUnresolved,
    /// Foreign operation callback active. [Detection, owner and recovery](#cause-ForeignOperationCallbackActive).
    ForeignOperationCallbackActive,
    /// Foreign session activity. [Detection, owner and recovery](#cause-ForeignSessionActivity).
    ForeignSessionActivity,
    /// Foreign session callback active. [Detection, owner and recovery](#cause-ForeignSessionCallbackActive).
    ForeignSessionCallbackActive,
    /// Foreign session close lacks termination contract. [Detection, owner and recovery](#cause-ForeignSessionCloseLacksTerminationContract).
    ForeignSessionCloseLacksTerminationContract,
    /// Foreign session execution active. [Detection, owner and recovery](#cause-ForeignSessionExecutionActive).
    ForeignSessionExecutionActive,
    /// Foreign session native call pending. [Detection, owner and recovery](#cause-ForeignSessionNativeCallPending).
    ForeignSessionNativeCallPending,
    /// Foreign slot callback admission closed. [Detection, owner and recovery](#cause-ForeignSlotCallbackAdmissionClosed).
    ForeignSlotCallbackAdmissionClosed,
    /// Foreign token activity. [Detection, owner and recovery](#cause-ForeignTokenActivity).
    ForeignTokenActivity,
    /// Foreign token callback active. [Detection, owner and recovery](#cause-ForeignTokenCallbackActive).
    ForeignTokenCallbackActive,
    /// Foreign token execution unresolved. [Detection, owner and recovery](#cause-ForeignTokenExecutionUnresolved).
    ForeignTokenExecutionUnresolved,
    /// Foreign token resources active. [Detection, owner and recovery](#cause-ForeignTokenResourcesActive).
    ForeignTokenResourcesActive,
    /// Live foreign token resources require completion. [Detection, owner and recovery](#cause-LiveForeignTokenResourcesRequireCompletion).
    LiveForeignTokenResourcesRequireCompletion,
    /// Native lifecycle reentry. [Detection, owner and recovery](#cause-NativeLifecycleReentry).
    NativeLifecycleReentry,
    /// Reused foreign execution unresolved. [Detection, owner and recovery](#cause-ReusedForeignExecutionUnresolved).
    ReusedForeignExecutionUnresolved,
    /// Reused foreign session callback active. [Detection, owner and recovery](#cause-ReusedForeignSessionCallbackActive).
    ReusedForeignSessionCallbackActive,
    /// Unregistered foreign native resource retained. [Detection, owner and recovery](#cause-UnregisteredForeignNativeResourceRetained).
    UnregisteredForeignNativeResourceRetained,
}

impl std::fmt::Display for ExternalExecutionBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignJoinSourceClaimed => f.write_str("foreign Join source claimed"),
            Self::ForeignCallbackActive => f.write_str("foreign callback active"),
            Self::ForeignCallbackActiveOrClosing => {
                f.write_str("foreign callback active or closing")
            }
            Self::ForeignCallbackAdmissionClosed => {
                f.write_str("foreign callback admission closed")
            }
            Self::ForeignCollectiveCloseLacksTerminationContract => {
                f.write_str("foreign collective close lacks termination contract")
            }
            Self::ForeignNativeExecutionUnresolved => {
                f.write_str("foreign native execution unresolved")
            }
            Self::ForeignNativeWorkUnresolved => f.write_str("foreign native work unresolved"),
            Self::ForeignOperationCallbackActive => {
                f.write_str("foreign operation callback active")
            }
            Self::ForeignSessionActivity => f.write_str("foreign session activity"),
            Self::ForeignSessionCallbackActive => f.write_str("foreign session callback active"),
            Self::ForeignSessionCloseLacksTerminationContract => {
                f.write_str("foreign session close lacks termination contract")
            }
            Self::ForeignSessionExecutionActive => f.write_str("foreign session execution active"),
            Self::ForeignSessionNativeCallPending => {
                f.write_str("foreign session native call pending")
            }
            Self::ForeignSlotCallbackAdmissionClosed => {
                f.write_str("foreign slot callback admission closed")
            }
            Self::ForeignTokenActivity => f.write_str("foreign token activity"),
            Self::ForeignTokenCallbackActive => f.write_str("foreign token callback active"),
            Self::ForeignTokenExecutionUnresolved => {
                f.write_str("foreign token execution unresolved")
            }
            Self::ForeignTokenResourcesActive => f.write_str("foreign token resources active"),
            Self::LiveForeignTokenResourcesRequireCompletion => {
                f.write_str("live foreign token resources require completion")
            }
            Self::NativeLifecycleReentry => f.write_str("native lifecycle reentry"),
            Self::ReusedForeignExecutionUnresolved => {
                f.write_str("reused foreign execution unresolved")
            }
            Self::ReusedForeignSessionCallbackActive => {
                f.write_str("reused foreign session callback active")
            }
            Self::UnregisteredForeignNativeResourceRetained => {
                f.write_str("unregistered foreign native resource retained")
            }
        }
    }
}
