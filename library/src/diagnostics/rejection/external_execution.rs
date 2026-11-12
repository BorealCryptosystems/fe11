// SPDX-License-Identifier: Apache-2.0
//! ExternalExecution causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to external execution.
#[doc = include_str!("../../../docs/diagnostics/rejection-external_execution.md")]
pub enum ExternalExecutionRejection {
    /// Foreign Join owner mismatch. [Detection, owner and recovery](#cause-ForeignJoinOwnerMismatch).
    ForeignJoinOwnerMismatch,
    /// Foreign Join source missing. [Detection, owner and recovery](#cause-ForeignJoinSourceMissing).
    ForeignJoinSourceMissing,
    /// Foreign Join source not detached. [Detection, owner and recovery](#cause-ForeignJoinSourceNotDetached).
    ForeignJoinSourceNotDetached,
    /// Foreign adopted progress mismatch. [Detection, owner and recovery](#cause-ForeignAdoptedProgressMismatch).
    ForeignAdoptedProgressMismatch,
    /// Foreign call already dispatched. [Detection, owner and recovery](#cause-ForeignCallAlreadyDispatched).
    ForeignCallAlreadyDispatched,
    /// Foreign call reservation changed. [Detection, owner and recovery](#cause-ForeignCallReservationChanged).
    ForeignCallReservationChanged,
    /// Foreign call scope allocation. [Detection, owner and recovery](#cause-ForeignCallScopeAllocation).
    ForeignCallScopeAllocation,
    /// Foreign callback count. [Detection, owner and recovery](#cause-ForeignCallbackCount).
    ForeignCallbackCount,
    /// Foreign callback count exhausted. [Detection, owner and recovery](#cause-ForeignCallbackCountExhausted).
    ForeignCallbackCountExhausted,
    /// Foreign callback graph retired. [Detection, owner and recovery](#cause-ForeignCallbackGraphRetired).
    ForeignCallbackGraphRetired,
    /// Foreign callback scope allocation. [Detection, owner and recovery](#cause-ForeignCallbackScopeAllocation).
    ForeignCallbackScopeAllocation,
    /// Foreign close session owner. [Detection, owner and recovery](#cause-ForeignCloseSessionOwner).
    ForeignCloseSessionOwner,
    /// Foreign close session owner required. [Detection, owner and recovery](#cause-ForeignCloseSessionOwnerRequired).
    ForeignCloseSessionOwnerRequired,
    /// Foreign collection allocation. [Detection, owner and recovery](#cause-ForeignCollectionAllocation).
    ForeignCollectionAllocation,
    /// Foreign draining runtime. [Detection, owner and recovery](#cause-ForeignDrainingRuntime).
    ForeignDrainingRuntime,
    /// Foreign draining slot. [Detection, owner and recovery](#cause-ForeignDrainingSlot).
    ForeignDrainingSlot,
    /// Foreign event already issued. [Detection, owner and recovery](#cause-ForeignEventAlreadyIssued).
    ForeignEventAlreadyIssued,
    /// Foreign event code conversion. [Detection, owner and recovery](#cause-ForeignEventCodeConversion).
    ForeignEventCodeConversion,
    /// Foreign event completion unproven. [Detection, owner and recovery](#cause-ForeignEventCompletionUnproven).
    ForeignEventCompletionUnproven,
    /// Foreign event not dispatched. [Detection, owner and recovery](#cause-ForeignEventNotDispatched).
    ForeignEventNotDispatched,
    /// Foreign event runtime mismatch. [Detection, owner and recovery](#cause-ForeignEventRuntimeMismatch).
    ForeignEventRuntimeMismatch,
    /// Foreign event slot conversion. [Detection, owner and recovery](#cause-ForeignEventSlotConversion).
    ForeignEventSlotConversion,
    /// Foreign graph retired. [Detection, owner and recovery](#cause-ForeignGraphRetired).
    ForeignGraphRetired,
    /// Foreign initialization finalized. [Detection, owner and recovery](#cause-ForeignInitializationFinalized).
    ForeignInitializationFinalized,
    /// Foreign native context retired. [Detection, owner and recovery](#cause-ForeignNativeContextRetired).
    ForeignNativeContextRetired,
    /// Foreign native return without matching dispatch. [Detection, owner and recovery](#cause-ForeignNativeReturnWithoutMatchingDispatch).
    ForeignNativeReturnWithoutMatchingDispatch,
    /// Foreign native session handle reused. [Detection, owner and recovery](#cause-ForeignNativeSessionHandleReused).
    ForeignNativeSessionHandleReused,
    /// Foreign open session owner required. [Detection, owner and recovery](#cause-ForeignOpenSessionOwnerRequired).
    ForeignOpenSessionOwnerRequired,
    /// Foreign open session receipt required. [Detection, owner and recovery](#cause-ForeignOpenSessionReceiptRequired).
    ForeignOpenSessionReceiptRequired,
    /// Foreign open without dispatch. [Detection, owner and recovery](#cause-ForeignOpenWithoutDispatch).
    ForeignOpenWithoutDispatch,
    /// Foreign operation session mismatch. [Detection, owner and recovery](#cause-ForeignOperationSessionMismatch).
    ForeignOperationSessionMismatch,
    /// Foreign participant allocation. [Detection, owner and recovery](#cause-ForeignParticipantAllocation).
    ForeignParticipantAllocation,
    /// Foreign participant retired. [Detection, owner and recovery](#cause-ForeignParticipantRetired).
    ForeignParticipantRetired,
    /// Foreign retirement allocation. [Detection, owner and recovery](#cause-ForeignRetirementAllocation).
    ForeignRetirementAllocation,
    /// Foreign retirement capacity changed. [Detection, owner and recovery](#cause-ForeignRetirementCapacityChanged).
    ForeignRetirementCapacityChanged,
    /// Foreign return code conversion. [Detection, owner and recovery](#cause-ForeignReturnCodeConversion).
    ForeignReturnCodeConversion,
    /// Foreign return does not prove declared completion. [Detection, owner and recovery](#cause-ForeignReturnDoesNotProveDeclaredCompletion).
    ForeignReturnDoesNotProveDeclaredCompletion,
    /// Foreign runtime retired. [Detection, owner and recovery](#cause-ForeignRuntimeRetired).
    ForeignRuntimeRetired,
    /// Foreign session already registered. [Detection, owner and recovery](#cause-ForeignSessionAlreadyRegistered).
    ForeignSessionAlreadyRegistered,
    /// Foreign session handle conversion. [Detection, owner and recovery](#cause-ForeignSessionHandleConversion).
    ForeignSessionHandleConversion,
    /// Foreign session handle invalid. [Detection, owner and recovery](#cause-ForeignSessionHandleInvalid).
    ForeignSessionHandleInvalid,
    /// Foreign session owner required. [Detection, owner and recovery](#cause-ForeignSessionOwnerRequired).
    ForeignSessionOwnerRequired,
    /// Foreign session retired. [Detection, owner and recovery](#cause-ForeignSessionRetired).
    ForeignSessionRetired,
    /// Foreign sessions active. [Detection, owner and recovery](#cause-ForeignSessionsActive).
    ForeignSessionsActive,
    /// Foreign slot conversion. [Detection, owner and recovery](#cause-ForeignSlotConversion).
    ForeignSlotConversion,
    /// Foreign slot registry allocation. [Detection, owner and recovery](#cause-ForeignSlotRegistryAllocation).
    ForeignSlotRegistryAllocation,
    /// Foreign work registry allocation. [Detection, owner and recovery](#cause-ForeignWorkRegistryAllocation).
    ForeignWorkRegistryAllocation,
    /// Foreign work step not admitted. [Detection, owner and recovery](#cause-ForeignWorkStepNotAdmitted).
    ForeignWorkStepNotAdmitted,
}

impl std::fmt::Display for ExternalExecutionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignJoinOwnerMismatch => f.write_str("foreign Join owner mismatch"),
            Self::ForeignJoinSourceMissing => f.write_str("foreign Join source missing"),
            Self::ForeignJoinSourceNotDetached => f.write_str("foreign Join source not detached"),
            Self::ForeignAdoptedProgressMismatch => {
                f.write_str("foreign adopted progress mismatch")
            }
            Self::ForeignCallAlreadyDispatched => f.write_str("foreign call already dispatched"),
            Self::ForeignCallReservationChanged => f.write_str("foreign call reservation changed"),
            Self::ForeignCallScopeAllocation => f.write_str("foreign call scope allocation"),
            Self::ForeignCallbackCount => f.write_str("foreign callback count"),
            Self::ForeignCallbackCountExhausted => f.write_str("foreign callback count exhausted"),
            Self::ForeignCallbackGraphRetired => f.write_str("foreign callback graph retired"),
            Self::ForeignCallbackScopeAllocation => {
                f.write_str("foreign callback scope allocation")
            }
            Self::ForeignCloseSessionOwner => f.write_str("foreign close session owner"),
            Self::ForeignCloseSessionOwnerRequired => {
                f.write_str("foreign close session owner required")
            }
            Self::ForeignCollectionAllocation => f.write_str("foreign collection allocation"),
            Self::ForeignDrainingRuntime => f.write_str("foreign draining runtime"),
            Self::ForeignDrainingSlot => f.write_str("foreign draining slot"),
            Self::ForeignEventAlreadyIssued => f.write_str("foreign event already issued"),
            Self::ForeignEventCodeConversion => f.write_str("foreign event code conversion"),
            Self::ForeignEventCompletionUnproven => {
                f.write_str("foreign event completion unproven")
            }
            Self::ForeignEventNotDispatched => f.write_str("foreign event not dispatched"),
            Self::ForeignEventRuntimeMismatch => f.write_str("foreign event runtime mismatch"),
            Self::ForeignEventSlotConversion => f.write_str("foreign event slot conversion"),
            Self::ForeignGraphRetired => f.write_str("foreign graph retired"),
            Self::ForeignInitializationFinalized => f.write_str("foreign initialization finalized"),
            Self::ForeignNativeContextRetired => f.write_str("foreign native context retired"),
            Self::ForeignNativeReturnWithoutMatchingDispatch => {
                f.write_str("foreign native return without matching dispatch")
            }
            Self::ForeignNativeSessionHandleReused => {
                f.write_str("foreign native session handle reused")
            }
            Self::ForeignOpenSessionOwnerRequired => {
                f.write_str("foreign open session owner required")
            }
            Self::ForeignOpenSessionReceiptRequired => {
                f.write_str("foreign open session receipt required")
            }
            Self::ForeignOpenWithoutDispatch => f.write_str("foreign open without dispatch"),
            Self::ForeignOperationSessionMismatch => {
                f.write_str("foreign operation session mismatch")
            }
            Self::ForeignParticipantAllocation => f.write_str("foreign participant allocation"),
            Self::ForeignParticipantRetired => f.write_str("foreign participant retired"),
            Self::ForeignRetirementAllocation => f.write_str("foreign retirement allocation"),
            Self::ForeignRetirementCapacityChanged => {
                f.write_str("foreign retirement capacity changed")
            }
            Self::ForeignReturnCodeConversion => f.write_str("foreign return code conversion"),
            Self::ForeignReturnDoesNotProveDeclaredCompletion => {
                f.write_str("foreign return does not prove declared completion")
            }
            Self::ForeignRuntimeRetired => f.write_str("foreign runtime retired"),
            Self::ForeignSessionAlreadyRegistered => {
                f.write_str("foreign session already registered")
            }
            Self::ForeignSessionHandleConversion => {
                f.write_str("foreign session handle conversion")
            }
            Self::ForeignSessionHandleInvalid => f.write_str("foreign session handle invalid"),
            Self::ForeignSessionOwnerRequired => f.write_str("foreign session owner required"),
            Self::ForeignSessionRetired => f.write_str("foreign session retired"),
            Self::ForeignSessionsActive => f.write_str("foreign sessions active"),
            Self::ForeignSlotConversion => f.write_str("foreign slot conversion"),
            Self::ForeignSlotRegistryAllocation => f.write_str("foreign slot registry allocation"),
            Self::ForeignWorkRegistryAllocation => f.write_str("foreign work registry allocation"),
            Self::ForeignWorkStepNotAdmitted => f.write_str("foreign work step not admitted"),
        }
    }
}
