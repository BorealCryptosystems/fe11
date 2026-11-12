// SPDX-License-Identifier: Apache-2.0
//! OperationOwnership causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to operation ownership.
#[doc = include_str!("../../../docs/diagnostics/busy-operation_ownership.md")]
pub enum OperationOwnershipBusy {
    /// Advanced finalization activity. [Detection, owner and recovery](#cause-AdvancedFinalizationActivity).
    AdvancedFinalizationActivity,
    /// Advanced native completion unproven. [Detection, owner and recovery](#cause-AdvancedNativeCompletionUnproven).
    AdvancedNativeCompletionUnproven,
    /// Advanced operation. [Detection, owner and recovery](#cause-AdvancedOperation).
    AdvancedOperation,
    /// Advanced retirement activity. [Detection, owner and recovery](#cause-AdvancedRetirementActivity).
    AdvancedRetirementActivity,
    /// Asynchronous join control. [Detection, owner and recovery](#cause-AsynchronousJoinControl).
    AsynchronousJoinControl,
    /// Live advanced token binding. [Detection, owner and recovery](#cause-LiveAdvancedTokenBinding).
    LiveAdvancedTokenBinding,
    /// Native operation call pending. [Detection, owner and recovery](#cause-NativeOperationCallPending).
    NativeOperationCallPending,
    /// Operation observation in progress. [Detection, owner and recovery](#cause-OperationObservationInProgress).
    OperationObservationInProgress,
    /// Operation state control. [Detection, owner and recovery](#cause-OperationStateControl).
    OperationStateControl,
}

impl std::fmt::Display for OperationOwnershipBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdvancedFinalizationActivity => f.write_str("advanced finalization activity"),
            Self::AdvancedNativeCompletionUnproven => {
                f.write_str("advanced native completion unproven")
            }
            Self::AdvancedOperation => f.write_str("advanced operation"),
            Self::AdvancedRetirementActivity => f.write_str("advanced retirement activity"),
            Self::AsynchronousJoinControl => f.write_str("asynchronous join control"),
            Self::LiveAdvancedTokenBinding => f.write_str("live advanced token binding"),
            Self::NativeOperationCallPending => f.write_str("native operation call pending"),
            Self::OperationObservationInProgress => {
                f.write_str("operation observation in progress")
            }
            Self::OperationStateControl => f.write_str("operation state control"),
        }
    }
}
