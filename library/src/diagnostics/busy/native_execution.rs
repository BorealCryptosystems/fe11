// SPDX-License-Identifier: Apache-2.0
//! NativeExecution causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native execution.
#[doc = include_str!("../../../docs/diagnostics/busy-native_execution.md")]
pub enum NativeExecutionBusy {
    /// Notification callback. [Detection, owner and recovery](#cause-NotificationCallback).
    NotificationCallback,
    /// Runtime native completion unproven. [Detection, owner and recovery](#cause-RuntimeNativeCompletionUnproven).
    RuntimeNativeCompletionUnproven,
    /// Runtime waiter or finalization unresolved. [Detection, owner and recovery](#cause-RuntimeWaiterOrFinalizationUnresolved).
    RuntimeWaiterOrFinalizationUnresolved,
    /// Serialized blocking slot event. [Detection, owner and recovery](#cause-SerializedBlockingSlotEvent).
    SerializedBlockingSlotEvent,
    /// Serialized module closing. [Detection, owner and recovery](#cause-SerializedModuleClosing).
    SerializedModuleClosing,
    /// Serialized module dispatch. [Detection, owner and recovery](#cause-SerializedModuleDispatch).
    SerializedModuleDispatch,
    /// Serialized module event admission. [Detection, owner and recovery](#cause-SerializedModuleEventAdmission).
    SerializedModuleEventAdmission,
    /// Serialized native callback. [Detection, owner and recovery](#cause-SerializedNativeCallback).
    SerializedNativeCallback,
    /// Slot event completion unproven. [Detection, owner and recovery](#cause-SlotEventCompletionUnproven).
    SlotEventCompletionUnproven,
    /// Slot event lifecycle unresolved. [Detection, owner and recovery](#cause-SlotEventLifecycleUnresolved).
    SlotEventLifecycleUnresolved,
    /// Slot event polling. [Detection, owner and recovery](#cause-SlotEventPolling).
    SlotEventPolling,
    /// Slot event request active. [Detection, owner and recovery](#cause-SlotEventRequestActive).
    SlotEventRequestActive,
    /// Slot event source in use. [Detection, owner and recovery](#cause-SlotEventSourceInUse).
    SlotEventSourceInUse,
}

impl std::fmt::Display for NativeExecutionBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotificationCallback => f.write_str("notification callback"),
            Self::RuntimeNativeCompletionUnproven => {
                f.write_str("runtime native completion unproven")
            }
            Self::RuntimeWaiterOrFinalizationUnresolved => {
                f.write_str("runtime waiter or finalization unresolved")
            }
            Self::SerializedBlockingSlotEvent => f.write_str("serialized blocking slot event"),
            Self::SerializedModuleClosing => f.write_str("serialized module closing"),
            Self::SerializedModuleDispatch => f.write_str("serialized module dispatch"),
            Self::SerializedModuleEventAdmission => {
                f.write_str("serialized module event admission")
            }
            Self::SerializedNativeCallback => f.write_str("serialized native callback"),
            Self::SlotEventCompletionUnproven => f.write_str("slot event completion unproven"),
            Self::SlotEventLifecycleUnresolved => f.write_str("slot event lifecycle unresolved"),
            Self::SlotEventPolling => f.write_str("slot event polling"),
            Self::SlotEventRequestActive => f.write_str("slot event request active"),
            Self::SlotEventSourceInUse => f.write_str("slot event source in use"),
        }
    }
}
