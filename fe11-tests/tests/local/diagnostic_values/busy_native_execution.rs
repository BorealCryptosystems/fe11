// SPDX-License-Identifier: Apache-2.0
//! Public NativeExecutionBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, NativeExecutionBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeExecutionBusy::NotificationCallback,
        NativeExecutionBusy::RuntimeNativeCompletionUnproven,
        NativeExecutionBusy::RuntimeWaiterOrFinalizationUnresolved,
        NativeExecutionBusy::SerializedBlockingSlotEvent,
        NativeExecutionBusy::SerializedModuleClosing,
        NativeExecutionBusy::SerializedModuleDispatch,
        NativeExecutionBusy::SerializedModuleEventAdmission,
        NativeExecutionBusy::SerializedNativeCallback,
        NativeExecutionBusy::SlotEventCompletionUnproven,
        NativeExecutionBusy::SlotEventLifecycleUnresolved,
        NativeExecutionBusy::SlotEventPolling,
        NativeExecutionBusy::SlotEventRequestActive,
        NativeExecutionBusy::SlotEventSourceInUse,
    ];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::NativeExecution(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Busy(BusyReason::NativeExecution(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
