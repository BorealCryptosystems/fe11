// SPDX-License-Identifier: Apache-2.0
//! Public ExternalExecutionBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, ExternalExecutionBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ExternalExecutionBusy::ForeignJoinSourceClaimed,
        ExternalExecutionBusy::ForeignCallbackActive,
        ExternalExecutionBusy::ForeignCallbackActiveOrClosing,
        ExternalExecutionBusy::ForeignCallbackAdmissionClosed,
        ExternalExecutionBusy::ForeignCollectiveCloseLacksTerminationContract,
        ExternalExecutionBusy::ForeignNativeExecutionUnresolved,
        ExternalExecutionBusy::ForeignNativeWorkUnresolved,
        ExternalExecutionBusy::ForeignOperationCallbackActive,
        ExternalExecutionBusy::ForeignSessionActivity,
        ExternalExecutionBusy::ForeignSessionCallbackActive,
        ExternalExecutionBusy::ForeignSessionCloseLacksTerminationContract,
        ExternalExecutionBusy::ForeignSessionExecutionActive,
        ExternalExecutionBusy::ForeignSessionNativeCallPending,
        ExternalExecutionBusy::ForeignSlotCallbackAdmissionClosed,
        ExternalExecutionBusy::ForeignTokenActivity,
        ExternalExecutionBusy::ForeignTokenCallbackActive,
        ExternalExecutionBusy::ForeignTokenExecutionUnresolved,
        ExternalExecutionBusy::ForeignTokenResourcesActive,
        ExternalExecutionBusy::LiveForeignTokenResourcesRequireCompletion,
        ExternalExecutionBusy::NativeLifecycleReentry,
        ExternalExecutionBusy::ReusedForeignExecutionUnresolved,
        ExternalExecutionBusy::ReusedForeignSessionCallbackActive,
        ExternalExecutionBusy::UnregisteredForeignNativeResourceRetained,
    ];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::ExternalExecution(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Busy(BusyReason::ExternalExecution(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
