// SPDX-License-Identifier: Apache-2.0
//! Public OperationOwnershipBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, OperationOwnershipBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        OperationOwnershipBusy::AdvancedFinalizationActivity,
        OperationOwnershipBusy::AdvancedNativeCompletionUnproven,
        OperationOwnershipBusy::AdvancedOperation,
        OperationOwnershipBusy::AdvancedRetirementActivity,
        OperationOwnershipBusy::AsynchronousJoinControl,
        OperationOwnershipBusy::LiveAdvancedTokenBinding,
        OperationOwnershipBusy::NativeOperationCallPending,
        OperationOwnershipBusy::OperationObservationInProgress,
        OperationOwnershipBusy::OperationStateControl,
    ];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::OperationOwnership(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Busy(BusyReason::OperationOwnership(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
