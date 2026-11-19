// SPDX-License-Identifier: Apache-2.0
//! Public ModuleLifecycleBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, ModuleLifecycleBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ModuleLifecycleBusy::AdvancedTokenActivity,
        ModuleLifecycleBusy::AsynchronousSessionRequiresExplicitClose,
        ModuleLifecycleBusy::ModuleFinalizationCompletionUnproven,
        ModuleLifecycleBusy::NativeCallCompletionUnproven,
        ModuleLifecycleBusy::NativeRecoveryCallPending,
        ModuleLifecycleBusy::NativeSessionCallPending,
        ModuleLifecycleBusy::NativeTokenCallPending,
        ModuleLifecycleBusy::SessionActivity,
        ModuleLifecycleBusy::SessionCloseCompletionUnproven,
        ModuleLifecycleBusy::SessionClosePending,
        ModuleLifecycleBusy::TokenActivity,
        ModuleLifecycleBusy::TokenActivityDuringContextAuthentication,
        ModuleLifecycleBusy::TokenActivityDuringSessionClose,
        ModuleLifecycleBusy::TokenAdministration,
        ModuleLifecycleBusy::TokenDraining,
        ModuleLifecycleBusy::UsableSessionPreventsRecoveryFinalization,
    ];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::ModuleLifecycle(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Busy(BusyReason::ModuleLifecycle(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
