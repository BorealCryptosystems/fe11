// SPDX-License-Identifier: Apache-2.0
//! Public ObjectCleanupBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, ObjectCleanupBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        ObjectCleanupBusy::CreatorMutation,
        ObjectCleanupBusy::ObjectCatalogue,
    ];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::ObjectCleanup(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Busy(BusyReason::ObjectCleanup(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
