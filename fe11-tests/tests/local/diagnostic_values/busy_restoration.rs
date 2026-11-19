// SPDX-License-Identifier: Apache-2.0
//! Public RestorationBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, RestorationBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        RestorationBusy::DestinationOperationControlActive,
        RestorationBusy::RestorationControlActive,
        RestorationBusy::RestorationTransferActive,
    ];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::Restoration(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(matches!(&error, Error::Busy(BusyReason::Restoration(actual)) if *actual == value));
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
