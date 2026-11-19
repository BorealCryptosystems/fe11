// SPDX-License-Identifier: Apache-2.0
//! Public SignatureMessagesBusy values retain identity through category conversion.
use fe11::{BusyReason, Error, SignatureMessagesBusy};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [SignatureMessagesBusy::MessageSignatureControlChanged];
    for value in cases {
        let category: BusyReason = value.into();
        assert!(matches!(category, BusyReason::SignatureMessages(actual) if actual == value));
        let error = Error::Busy(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Busy(BusyReason::SignatureMessages(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
