// SPDX-License-Identifier: Apache-2.0
//! Public NativeMessagesUnsupported values retain identity through category conversion.
use fe11::{Error, NativeMessagesUnsupported, UnsupportedReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeMessagesUnsupported::MessageInterface,
        NativeMessagesUnsupported::MessageSignatureFunctionTuple,
    ];
    for value in cases {
        let category: UnsupportedReason = value.into();
        assert!(matches!(category, UnsupportedReason::NativeMessages(actual) if actual == value));
        let error = Error::Unsupported(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Unsupported(UnsupportedReason::NativeMessages(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
