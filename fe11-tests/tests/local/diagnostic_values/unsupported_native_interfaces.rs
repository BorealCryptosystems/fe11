// SPDX-License-Identifier: Apache-2.0
//! Public NativeInterfacesUnsupported values retain identity through category conversion.
use fe11::{Error, NativeInterfacesUnsupported, UnsupportedReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [NativeInterfacesUnsupported::FunctionTableVersion];
    for value in cases {
        let category: UnsupportedReason = value.into();
        assert!(matches!(category, UnsupportedReason::NativeInterfaces(actual) if actual == value));
        let error = Error::Unsupported(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Unsupported(UnsupportedReason::NativeInterfaces(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
