// SPDX-License-Identifier: Apache-2.0
//! Public MechanismExtensionsUnsupported values retain identity through category conversion.
use fe11::{Error, MechanismExtensionsUnsupported, UnsupportedReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [MechanismExtensionsUnsupported::ExtensionNativeFunctionTuple];
    for value in cases {
        let category: UnsupportedReason = value.into();
        assert!(
            matches!(category, UnsupportedReason::MechanismExtensions(actual) if actual == value)
        );
        let error = Error::Unsupported(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Unsupported(UnsupportedReason::MechanismExtensions(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
