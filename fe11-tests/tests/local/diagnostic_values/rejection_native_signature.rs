// SPDX-License-Identifier: Apache-2.0
//! Public NativeSignatureRejection values retain identity through category conversion.
use fe11::{Error, NativeSignatureRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeSignatureRejection::SignatureParameterScalarAbiWidth,
        NativeSignatureRejection::SingleVerificationRequiresOneInput,
        NativeSignatureRejection::SinglePartSignatureRequiresOneInput,
        NativeSignatureRejection::SinglePartVerificationRequiresOneInput,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeSignature(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeSignature(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
