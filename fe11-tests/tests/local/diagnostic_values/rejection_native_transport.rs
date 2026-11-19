// SPDX-License-Identifier: Apache-2.0
//! Public NativeTransportRejection values retain identity through category conversion.
use fe11::{Error, NativeTransportRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeTransportRejection::SkipjackSharedPGExtent,
        NativeTransportRejection::HistoricalTransportMechanismLayoutMismatch,
        NativeTransportRejection::TransportFixedParameterExtent,
        NativeTransportRejection::TransportScalarAbiWidth,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeTransport(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeTransport(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
