// SPDX-License-Identifier: Apache-2.0
//! LLP64 must reject high bits rather than aliasing a standard identifier.
use fe11::*;

#[test]
fn standard_attribute_lookup_does_not_truncate_unknown_high_bits() {
    assert_eq!(
        StandardAttribute::from_identifier(0),
        Some(StandardAttribute::CLASS)
    );
    assert_eq!(
        StandardAttribute::from_identifier(1),
        Some(StandardAttribute::TOKEN)
    );
    for value in [u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        assert_eq!(StandardAttribute::from_identifier(value), None);
    }
    assert_eq!(
        StandardAttribute::from_identifier(0),
        Some(StandardAttribute::CLASS)
    );
}

#[test]
fn object_class_lookup_does_not_truncate_to_data() {
    assert_eq!(ManagedClass::from_identifier(0), Some(ManagedClass::Data));
    assert_eq!(
        ManagedClass::from_identifier(1),
        Some(ManagedClass::Certificate)
    );
    for value in [u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        assert_eq!(ManagedClass::from_identifier(value), None);
    }
    assert_eq!(ManagedClass::from_identifier(0), Some(ManagedClass::Data));
}

#[test]
fn digest_lookup_does_not_promote_non_digest_or_unknown_identifiers() {
    let sha256 = fe11_sys::CKM_SHA256 as u64;
    assert_eq!(
        NativeDigestAlgorithm::from_mechanism(sha256),
        Some(NativeDigestAlgorithm::Sha256)
    );
    // 0/1 name RSA mechanisms, not digest selectors. The high values are not
    // standard digest identities, even on platforms whose CK_ULONG fits them.
    for value in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        assert_eq!(NativeDigestAlgorithm::from_mechanism(value), None);
    }
    assert_eq!(
        NativeDigestAlgorithm::from_mechanism(sha256),
        Some(NativeDigestAlgorithm::Sha256)
    );
}

#[test]
fn cancellation_mixed_bits_distinguish_category_and_native_width() {
    for value in [1, u32::MAX as u64, u32::MAX as u64 + 1] {
        let expected = if value > fe11_sys::CK_FLAGS::MAX as u64 {
            CancellationRejection::CancellationFlagRange
        } else {
            CancellationRejection::CancellationFlagCategory
        };
        assert!(matches!(CancellationFlags::from_bits(value),
            Err(Error::Rejected(RejectionReason::Cancellation(actual))) if actual == expected));
    }
    assert_eq!(CancellationFlags::from_bits(0).unwrap().bits(), 0);
}
