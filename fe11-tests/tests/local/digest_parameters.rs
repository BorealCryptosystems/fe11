// SPDX-License-Identifier: Apache-2.0
//! Public constructor boundaries and owned-value observations.
use fe11::*;

#[test]
fn digest_truncation_0() {
    let bits = 0_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 0_usize);
    }
}

#[test]
fn digest_truncation_1() {
    let bits = 1_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 1_usize);
    }
}

#[test]
fn digest_truncation_7() {
    let bits = 7_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 1_usize);
    }
}

#[test]
fn digest_truncation_8() {
    let bits = 8_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 1_usize);
    }
}

#[test]
fn digest_truncation_9() {
    let bits = 9_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 2_usize);
    }
}

#[test]
fn digest_truncation_224() {
    let bits = 224_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 28_usize);
    }
}

#[test]
fn digest_truncation_256() {
    let bits = 256_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 32_usize);
    }
}

#[test]
fn digest_truncation_384() {
    let bits = 384_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 48_usize);
    }
}

#[test]
fn digest_truncation_511() {
    let bits = 511_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 64_usize);
    }
}

#[test]
fn digest_truncation_512() {
    let bits = 512_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 64_usize);
    }
}

#[test]
fn digest_truncation_513() {
    let bits = 513_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 65_usize);
    }
}

#[test]
fn digest_truncation_4294967295() {
    let bits = 4294967295_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 536870912_usize);
    }
}

#[test]
fn digest_truncation_4294967296() {
    let bits = 4294967296_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 536870912_usize);
    }
}

#[test]
fn digest_truncation_18446744073709551615() {
    let bits = 18446744073709551615_u64;
    let actual = NativeDigestTruncation::new(bits);
    if bits > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::NativeDigest(
            NativeDigestRejection::DigestBitCountAbiWidth
        )))));
    } else {
        let actual = actual.expect("representable bit count");
        assert_eq!(actual.bits(), bits);
        assert_eq!(NativeDigestAlgorithm::Sha512T(actual).output_length(), 2305843009213693952_usize);
    }
}

#[test]
fn null_digest_capacity_0() {
    let bytes = 0_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_1() {
    let bytes = 1_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_31() {
    let bytes = 31_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_32() {
    let bytes = 32_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_33() {
    let bytes = 33_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_4294967295() {
    let bytes = 4294967295_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_4294967296() {
    let bytes = 4294967296_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}

#[test]
fn null_digest_capacity_18446744073709551615() {
    let bytes = 18446744073709551615_usize;
    let actual = NativeNullDigestCapacity::new(bytes);
    if bytes as u64 > fe11_sys::CK_ULONG::MAX as u64 {
        assert!(matches!(actual, Err(Error::Rejected(RejectionReason::InputBounds(
            InputBoundsRejection::LengthConversion
        )))));
    } else {
        let actual = actual.expect("representable byte count");
        assert_eq!(actual.maximum_output_bytes(), bytes);
        assert_eq!(NativeDigestAlgorithm::Null(actual).output_length(), bytes);
    }
}
