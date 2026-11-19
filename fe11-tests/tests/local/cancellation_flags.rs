// SPDX-License-Identifier: Apache-2.0
//! PKCS#11 operation categories are distinct from mechanism-capability flags.
use fe11::{CancellationFlags, CancellationRejection, Error, RejectionReason};
use fe11_sys::*;

const CATEGORIES: [CK_FLAGS; 19] = [
    CKF_FIND_OBJECTS, CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN,
    CKF_SIGN_RECOVER, CKF_VERIFY, CKF_VERIFY_RECOVER, CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR, CKF_WRAP, CKF_UNWRAP, CKF_DERIVE, CKF_ENCAPSULATE,
    CKF_DECAPSULATE, CKF_MESSAGE_ENCRYPT, CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_SIGN, CKF_MESSAGE_VERIFY,
];

#[test]
fn operation_categories_and_union_preserve_exact_bits() {
    assert_eq!(CancellationFlags::NONE.bits(), 0);
    assert_eq!(CancellationFlags::from_bits(0).unwrap(), CancellationFlags::NONE);
    let mut combined = CancellationFlags::NONE;
    let mut expected = 0_u64;
    for bits in CATEGORIES {
        let flag = CancellationFlags::from_bits(bits as u64).unwrap();
        assert_eq!(flag.bits(), bits as u64);
        assert_eq!(flag.union(flag), flag);
        assert_eq!(flag.union(combined), combined.union(flag));
        for other in CATEGORIES {
            let other = CancellationFlags::from_bits(other as u64).unwrap();
            assert_eq!(combined.union(flag).union(other), combined.union(flag.union(other)));
        }
        combined = combined.union(flag);
        expected |= bits as u64;
        assert_eq!(combined.bits(), expected);
    }
    assert_eq!(CancellationFlags::from_bits(expected).unwrap(), combined);
}

#[test]
fn every_non_category_bit_is_rejected_without_truncation() {
    let categories = CATEGORIES.iter().fold(0_u64, |all, bit| all | *bit as u64);
    for bit in 0..64 {
        let bits = 1_u64 << bit;
        if categories & bits != 0 {
            continue;
        }
        let actual = CancellationFlags::from_bits(bits);
        if bits > CK_FLAGS::MAX as u64 {
            assert!(matches!(actual, Err(Error::Rejected(RejectionReason::Cancellation(
                CancellationRejection::CancellationFlagRange
            )))));
        } else {
            assert!(matches!(actual, Err(Error::Rejected(RejectionReason::Cancellation(
                CancellationRejection::CancellationFlagCategory
            )))));
        }
    }
    for bits in [CKF_HW, CKF_MULTI_MESSAGE, CKF_EXTENSION] {
        assert!(matches!(CancellationFlags::from_bits(bits as u64),
            Err(Error::Rejected(RejectionReason::Cancellation(
                CancellationRejection::CancellationFlagCategory
            )))
        ));
    }
}
