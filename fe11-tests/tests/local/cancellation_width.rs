// SPDX-License-Identifier: Apache-2.0
//! Native unsigned-long width and operation-category validity are separate checks.
use fe11::{CancellationFlags, CancellationRejection, Error, RejectionReason};

#[test]
fn all_bits_obey_the_native_width_before_category_validation() {
    assert_eq!(CancellationFlags::from_bits(0).unwrap().bits(), 0);
    let expected = if std::mem::size_of::<fe11_sys::CK_FLAGS>() == 4 {
        CancellationRejection::CancellationFlagRange
    } else {
        assert_eq!(std::mem::size_of::<fe11_sys::CK_FLAGS>(), 8);
        CancellationRejection::CancellationFlagCategory
    };
    match CancellationFlags::from_bits(u64::MAX) {
        Err(Error::Rejected(RejectionReason::Cancellation(actual))) => {
            assert_eq!(actual, expected);
        }
        Err(error) => panic!("unexpected cancellation diagnostic: {error}"),
        Ok(_) => panic!("undefined operation-category bits were accepted"),
    }
    assert_eq!(CancellationFlags::from_bits(0).unwrap().bits(), 0);
}
