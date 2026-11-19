// SPDX-License-Identifier: Apache-2.0
//! Capacity overflow is distinct from a declared native output allowance.
use fe11::*;

#[test]
fn secret_byte_capacity_overflow_is_fallible() {
    // Vec<u8> cannot represent usize::MAX bytes: try_reserve_exact rejects the
    // capacity before allocating or initializing any such buffer.
    assert!(matches!(
        SecretBytes::new(usize::MAX),
        Err(Error::Rejected(RejectionReason::RandomGeneration(
            RandomGenerationRejection::SecretBufferAllocation
        )))
    ));
    let empty = SecretBytes::new(0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.as_slice(), &[]);
    assert_eq!(SecretBytes::new(1).unwrap().as_slice(), &[0]);
}

#[test]
fn plaintext_capacity_overflow_preserves_the_first_checked_boundary() {
    let expected = if usize::MAX as u128 > fe11_sys::CK_ULONG::MAX as u128 {
        RejectionReason::InputBounds(InputBoundsRejection::LengthConversion)
    } else {
        RejectionReason::KeyTransport(KeyTransportRejection::OaepPlaintextAllocation)
    };
    assert!(matches!(SecretPlaintext::new(usize::MAX),
        Err(Error::Rejected(actual)) if actual == expected));
    let empty = SecretPlaintext::new(0).unwrap();
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.as_slice(), &[]);
    assert_eq!(SecretPlaintext::new(1).unwrap().as_slice(), &[0]);
}

#[test]
fn native_output_allowance_checks_width_without_allocating_the_allowance() {
    for amount in [0_u64, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        let amount = usize::try_from(amount).expect("the suite uses 64-bit targets");
        let result = NativeNullDigestCapacity::new(amount);
        if amount as u128 > fe11_sys::CK_ULONG::MAX as u128 {
            assert!(matches!(
                result,
                Err(Error::Rejected(RejectionReason::InputBounds(
                    InputBoundsRejection::LengthConversion
                )))
            ));
        } else {
            assert_eq!(result.unwrap().maximum_output_bytes(), amount);
        }
    }
}
