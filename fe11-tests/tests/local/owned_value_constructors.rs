// SPDX-License-Identifier: Apache-2.0
//! Bounded public construction and borrowing, without a native module.
use fe11::*;

#[test]
fn secret_byte_owners_preserve_initialized_length_and_mutation() {
    // These are public synthetic bytes, not an operational credential. Larger
    // sizes are not requested merely to provoke allocator exhaustion.
    for length in [0, 1, 31, 32, 33, 64] {
        let mut value = SecretBytes::new(length).unwrap();
        assert_eq!(value.len(), length);
        assert_eq!(value.is_empty(), length == 0);
        assert_eq!(value.as_slice(), vec![0; length]);
        for (index, byte) in value.as_mut_slice().iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        let expected: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
            .collect();
        assert_eq!(value.as_slice(), expected);
    }
}

#[test]
fn plaintext_owners_preserve_initialized_length_and_mutation() {
    for length in [0, 1, 31, 32, 33, 64] {
        let mut value = SecretPlaintext::new(length).unwrap();
        assert_eq!(value.len(), length);
        assert_eq!(value.is_empty(), length == 0);
        assert_eq!(value.as_slice(), vec![0; length]);
        for (index, byte) in value.as_mut_slice().iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(19).wrapping_add(5);
        }
        let expected: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(19).wrapping_add(5))
            .collect();
        assert_eq!(value.as_slice(), expected);
    }
    // LLP64 rejects a length above CK_ULONG before the allocator is reached.
    // On LP64 this value would be a real allocation request and is not exercised.
    if std::mem::size_of::<usize>() > std::mem::size_of::<fe11_sys::CK_ULONG>() {
        assert!(matches!(
            SecretPlaintext::new(usize::try_from(u32::MAX as u64 + 1).unwrap()),
            Err(Error::Rejected(RejectionReason::InputBounds(
                InputBoundsRejection::LengthConversion
            )))
        ));
    }
}

#[test]
fn digest32_rejects_every_adjacent_width_without_padding() {
    for length in [0, 1, 31, 33, 64] {
        assert!(matches!(
            Digest32::from_bytes(&vec![0xa5; length]),
            Err(Error::Rejected(RejectionReason::SessionLifecycle(
                SessionLifecycleRejection::Sha256DigestLength
            )))
        ));
    }
    assert!(Digest32::from_bytes(&[0xa5; 32]).is_ok());
}

#[test]
fn cancellation_clones_share_one_monotonic_signal() {
    let original = AdmissionCancellation::new();
    let clone = original.clone();
    let independent = AdmissionCancellation::default();
    assert!(!original.is_cancelled());
    assert!(!clone.is_cancelled());
    clone.cancel();
    assert!(original.is_cancelled());
    assert!(clone.is_cancelled());
    original.cancel();
    assert!(clone.is_cancelled());
    assert!(!independent.is_cancelled());
}

#[test]
fn protected_content_preserves_bytes_or_the_exact_diagnostic() {
    let mut bytes = SecretBytes::new(3).unwrap();
    bytes.as_mut_slice().copy_from_slice(&[0x42, 0, 0x81]);
    let available = ProtectedContent::Available(bytes);
    assert_eq!(available.status(), ContentStatus::Available);
    assert_eq!(available.into_bytes().unwrap().as_slice(), &[0x42, 0, 0x81]);

    let attribute = fe11_sys::CKA_VALUE as u64;
    let cause = AttributeUnavailableCause::Sensitive;
    let issue = ContentIssue::IntegerEncoding;
    for (content, expected) in [
        (
            ProtectedContent::Unavailable { attribute, cause },
            ContentStatus::Unavailable { attribute, cause },
        ),
        (
            ProtectedContent::Unusable { attribute, issue },
            ContentStatus::Unusable { attribute, issue },
        ),
    ] {
        assert_eq!(content.status(), expected);
        assert!(matches!(
            content.into_bytes(),
            Err(Error::ContentUnavailable { status }) if status == expected
        ));
    }
}
