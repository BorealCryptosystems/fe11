// SPDX-License-Identifier: Apache-2.0
//! Public OTP representation checks that require neither a token nor an OTP key.
use fe11::{NativeOtpAlgorithm, NativeOtpParameter, NativeOtpValue};
use fe11_sys::{CKM_ACTI, CKM_HOTP, CKM_SECURID, CK_ULONG};

#[test]
fn standard_selectors_preserve_their_native_identifiers() {
    for (algorithm, expected) in [
        (NativeOtpAlgorithm::SecurId, CKM_SECURID),
        (NativeOtpAlgorithm::Hotp, CKM_HOTP),
        (NativeOtpAlgorithm::Acti, CKM_ACTI),
    ] {
        assert_eq!(algorithm.mechanism_number(), expected as u64);
    }
}

#[test]
fn borrowed_fields_preserve_empty_and_binary_values_without_reinterpretation() {
    let normal = b"20261116120000";
    let binary = [0, 255, 0, 128];
    for value in [&[][..], normal.as_slice(), binary.as_slice()] {
        let fields = [
            NativeOtpParameter::Value(value),
            NativeOtpParameter::Pin(value),
            NativeOtpParameter::Challenge(value),
            NativeOtpParameter::Time(value),
            NativeOtpParameter::Counter(value),
        ];
        for (index, field) in fields.iter().enumerate() {
            let (kind, bytes) = match field {
                NativeOtpParameter::Value(bytes) => (0, *bytes),
                NativeOtpParameter::Pin(bytes) => (1, *bytes),
                NativeOtpParameter::Challenge(bytes) => (2, *bytes),
                NativeOtpParameter::Time(bytes) => (3, *bytes),
                NativeOtpParameter::Counter(bytes) => (4, *bytes),
                _ => panic!("byte parameter changed variant"),
            };
            assert_eq!(kind, index);
            assert_eq!(bytes, value);
            assert_eq!(bytes.as_ptr(), value.as_ptr());
        }
    }
    // These scalar values remain caller choices. Native-width conversion and
    // semantic acceptance require an actual OTP operation, not this local check.
    for value in [0, 1, CK_ULONG::MAX as u64, u64::MAX] {
        for (index, field) in [
            NativeOtpParameter::Flags(value),
            NativeOtpParameter::OutputLength(value),
            NativeOtpParameter::OutputFormat(value),
        ]
        .iter()
        .enumerate()
        {
            let (kind, actual) = match field {
                NativeOtpParameter::Flags(actual) => (0, *actual),
                NativeOtpParameter::OutputLength(actual) => (1, *actual),
                NativeOtpParameter::OutputFormat(actual) => (2, *actual),
                _ => panic!("scalar parameter changed variant"),
            };
            assert_eq!((kind, actual), (index, value));
        }
    }
}

#[test]
fn native_scalar_decode_requires_exact_unsigned_long_width() {
    for value in [0 as CK_ULONG, 1, CK_ULONG::MAX] {
        let bytes = value.to_ne_bytes();
        let view = NativeOtpValue {
            kind: 0,
            bytes: &bytes,
        };
        assert_eq!(view.native_unsigned(), Some(value as u64));
    }
    let width = std::mem::size_of::<CK_ULONG>();
    for length in 0..=width + 1 {
        if length == width {
            continue;
        }
        let bytes = vec![0; length];
        let view = NativeOtpValue {
            kind: u64::MAX,
            bytes: &bytes,
        };
        assert_eq!(view.native_unsigned(), None);
        assert_eq!(view.kind, u64::MAX);
    }
}

#[test]
fn borrowed_scalar_decode_does_not_require_aligned_memory() {
    let value: CK_ULONG = 0x10203;
    let bytes = value.to_ne_bytes();
    // Cover every offset modulo native alignment. The method copies bytes;
    // it must not dereference the caller's slice as an aligned CK_ULONG.
    let mut storage = vec![0; bytes.len() + std::mem::align_of::<CK_ULONG>()];
    for offset in 0..std::mem::align_of::<CK_ULONG>() {
        storage[offset..offset + bytes.len()].copy_from_slice(&bytes);
        let view = NativeOtpValue {
            kind: 0,
            bytes: &storage[offset..offset + bytes.len()],
        };
        assert_eq!(view.native_unsigned(), Some(value as u64));
    }
}
