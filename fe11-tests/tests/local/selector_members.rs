// SPDX-License-Identifier: Apache-2.0
//! Public selector constants and metadata that can be inspected before dispatch.
use fe11::{AeadNonce, CancellationFlags, EdwardsKeySizeUnits, EdwardsOptions,
    EdwardsParameterEncoding, EdwardsPointEncoding};

#[test]
fn named_operation_flags_select_the_corresponding_native_category() {
    for (flag, expected) in [
        (CancellationFlags::ENCRYPT, fe11_sys::CKF_ENCRYPT),
        (CancellationFlags::DECRYPT, fe11_sys::CKF_DECRYPT),
        (CancellationFlags::DIGEST, fe11_sys::CKF_DIGEST),
        (CancellationFlags::SIGN, fe11_sys::CKF_SIGN),
        (CancellationFlags::VERIFY, fe11_sys::CKF_VERIFY),
        (CancellationFlags::MESSAGE_ENCRYPT, fe11_sys::CKF_MESSAGE_ENCRYPT),
        (CancellationFlags::MESSAGE_DECRYPT, fe11_sys::CKF_MESSAGE_DECRYPT),
        (CancellationFlags::MESSAGE_SIGN, fe11_sys::CKF_MESSAGE_SIGN),
        (CancellationFlags::MESSAGE_VERIFY, fe11_sys::CKF_MESSAGE_VERIFY),
    ] {
        assert_eq!(flag.bits(), expected as u64);
    }
}

#[test]
fn edwards_standard_profile_selects_raw_points_curve_names_and_field_bits() {
    let profile = EdwardsOptions::PKCS11_32;
    assert_eq!(profile.point_encoding, EdwardsPointEncoding::Raw);
    assert_eq!(profile.parameter_encoding, EdwardsParameterEncoding::CurveName);
    assert_eq!(profile.key_size_units, EdwardsKeySizeUnits::FieldBits);
}

#[test]
fn nonce_tag_accessor_preserves_the_caller_selected_bit_count() {
    assert_eq!(AeadNonce::Provided([0; 12]).tag_bits(), 128);
    assert_eq!(AeadNonce::BackendRandom.tag_bits(), 128);
    for bits in [0, 1, 7, 8, 96, 127, 128] {
        let choice = AeadNonce::Gcm {
            iv: [0xa5_u8; 12].as_slice().into(),
            generator: 0,
            fixed_bits: 0,
            tag_bits: bits,
        };
        assert_eq!(choice.tag_bits(), bits);
    }
}
