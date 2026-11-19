// SPDX-License-Identifier: Apache-2.0
//! General-length mechanism identity does not imply a module implements it.
use fe11::*;

#[test]
fn all_scalar_general_selectors_keep_the_standard_identifier() {
    let cases = [
        (
            NativeMacAlgorithm::AES_CMAC,
            fe11_sys::CKM_AES_CMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::AES_MAC,
            fe11_sys::CKM_AES_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::ARIA_MAC,
            fe11_sys::CKM_ARIA_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::BLAKE2B_160_HMAC,
            fe11_sys::CKM_BLAKE2B_160_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::BLAKE2B_256_HMAC,
            fe11_sys::CKM_BLAKE2B_256_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::BLAKE2B_384_HMAC,
            fe11_sys::CKM_BLAKE2B_384_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::BLAKE2B_512_HMAC,
            fe11_sys::CKM_BLAKE2B_512_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::CAMELLIA_MAC,
            fe11_sys::CKM_CAMELLIA_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::CAST128_MAC,
            fe11_sys::CKM_CAST128_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::CAST3_MAC,
            fe11_sys::CKM_CAST3_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::CAST5_MAC,
            fe11_sys::CKM_CAST5_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::CAST_MAC,
            fe11_sys::CKM_CAST_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::CDMF_MAC,
            fe11_sys::CKM_CDMF_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::DES3_CMAC,
            fe11_sys::CKM_DES3_CMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::DES3_MAC,
            fe11_sys::CKM_DES3_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::DES_MAC,
            fe11_sys::CKM_DES_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::IDEA_MAC,
            fe11_sys::CKM_IDEA_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::MD2_HMAC,
            fe11_sys::CKM_MD2_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::MD5_HMAC,
            fe11_sys::CKM_MD5_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::RIPEMD128_HMAC,
            fe11_sys::CKM_RIPEMD128_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::RIPEMD160_HMAC,
            fe11_sys::CKM_RIPEMD160_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SEED_MAC,
            fe11_sys::CKM_SEED_MAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA224_HMAC,
            fe11_sys::CKM_SHA224_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA256_HMAC,
            fe11_sys::CKM_SHA256_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA384_HMAC,
            fe11_sys::CKM_SHA384_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA3_224_HMAC,
            fe11_sys::CKM_SHA3_224_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA3_256_HMAC,
            fe11_sys::CKM_SHA3_256_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA3_384_HMAC,
            fe11_sys::CKM_SHA3_384_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA3_512_HMAC,
            fe11_sys::CKM_SHA3_512_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA512_224_HMAC,
            fe11_sys::CKM_SHA512_224_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA512_256_HMAC,
            fe11_sys::CKM_SHA512_256_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA512_HMAC,
            fe11_sys::CKM_SHA512_HMAC_GENERAL as u64,
        ),
        (
            NativeMacAlgorithm::SHA_1_HMAC,
            fe11_sys::CKM_SHA_1_HMAC_GENERAL as u64,
        ),
    ];
    for (algorithm, expected) in cases {
        for output_bytes in [0, 1, 8, 16, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                NativeMacParameters::General {
                    algorithm,
                    output_bytes
                }
                .mechanism_number()
                .unwrap(),
                expected
            );
        }
    }
}

#[test]
fn structured_general_selectors_are_distinct_from_the_full_mac() {
    for output_bytes in [0, 1, 4, 8, 16, u64::MAX] {
        assert_eq!(
            NativeMacParameters::Rc2 {
                effective_bits: 128,
                output_bytes: Some(output_bytes)
            }
            .mechanism_number()
            .unwrap(),
            fe11_sys::CKM_RC2_MAC_GENERAL as u64
        );
        assert_eq!(
            NativeMacParameters::Rc5 {
                word_bytes: 4,
                rounds: 12,
                output_bytes: Some(output_bytes)
            }
            .mechanism_number()
            .unwrap(),
            fe11_sys::CKM_RC5_MAC_GENERAL as u64
        );
    }
    assert_eq!(
        NativeMacParameters::Rc2 {
            effective_bits: 128,
            output_bytes: None
        }
        .mechanism_number()
        .unwrap(),
        fe11_sys::CKM_RC2_MAC as u64
    );
    assert_eq!(
        NativeMacParameters::Rc5 {
            word_bytes: 4,
            rounds: 12,
            output_bytes: None
        }
        .mechanism_number()
        .unwrap(),
        fe11_sys::CKM_RC5_MAC as u64
    );
}
