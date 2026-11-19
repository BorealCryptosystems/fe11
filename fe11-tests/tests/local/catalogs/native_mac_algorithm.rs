// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::NativeMacAlgorithm;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (NativeMacAlgorithm::AES_CMAC, fe11_sys::CKM_AES_CMAC as u64),
        (NativeMacAlgorithm::AES_MAC, fe11_sys::CKM_AES_MAC as u64),
        (NativeMacAlgorithm::AES_XCBC_MAC, fe11_sys::CKM_AES_XCBC_MAC as u64),
        (NativeMacAlgorithm::AES_XCBC_MAC_96, fe11_sys::CKM_AES_XCBC_MAC_96 as u64),
        (NativeMacAlgorithm::ARIA_MAC, fe11_sys::CKM_ARIA_MAC as u64),
        (NativeMacAlgorithm::BLAKE2B_160_HMAC, fe11_sys::CKM_BLAKE2B_160_HMAC as u64),
        (NativeMacAlgorithm::BLAKE2B_256_HMAC, fe11_sys::CKM_BLAKE2B_256_HMAC as u64),
        (NativeMacAlgorithm::BLAKE2B_384_HMAC, fe11_sys::CKM_BLAKE2B_384_HMAC as u64),
        (NativeMacAlgorithm::BLAKE2B_512_HMAC, fe11_sys::CKM_BLAKE2B_512_HMAC as u64),
        (NativeMacAlgorithm::CAMELLIA_MAC, fe11_sys::CKM_CAMELLIA_MAC as u64),
        (NativeMacAlgorithm::CAST128_MAC, fe11_sys::CKM_CAST128_MAC as u64),
        (NativeMacAlgorithm::CAST3_MAC, fe11_sys::CKM_CAST3_MAC as u64),
        (NativeMacAlgorithm::CAST5_MAC, fe11_sys::CKM_CAST5_MAC as u64),
        (NativeMacAlgorithm::CAST_MAC, fe11_sys::CKM_CAST_MAC as u64),
        (NativeMacAlgorithm::CDMF_MAC, fe11_sys::CKM_CDMF_MAC as u64),
        (NativeMacAlgorithm::DES3_CMAC, fe11_sys::CKM_DES3_CMAC as u64),
        (NativeMacAlgorithm::DES3_MAC, fe11_sys::CKM_DES3_MAC as u64),
        (NativeMacAlgorithm::DES_MAC, fe11_sys::CKM_DES_MAC as u64),
        (NativeMacAlgorithm::IDEA_MAC, fe11_sys::CKM_IDEA_MAC as u64),
        (NativeMacAlgorithm::MD2_HMAC, fe11_sys::CKM_MD2_HMAC as u64),
        (NativeMacAlgorithm::MD5_HMAC, fe11_sys::CKM_MD5_HMAC as u64),
        (NativeMacAlgorithm::POLY1305, fe11_sys::CKM_POLY1305 as u64),
        (NativeMacAlgorithm::RIPEMD128_HMAC, fe11_sys::CKM_RIPEMD128_HMAC as u64),
        (NativeMacAlgorithm::RIPEMD160_HMAC, fe11_sys::CKM_RIPEMD160_HMAC as u64),
        (NativeMacAlgorithm::SEED_MAC, fe11_sys::CKM_SEED_MAC as u64),
        (NativeMacAlgorithm::SHA224_HMAC, fe11_sys::CKM_SHA224_HMAC as u64),
        (NativeMacAlgorithm::SHA256_HMAC, fe11_sys::CKM_SHA256_HMAC as u64),
        (NativeMacAlgorithm::SHA384_HMAC, fe11_sys::CKM_SHA384_HMAC as u64),
        (NativeMacAlgorithm::SHA3_224_HMAC, fe11_sys::CKM_SHA3_224_HMAC as u64),
        (NativeMacAlgorithm::SHA3_256_HMAC, fe11_sys::CKM_SHA3_256_HMAC as u64),
        (NativeMacAlgorithm::SHA3_384_HMAC, fe11_sys::CKM_SHA3_384_HMAC as u64),
        (NativeMacAlgorithm::SHA3_512_HMAC, fe11_sys::CKM_SHA3_512_HMAC as u64),
        (NativeMacAlgorithm::SHA512_224_HMAC, fe11_sys::CKM_SHA512_224_HMAC as u64),
        (NativeMacAlgorithm::SHA512_256_HMAC, fe11_sys::CKM_SHA512_256_HMAC as u64),
        (NativeMacAlgorithm::SHA512_HMAC, fe11_sys::CKM_SHA512_HMAC as u64),
        (NativeMacAlgorithm::SHA_1_HMAC, fe11_sys::CKM_SHA_1_HMAC as u64),
    ];
    assert_eq!(NativeMacAlgorithm::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(NativeMacAlgorithm::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
