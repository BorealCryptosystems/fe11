// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::KeyDerivationHash;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (KeyDerivationHash::BLAKE2B_160_KEY_DERIVE, fe11_sys::CKM_BLAKE2B_160_KEY_DERIVE as u64),
        (KeyDerivationHash::BLAKE2B_256_KEY_DERIVE, fe11_sys::CKM_BLAKE2B_256_KEY_DERIVE as u64),
        (KeyDerivationHash::BLAKE2B_384_KEY_DERIVE, fe11_sys::CKM_BLAKE2B_384_KEY_DERIVE as u64),
        (KeyDerivationHash::BLAKE2B_512_KEY_DERIVE, fe11_sys::CKM_BLAKE2B_512_KEY_DERIVE as u64),
        (KeyDerivationHash::MD2_KEY_DERIVATION, fe11_sys::CKM_MD2_KEY_DERIVATION as u64),
        (KeyDerivationHash::MD5_KEY_DERIVATION, fe11_sys::CKM_MD5_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA1_KEY_DERIVATION, fe11_sys::CKM_SHA1_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA224_KEY_DERIVATION, fe11_sys::CKM_SHA224_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA256_KEY_DERIVATION, fe11_sys::CKM_SHA256_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA384_KEY_DERIVATION, fe11_sys::CKM_SHA384_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA3_224_KEY_DERIVATION, fe11_sys::CKM_SHA3_224_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA3_256_KEY_DERIVATION, fe11_sys::CKM_SHA3_256_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA3_384_KEY_DERIVATION, fe11_sys::CKM_SHA3_384_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA3_512_KEY_DERIVATION, fe11_sys::CKM_SHA3_512_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA512_224_KEY_DERIVATION, fe11_sys::CKM_SHA512_224_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA512_256_KEY_DERIVATION, fe11_sys::CKM_SHA512_256_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA512_KEY_DERIVATION, fe11_sys::CKM_SHA512_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHA512_T_KEY_DERIVATION, fe11_sys::CKM_SHA512_T_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHAKE_128_KEY_DERIVATION, fe11_sys::CKM_SHAKE_128_KEY_DERIVATION as u64),
        (KeyDerivationHash::SHAKE_256_KEY_DERIVATION, fe11_sys::CKM_SHAKE_256_KEY_DERIVATION as u64),
    ];
    assert_eq!(KeyDerivationHash::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(KeyDerivationHash::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
