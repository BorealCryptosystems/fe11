// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::KeyGenerator;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (KeyGenerator::ACTI_KEY_GEN, fe11_sys::CKM_ACTI_KEY_GEN as u64),
        (KeyGenerator::AES_KEY_GEN, fe11_sys::CKM_AES_KEY_GEN as u64),
        (KeyGenerator::AES_XTS_KEY_GEN, fe11_sys::CKM_AES_XTS_KEY_GEN as u64),
        (KeyGenerator::ARIA_KEY_GEN, fe11_sys::CKM_ARIA_KEY_GEN as u64),
        (KeyGenerator::BATON_KEY_GEN, fe11_sys::CKM_BATON_KEY_GEN as u64),
        (KeyGenerator::BLAKE2B_160_KEY_GEN, fe11_sys::CKM_BLAKE2B_160_KEY_GEN as u64),
        (KeyGenerator::BLAKE2B_256_KEY_GEN, fe11_sys::CKM_BLAKE2B_256_KEY_GEN as u64),
        (KeyGenerator::BLAKE2B_384_KEY_GEN, fe11_sys::CKM_BLAKE2B_384_KEY_GEN as u64),
        (KeyGenerator::BLAKE2B_512_KEY_GEN, fe11_sys::CKM_BLAKE2B_512_KEY_GEN as u64),
        (KeyGenerator::BLOWFISH_KEY_GEN, fe11_sys::CKM_BLOWFISH_KEY_GEN as u64),
        (KeyGenerator::CAMELLIA_KEY_GEN, fe11_sys::CKM_CAMELLIA_KEY_GEN as u64),
        (KeyGenerator::CAST128_KEY_GEN, fe11_sys::CKM_CAST128_KEY_GEN as u64),
        (KeyGenerator::CAST3_KEY_GEN, fe11_sys::CKM_CAST3_KEY_GEN as u64),
        (KeyGenerator::CAST5_KEY_GEN, fe11_sys::CKM_CAST5_KEY_GEN as u64),
        (KeyGenerator::CAST_KEY_GEN, fe11_sys::CKM_CAST_KEY_GEN as u64),
        (KeyGenerator::CDMF_KEY_GEN, fe11_sys::CKM_CDMF_KEY_GEN as u64),
        (KeyGenerator::CHACHA20_KEY_GEN, fe11_sys::CKM_CHACHA20_KEY_GEN as u64),
        (KeyGenerator::DES2_KEY_GEN, fe11_sys::CKM_DES2_KEY_GEN as u64),
        (KeyGenerator::DES3_KEY_GEN, fe11_sys::CKM_DES3_KEY_GEN as u64),
        (KeyGenerator::DES_KEY_GEN, fe11_sys::CKM_DES_KEY_GEN as u64),
        (KeyGenerator::DH_PKCS_PARAMETER_GEN, fe11_sys::CKM_DH_PKCS_PARAMETER_GEN as u64),
        (KeyGenerator::DSA_PARAMETER_GEN, fe11_sys::CKM_DSA_PARAMETER_GEN as u64),
        (KeyGenerator::GENERIC_SECRET_KEY_GEN, fe11_sys::CKM_GENERIC_SECRET_KEY_GEN as u64),
        (KeyGenerator::GOST28147_KEY_GEN, fe11_sys::CKM_GOST28147_KEY_GEN as u64),
        (KeyGenerator::HKDF_KEY_GEN, fe11_sys::CKM_HKDF_KEY_GEN as u64),
        (KeyGenerator::HOTP_KEY_GEN, fe11_sys::CKM_HOTP_KEY_GEN as u64),
        (KeyGenerator::IDEA_KEY_GEN, fe11_sys::CKM_IDEA_KEY_GEN as u64),
        (KeyGenerator::JUNIPER_KEY_GEN, fe11_sys::CKM_JUNIPER_KEY_GEN as u64),
        (KeyGenerator::POLY1305_KEY_GEN, fe11_sys::CKM_POLY1305_KEY_GEN as u64),
        (KeyGenerator::RC2_KEY_GEN, fe11_sys::CKM_RC2_KEY_GEN as u64),
        (KeyGenerator::RC4_KEY_GEN, fe11_sys::CKM_RC4_KEY_GEN as u64),
        (KeyGenerator::RC5_KEY_GEN, fe11_sys::CKM_RC5_KEY_GEN as u64),
        (KeyGenerator::SALSA20_KEY_GEN, fe11_sys::CKM_SALSA20_KEY_GEN as u64),
        (KeyGenerator::SECURID_KEY_GEN, fe11_sys::CKM_SECURID_KEY_GEN as u64),
        (KeyGenerator::SEED_KEY_GEN, fe11_sys::CKM_SEED_KEY_GEN as u64),
        (KeyGenerator::SHA224_KEY_GEN, fe11_sys::CKM_SHA224_KEY_GEN as u64),
        (KeyGenerator::SHA256_KEY_GEN, fe11_sys::CKM_SHA256_KEY_GEN as u64),
        (KeyGenerator::SHA384_KEY_GEN, fe11_sys::CKM_SHA384_KEY_GEN as u64),
        (KeyGenerator::SHA3_224_KEY_GEN, fe11_sys::CKM_SHA3_224_KEY_GEN as u64),
        (KeyGenerator::SHA3_256_KEY_GEN, fe11_sys::CKM_SHA3_256_KEY_GEN as u64),
        (KeyGenerator::SHA3_384_KEY_GEN, fe11_sys::CKM_SHA3_384_KEY_GEN as u64),
        (KeyGenerator::SHA3_512_KEY_GEN, fe11_sys::CKM_SHA3_512_KEY_GEN as u64),
        (KeyGenerator::SHA512_224_KEY_GEN, fe11_sys::CKM_SHA512_224_KEY_GEN as u64),
        (KeyGenerator::SHA512_256_KEY_GEN, fe11_sys::CKM_SHA512_256_KEY_GEN as u64),
        (KeyGenerator::SHA512_KEY_GEN, fe11_sys::CKM_SHA512_KEY_GEN as u64),
        (KeyGenerator::SHA512_T_KEY_GEN, fe11_sys::CKM_SHA512_T_KEY_GEN as u64),
        (KeyGenerator::SHA_1_KEY_GEN, fe11_sys::CKM_SHA_1_KEY_GEN as u64),
        (KeyGenerator::SKIPJACK_KEY_GEN, fe11_sys::CKM_SKIPJACK_KEY_GEN as u64),
        (KeyGenerator::TWOFISH_KEY_GEN, fe11_sys::CKM_TWOFISH_KEY_GEN as u64),
        (KeyGenerator::X9_42_DH_PARAMETER_GEN, fe11_sys::CKM_X9_42_DH_PARAMETER_GEN as u64),
    ];
    assert_eq!(KeyGenerator::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(KeyGenerator::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
