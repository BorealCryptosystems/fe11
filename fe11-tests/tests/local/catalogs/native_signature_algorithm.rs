// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::NativeSignatureAlgorithm;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (NativeSignatureAlgorithm::DSA, fe11_sys::CKM_DSA as u64),
        (NativeSignatureAlgorithm::DSA_SHA1, fe11_sys::CKM_DSA_SHA1 as u64),
        (NativeSignatureAlgorithm::DSA_SHA224, fe11_sys::CKM_DSA_SHA224 as u64),
        (NativeSignatureAlgorithm::DSA_SHA256, fe11_sys::CKM_DSA_SHA256 as u64),
        (NativeSignatureAlgorithm::DSA_SHA384, fe11_sys::CKM_DSA_SHA384 as u64),
        (NativeSignatureAlgorithm::DSA_SHA3_224, fe11_sys::CKM_DSA_SHA3_224 as u64),
        (NativeSignatureAlgorithm::DSA_SHA3_256, fe11_sys::CKM_DSA_SHA3_256 as u64),
        (NativeSignatureAlgorithm::DSA_SHA3_384, fe11_sys::CKM_DSA_SHA3_384 as u64),
        (NativeSignatureAlgorithm::DSA_SHA3_512, fe11_sys::CKM_DSA_SHA3_512 as u64),
        (NativeSignatureAlgorithm::DSA_SHA512, fe11_sys::CKM_DSA_SHA512 as u64),
        (NativeSignatureAlgorithm::ECDSA, fe11_sys::CKM_ECDSA as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA1, fe11_sys::CKM_ECDSA_SHA1 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA224, fe11_sys::CKM_ECDSA_SHA224 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA256, fe11_sys::CKM_ECDSA_SHA256 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA384, fe11_sys::CKM_ECDSA_SHA384 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA3_224, fe11_sys::CKM_ECDSA_SHA3_224 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA3_256, fe11_sys::CKM_ECDSA_SHA3_256 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA3_384, fe11_sys::CKM_ECDSA_SHA3_384 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA3_512, fe11_sys::CKM_ECDSA_SHA3_512 as u64),
        (NativeSignatureAlgorithm::ECDSA_SHA512, fe11_sys::CKM_ECDSA_SHA512 as u64),
        (NativeSignatureAlgorithm::FORTEZZA_TIMESTAMP, fe11_sys::CKM_FORTEZZA_TIMESTAMP as u64),
        (NativeSignatureAlgorithm::GOSTR3410, fe11_sys::CKM_GOSTR3410 as u64),
        (NativeSignatureAlgorithm::HSS, fe11_sys::CKM_HSS as u64),
        (NativeSignatureAlgorithm::MD2_RSA_PKCS, fe11_sys::CKM_MD2_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::MD5_RSA_PKCS, fe11_sys::CKM_MD5_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::NULL, fe11_sys::CKM_NULL as u64),
        (NativeSignatureAlgorithm::RIPEMD128_RSA_PKCS, fe11_sys::CKM_RIPEMD128_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::RIPEMD160_RSA_PKCS, fe11_sys::CKM_RIPEMD160_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::RSA_9796, fe11_sys::CKM_RSA_9796 as u64),
        (NativeSignatureAlgorithm::RSA_PKCS, fe11_sys::CKM_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::RSA_X9_31, fe11_sys::CKM_RSA_X9_31 as u64),
        (NativeSignatureAlgorithm::RSA_X_509, fe11_sys::CKM_RSA_X_509 as u64),
        (NativeSignatureAlgorithm::SHA1_RSA_PKCS, fe11_sys::CKM_SHA1_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA1_RSA_X9_31, fe11_sys::CKM_SHA1_RSA_X9_31 as u64),
        (NativeSignatureAlgorithm::SHA224_RSA_PKCS, fe11_sys::CKM_SHA224_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA256_RSA_PKCS, fe11_sys::CKM_SHA256_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA384_RSA_PKCS, fe11_sys::CKM_SHA384_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA3_224_RSA_PKCS, fe11_sys::CKM_SHA3_224_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA3_256_RSA_PKCS, fe11_sys::CKM_SHA3_256_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA3_384_RSA_PKCS, fe11_sys::CKM_SHA3_384_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA3_512_RSA_PKCS, fe11_sys::CKM_SHA3_512_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::SHA512_RSA_PKCS, fe11_sys::CKM_SHA512_RSA_PKCS as u64),
        (NativeSignatureAlgorithm::XMSS, fe11_sys::CKM_XMSS as u64),
        (NativeSignatureAlgorithm::XMSSMT, fe11_sys::CKM_XMSSMT as u64),
    ];
    assert_eq!(NativeSignatureAlgorithm::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(NativeSignatureAlgorithm::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
