// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::NativeDigestAlgorithm;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (NativeDigestAlgorithm::Blake2b160, fe11_sys::CKM_BLAKE2B_160 as u64),
        (NativeDigestAlgorithm::Blake2b256, fe11_sys::CKM_BLAKE2B_256 as u64),
        (NativeDigestAlgorithm::Blake2b384, fe11_sys::CKM_BLAKE2B_384 as u64),
        (NativeDigestAlgorithm::Blake2b512, fe11_sys::CKM_BLAKE2B_512 as u64),
        (NativeDigestAlgorithm::FastHash, fe11_sys::CKM_FASTHASH as u64),
        (NativeDigestAlgorithm::GostR3411, fe11_sys::CKM_GOSTR3411 as u64),
        (NativeDigestAlgorithm::Md2, fe11_sys::CKM_MD2 as u64),
        (NativeDigestAlgorithm::Md5, fe11_sys::CKM_MD5 as u64),
        (NativeDigestAlgorithm::Ripemd128, fe11_sys::CKM_RIPEMD128 as u64),
        (NativeDigestAlgorithm::Ripemd160, fe11_sys::CKM_RIPEMD160 as u64),
        (NativeDigestAlgorithm::Sha1, fe11_sys::CKM_SHA_1 as u64),
        (NativeDigestAlgorithm::Sha224, fe11_sys::CKM_SHA224 as u64),
        (NativeDigestAlgorithm::Sha256, fe11_sys::CKM_SHA256 as u64),
        (NativeDigestAlgorithm::Sha384, fe11_sys::CKM_SHA384 as u64),
        (NativeDigestAlgorithm::Sha3_224, fe11_sys::CKM_SHA3_224 as u64),
        (NativeDigestAlgorithm::Sha3_256, fe11_sys::CKM_SHA3_256 as u64),
        (NativeDigestAlgorithm::Sha3_384, fe11_sys::CKM_SHA3_384 as u64),
        (NativeDigestAlgorithm::Sha3_512, fe11_sys::CKM_SHA3_512 as u64),
        (NativeDigestAlgorithm::Sha512, fe11_sys::CKM_SHA512 as u64),
        (NativeDigestAlgorithm::Sha512_224, fe11_sys::CKM_SHA512_224 as u64),
        (NativeDigestAlgorithm::Sha512_256, fe11_sys::CKM_SHA512_256 as u64),
    ];
    assert_eq!(NativeDigestAlgorithm::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(NativeDigestAlgorithm::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
        assert_eq!(NativeDigestAlgorithm::from_mechanism(identifier), Some(member));
    }
}
