// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::HashAlgorithm;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (HashAlgorithm::Sha224, fe11_sys::CKM_SHA224 as u64),
        (HashAlgorithm::Sha256, fe11_sys::CKM_SHA256 as u64),
        (HashAlgorithm::Sha384, fe11_sys::CKM_SHA384 as u64),
        (HashAlgorithm::Sha3_224, fe11_sys::CKM_SHA3_224 as u64),
        (HashAlgorithm::Sha3_256, fe11_sys::CKM_SHA3_256 as u64),
        (HashAlgorithm::Sha3_384, fe11_sys::CKM_SHA3_384 as u64),
        (HashAlgorithm::Sha3_512, fe11_sys::CKM_SHA3_512 as u64),
        (HashAlgorithm::Sha512, fe11_sys::CKM_SHA512 as u64),
    ];
    assert_eq!(HashAlgorithm::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(HashAlgorithm::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}

#[test]
fn hash_catalogue_keeps_its_documented_family_order() {
    assert_eq!(HashAlgorithm::ALL, [
        HashAlgorithm::Sha224, HashAlgorithm::Sha256,
        HashAlgorithm::Sha384, HashAlgorithm::Sha512,
        HashAlgorithm::Sha3_224, HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384, HashAlgorithm::Sha3_512,
    ]);
}
