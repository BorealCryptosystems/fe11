// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::NativePssAlgorithm;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (NativePssAlgorithm::RSA_PKCS_PSS, fe11_sys::CKM_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA1_RSA_PKCS_PSS, fe11_sys::CKM_SHA1_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA224_RSA_PKCS_PSS, fe11_sys::CKM_SHA224_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA256_RSA_PKCS_PSS, fe11_sys::CKM_SHA256_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA384_RSA_PKCS_PSS, fe11_sys::CKM_SHA384_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA3_224_RSA_PKCS_PSS, fe11_sys::CKM_SHA3_224_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA3_256_RSA_PKCS_PSS, fe11_sys::CKM_SHA3_256_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA3_384_RSA_PKCS_PSS, fe11_sys::CKM_SHA3_384_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA3_512_RSA_PKCS_PSS, fe11_sys::CKM_SHA3_512_RSA_PKCS_PSS as u64),
        (NativePssAlgorithm::SHA512_RSA_PKCS_PSS, fe11_sys::CKM_SHA512_RSA_PKCS_PSS as u64),
    ];
    assert_eq!(NativePssAlgorithm::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(NativePssAlgorithm::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
