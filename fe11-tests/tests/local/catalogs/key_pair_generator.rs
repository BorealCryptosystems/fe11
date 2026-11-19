// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::KeyPairGenerator;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (KeyPairGenerator::DH_PKCS_KEY_PAIR_GEN, fe11_sys::CKM_DH_PKCS_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::DSA_KEY_PAIR_GEN, fe11_sys::CKM_DSA_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::ECDSA_KEY_PAIR_GEN, fe11_sys::CKM_ECDSA_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::EC_EDWARDS_KEY_PAIR_GEN, fe11_sys::CKM_EC_EDWARDS_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::EC_KEY_PAIR_GEN, fe11_sys::CKM_EC_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::EC_KEY_PAIR_GEN_W_EXTRA_BITS, fe11_sys::CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS as u64),
        (KeyPairGenerator::EC_MONTGOMERY_KEY_PAIR_GEN, fe11_sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::GOSTR3410_KEY_PAIR_GEN, fe11_sys::CKM_GOSTR3410_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::HSS_KEY_PAIR_GEN, fe11_sys::CKM_HSS_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::KEA_KEY_PAIR_GEN, fe11_sys::CKM_KEA_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::ML_DSA_KEY_PAIR_GEN, fe11_sys::CKM_ML_DSA_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::ML_KEM_KEY_PAIR_GEN, fe11_sys::CKM_ML_KEM_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::RSA_PKCS_KEY_PAIR_GEN, fe11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::RSA_X9_31_KEY_PAIR_GEN, fe11_sys::CKM_RSA_X9_31_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::SLH_DSA_KEY_PAIR_GEN, fe11_sys::CKM_SLH_DSA_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::X9_42_DH_KEY_PAIR_GEN, fe11_sys::CKM_X9_42_DH_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::XMSSMT_KEY_PAIR_GEN, fe11_sys::CKM_XMSSMT_KEY_PAIR_GEN as u64),
        (KeyPairGenerator::XMSS_KEY_PAIR_GEN, fe11_sys::CKM_XMSS_KEY_PAIR_GEN as u64),
    ];
    assert_eq!(KeyPairGenerator::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(KeyPairGenerator::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
