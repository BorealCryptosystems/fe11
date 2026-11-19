// SPDX-License-Identifier: Apache-2.0
//! Stateful signature selectors retain their exact parameterless native identity.
use fe11::{KeyPairGenerator, NativeSignatureAlgorithm, NativeSignatureParameters};

#[test]
fn hss_parameterless_request_and_generator_are_distinct() {
    let request = NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::HSS);
    assert_eq!(request.mechanism_number(), fe11_sys::CKM_HSS as u64);
    assert_eq!(
        KeyPairGenerator::HSS_KEY_PAIR_GEN.mechanism_number(),
        fe11_sys::CKM_HSS_KEY_PAIR_GEN as u64
    );
    assert_ne!(
        request.mechanism_number(),
        KeyPairGenerator::HSS_KEY_PAIR_GEN.mechanism_number()
    );
}

#[test]
fn xmss_parameterless_request_and_generator_are_distinct() {
    let request = NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::XMSS);
    assert_eq!(request.mechanism_number(), fe11_sys::CKM_XMSS as u64);
    assert_eq!(
        KeyPairGenerator::XMSS_KEY_PAIR_GEN.mechanism_number(),
        fe11_sys::CKM_XMSS_KEY_PAIR_GEN as u64
    );
    assert_ne!(
        request.mechanism_number(),
        KeyPairGenerator::XMSS_KEY_PAIR_GEN.mechanism_number()
    );
}

#[test]
fn xmssmt_parameterless_request_and_generator_are_distinct() {
    let request = NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::XMSSMT);
    assert_eq!(request.mechanism_number(), fe11_sys::CKM_XMSSMT as u64);
    assert_eq!(
        KeyPairGenerator::XMSSMT_KEY_PAIR_GEN.mechanism_number(),
        fe11_sys::CKM_XMSSMT_KEY_PAIR_GEN as u64
    );
    assert_ne!(
        request.mechanism_number(),
        KeyPairGenerator::XMSSMT_KEY_PAIR_GEN.mechanism_number()
    );
}
