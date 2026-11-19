// SPDX-License-Identifier: Apache-2.0
use super::super::fixtures;
use fe11::*;

#[test]
fn rsa_signature_profile() {
    let values: [RsaSignatureProfile; 2] = [
        RsaSignatureProfile::Pkcs1(HashAlgorithm::Sha224),
        RsaSignatureProfile::Pss(fixtures::rsa_pss_parameters(false)),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn session_validation() {
    let values: [SessionValidation; 2] = [
        SessionValidation::Reported(4),
        SessionValidation::Unavailable,
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn signature_output_plan() {
    let values: [SignatureOutputPlan; 2] = [
        SignatureOutputPlan::Buffer { capacity: 4 },
        SignatureOutputPlan::LengthOnly,
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn stream_aead_nonce() {
    let values: [StreamAeadNonce; 5] = [
        StreamAeadNonce::ChaCha20([3; 8]),
        StreamAeadNonce::ChaCha20Ietf([3; 12]),
        StreamAeadNonce::Salsa20([3; 8]),
        StreamAeadNonce::XChaCha20([3; 24]),
        StreamAeadNonce::XSalsa20([3; 24]),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn stream_progress() {
    let values: [StreamProgress; 2] = [
        fixtures::stream_progress(false),
        fixtures::stream_progress(true),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
}

#[test]
fn tls_prf_mechanism() {
    let values: [TlsPrfMechanism; 2] = [TlsPrfMechanism::Tls, TlsPrfMechanism::Wtls { digest: 4 }];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn token_iv() {
    let values: [TokenIv; 2] = [TokenIv::Generate, TokenIv::Provided([3; 24])];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let copied = *item;
        assert_eq!(&copied, item);
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
    for (index, item) in values.iter().enumerate() {
        for different_variant in &values[index + 1..] {
            assert_ne!(item, different_variant);
        }
    }
}

#[test]
fn token_resource_status() {
    let values: [TokenResourceStatus; 2] = [
        fixtures::token_resource_status(false),
        fixtures::token_resource_status(true),
    ];
    for item in &values {
        fn require_eq<T: Eq>(_: &T) {}
        require_eq(item);
        assert_eq!(item, item);
        assert!(!format!("{item:?}").is_empty());
        let cloned = (*item).clone();
        assert_eq!(&cloned, item);
    }
}
