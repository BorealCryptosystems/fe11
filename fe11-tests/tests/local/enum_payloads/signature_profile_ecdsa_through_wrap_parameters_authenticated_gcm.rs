// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn signature_profile_ecdsa() {
    let inputs: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ];
    for expected in inputs {
        let candidate = SignatureProfile::Ecdsa(expected.clone());
        let SignatureProfile::Ecdsa(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn signature_profile_rsa_pkcs1() {
    let inputs: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ];
    for expected in inputs {
        let candidate = SignatureProfile::RsaPkcs1(expected.clone());
        let SignatureProfile::RsaPkcs1(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn signing_request_ecdsa() {
    let inputs: [HashExecution; 3] = [
        HashExecution::Pkcs11Combined,
        HashExecution::Pkcs11DigestThenPrimitive,
        HashExecution::RustSoftware,
    ];
    for expected in inputs {
        let candidate = SigningRequest::Ecdsa {
            execution: expected.clone(),
            hash: HashAlgorithm::Sha224,
        };
        let SigningRequest::Ecdsa { execution, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(execution, expected);
    }
    let inputs: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ];
    for expected in inputs {
        let candidate = SigningRequest::Ecdsa {
            execution: HashExecution::Pkcs11Combined,
            hash: expected.clone(),
        };
        let SigningRequest::Ecdsa { hash, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(hash, expected);
    }
}

#[test]
fn signing_request_rsa_pkcs1() {
    let inputs: [HashExecution; 3] = [
        HashExecution::Pkcs11Combined,
        HashExecution::Pkcs11DigestThenPrimitive,
        HashExecution::RustSoftware,
    ];
    for expected in inputs {
        let candidate = SigningRequest::RsaPkcs1 {
            execution: expected.clone(),
            hash: HashAlgorithm::Sha224,
        };
        let SigningRequest::RsaPkcs1 { execution, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(execution, expected);
    }
    let inputs: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ];
    for expected in inputs {
        let candidate = SigningRequest::RsaPkcs1 {
            execution: HashExecution::Pkcs11Combined,
            hash: expected.clone(),
        };
        let SigningRequest::RsaPkcs1 { hash, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(hash, expected);
    }
}

#[test]
fn slot_event_changed() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = SlotEvent::Changed(expected.clone());
        let SlotEvent::Changed(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn sp800_data_bytes() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = Sp800Data::Bytes(expected);
        let Sp800Data::Bytes(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn stream_aead_nonce_cha_cha20() {
    let inputs: [[u8; 8]; 4] = [
        [2; 8],
        [0; 8],
        [255; 8],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = StreamAeadNonce::ChaCha20(expected.clone());
        let StreamAeadNonce::ChaCha20(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn stream_aead_nonce_cha_cha20_ietf() {
    let inputs: [[u8; 12]; 4] = [
        [2; 12],
        [0; 12],
        [255; 12],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = StreamAeadNonce::ChaCha20Ietf(expected.clone());
        let StreamAeadNonce::ChaCha20Ietf(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn stream_aead_nonce_salsa20() {
    let inputs: [[u8; 8]; 4] = [
        [2; 8],
        [0; 8],
        [255; 8],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = StreamAeadNonce::Salsa20(expected.clone());
        let StreamAeadNonce::Salsa20(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn stream_aead_nonce_x_cha_cha20() {
    let inputs: [[u8; 24]; 4] = [
        [2; 24],
        [0; 24],
        [255; 24],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = StreamAeadNonce::XChaCha20(expected.clone());
        let StreamAeadNonce::XChaCha20(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn stream_aead_nonce_x_salsa20() {
    let inputs: [[u8; 24]; 4] = [
        [2; 24],
        [0; 24],
        [255; 24],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = StreamAeadNonce::XSalsa20(expected.clone());
        let StreamAeadNonce::XSalsa20(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn template_attribute_value_unavailable() {
    let inputs: [AttributeUnavailableCause; 3] = [
        AttributeUnavailableCause::Sensitive,
        AttributeUnavailableCause::Unspecified,
        AttributeUnavailableCause::Unsupported,
    ];
    for expected in inputs {
        let candidate = TemplateAttributeValue::Unavailable(expected.clone());
        let TemplateAttributeValue::Unavailable(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn token_iv_provided() {
    let inputs: [[u8; 24]; 4] = [
        [2; 24],
        [0; 24],
        [255; 24],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = TokenIv::Provided(expected.clone());
        let TokenIv::Provided(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn unwrap_parameters_authenticated_gcm() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = UnwrapParameters::AuthenticatedGcm {
            aad: expected,
            nonce: AeadNonce::BackendRandom,
            tag: &[],
        };
        let UnwrapParameters::AuthenticatedGcm { aad, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(aad, expected);
    }
    let inputs: [AeadNonce; 3] = [
        AeadNonce::BackendRandom,
        AeadNonce::Gcm {
            fixed_bits: 5,
            generator: 6,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 8,
        },
        AeadNonce::Provided([4; 12]),
    ];
    for expected in inputs {
        let candidate = UnwrapParameters::AuthenticatedGcm {
            aad: &[],
            nonce: expected.clone(),
            tag: &[],
        };
        let UnwrapParameters::AuthenticatedGcm { nonce, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(nonce, expected);
    }
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
    for expected in inputs {
        let candidate = UnwrapParameters::AuthenticatedGcm {
            aad: &[],
            nonce: AeadNonce::BackendRandom,
            tag: expected,
        };
        let UnwrapParameters::AuthenticatedGcm { tag, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(tag, expected);
    }
}

#[test]
fn verification_profile_ecdsa() {
    let inputs: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ];
    for expected in inputs {
        let candidate = VerificationProfile::Ecdsa(expected.clone());
        let VerificationProfile::Ecdsa(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn verification_profile_rsa_pkcs1() {
    let inputs: [HashAlgorithm; 8] = [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ];
    for expected in inputs {
        let candidate = VerificationProfile::RsaPkcs1(expected.clone());
        let VerificationProfile::RsaPkcs1(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn wrap_parameters_authenticated_gcm() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = WrapParameters::AuthenticatedGcm {
            aad: expected,
            nonce: AeadNonce::BackendRandom,
        };
        let WrapParameters::AuthenticatedGcm { aad, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(aad, expected);
    }
    let inputs: [AeadNonce; 3] = [
        AeadNonce::BackendRandom,
        AeadNonce::Gcm {
            fixed_bits: 5,
            generator: 6,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 8,
        },
        AeadNonce::Provided([4; 12]),
    ];
    for expected in inputs {
        let candidate = WrapParameters::AuthenticatedGcm {
            aad: &[],
            nonce: expected.clone(),
        };
        let WrapParameters::AuthenticatedGcm { nonce, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(nonce, expected);
    }
}
