// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn aead_nonce_gcm() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = AeadNonce::Gcm {
            fixed_bits: expected.clone(),
            generator: 4,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 6,
        };
        let AeadNonce::Gcm { fixed_bits, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(fixed_bits, expected);
    }
    let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = AeadNonce::Gcm {
            fixed_bits: 3,
            generator: expected.clone(),
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 6,
        };
        let AeadNonce::Gcm { generator, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(generator, expected);
    }
    let inputs: [std::sync::Arc<[u8]>; 4] = [
        std::sync::Arc::from(&[][..]),
        std::sync::Arc::from(&[0u8][..]),
        std::sync::Arc::from(&[255u8][..]),
        std::sync::Arc::from(&[0u8, 1, 254, 255][..]),
    ];
    for expected in inputs {
        let candidate = AeadNonce::Gcm {
            fixed_bits: 3,
            generator: 4,
            iv: expected.clone(),
            tag_bits: 6,
        };
        let AeadNonce::Gcm { iv, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iv, expected);
    }
    let inputs: [u64; 4] = [6, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = AeadNonce::Gcm {
            fixed_bits: 3,
            generator: 4,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: expected.clone(),
        };
        let AeadNonce::Gcm { tag_bits, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(tag_bits, expected);
    }
}

#[test]
fn aead_nonce_provided() {
    let inputs: [[u8; 12]; 4] = [
        [2; 12],
        [0; 12],
        [255; 12],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = AeadNonce::Provided(expected.clone());
        let AeadNonce::Provided(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_input_value_boolean() {
    let inputs: [bool; 2] = [true, false];
    for expected in inputs {
        let candidate = AttributeInputValue::Boolean(expected.clone());
        let AttributeInputValue::Boolean(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_input_value_bytes() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = AttributeInputValue::Bytes(expected);
        let AttributeInputValue::Bytes(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_input_value_date() {
    let inputs: [[u8; 8]; 4] = [
        [2; 8],
        [0; 8],
        [255; 8],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = AttributeInputValue::Date(expected.clone());
        let AttributeInputValue::Date(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_input_value_unsigned() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = AttributeInputValue::Unsigned(expected.clone());
        let AttributeInputValue::Unsigned(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_input_value_unsigned_array() {
    let inputs: [&[u64]; 5] = [&[], &[0], &[1], &[u64::MAX], &[0, 1, u64::MAX]];
    for expected in inputs {
        let candidate = AttributeInputValue::UnsignedArray(expected);
        let AttributeInputValue::UnsignedArray(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_input_value_version() {
    let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
    for expected in inputs {
        let candidate = AttributeInputValue::Version(expected.clone(), 4);
        let AttributeInputValue::Version(actual, _) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
    let inputs: [u8; 4] = [4, 0, 1, u8::MAX];
    for expected in inputs {
        let candidate = AttributeInputValue::Version(3, expected.clone());
        let AttributeInputValue::Version(_, actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn attribute_value_available() {
    let inputs: [Vec<u8>; 5] = [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![42],
    ];
    for expected in inputs {
        let candidate = AttributeValue::Available(expected.clone());
        let AttributeValue::Available(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn cipher_parameters_aes() {
    let inputs: [AesCipherParameters; 8] = [
        AesCipherParameters::Cbc { iv: [3; 16] },
        AesCipherParameters::CbcPad { iv: [3; 16] },
        AesCipherParameters::Cfb128 { iv: [3; 16] },
        AesCipherParameters::Cfb64 { iv: [3; 16] },
        AesCipherParameters::Cfb8 { iv: [3; 16] },
        AesCipherParameters::Ctr {
            counter_bits: 4,
            counter_block: [4; 16],
        },
        AesCipherParameters::Ecb,
        AesCipherParameters::Ofb { iv: [3; 16] },
    ];
    for expected in inputs {
        let candidate = CipherParameters::Aes(expected.clone());
        let CipherParameters::Aes(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn cipher_parameters_aes_key_wrap() {
    let inputs: [Option<[u8; 8]>; 5] = [
        None,
        Some([2; 8]),
        Some([0; 8]),
        Some([255; 8]),
        Some(std::array::from_fn(|i| i as u8 ^ 35)),
    ];
    for expected in inputs {
        let candidate = CipherParameters::AesKeyWrap {
            iv: expected.clone(),
        };
        let CipherParameters::AesKeyWrap { iv, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iv, expected);
    }
}

#[test]
fn cipher_parameters_aes_key_wrap_pad() {
    let inputs: [Option<[u8; 8]>; 5] = [
        None,
        Some([2; 8]),
        Some([0; 8]),
        Some([255; 8]),
        Some(std::array::from_fn(|i| i as u8 ^ 35)),
    ];
    for expected in inputs {
        let candidate = CipherParameters::AesKeyWrapPad {
            iv: expected.clone(),
        };
        let CipherParameters::AesKeyWrapPad { iv, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iv, expected);
    }
}

#[test]
fn cipher_parameters_aes_key_wrap_pkcs7() {
    let inputs: [Option<[u8; 8]>; 5] = [
        None,
        Some([2; 8]),
        Some([0; 8]),
        Some([255; 8]),
        Some(std::array::from_fn(|i| i as u8 ^ 35)),
    ];
    for expected in inputs {
        let candidate = CipherParameters::AesKeyWrapPkcs7 {
            iv: expected.clone(),
        };
        let CipherParameters::AesKeyWrapPkcs7 { iv, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iv, expected);
    }
}

#[test]
fn cipher_parameters_gost28147() {
    let inputs: [Option<[u8; 8]>; 5] = [
        None,
        Some([2; 8]),
        Some([0; 8]),
        Some([255; 8]),
        Some(std::array::from_fn(|i| i as u8 ^ 35)),
    ];
    for expected in inputs {
        let candidate = CipherParameters::Gost28147 {
            iv: expected.clone(),
        };
        let CipherParameters::Gost28147 { iv, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iv, expected);
    }
}

#[test]
fn cipher_parameters_token_iv() {
    let inputs: [TokenIvCipher; 16] = [
        TokenIvCipher::BatonCbc128,
        TokenIvCipher::BatonCounter,
        TokenIvCipher::BatonEcb128,
        TokenIvCipher::BatonEcb96,
        TokenIvCipher::BatonShuffle,
        TokenIvCipher::JuniperCbc128,
        TokenIvCipher::JuniperCounter,
        TokenIvCipher::JuniperEcb128,
        TokenIvCipher::JuniperShuffle,
        TokenIvCipher::SkipjackCbc64,
        TokenIvCipher::SkipjackCfb16,
        TokenIvCipher::SkipjackCfb32,
        TokenIvCipher::SkipjackCfb64,
        TokenIvCipher::SkipjackCfb8,
        TokenIvCipher::SkipjackEcb64,
        TokenIvCipher::SkipjackOfb64,
    ];
    for expected in inputs {
        let candidate = CipherParameters::TokenIv {
            cipher: expected.clone(),
            iv: TokenIv::Generate,
        };
        let CipherParameters::TokenIv { cipher, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(cipher, expected);
    }
    let inputs: [TokenIv; 2] = [TokenIv::Generate, TokenIv::Provided([4; 24])];
    for expected in inputs {
        let candidate = CipherParameters::TokenIv {
            cipher: TokenIvCipher::BatonCbc128,
            iv: expected.clone(),
        };
        let CipherParameters::TokenIv { iv, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iv, expected);
    }
}

#[test]
fn classic_aead_parameters_stream() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = ClassicAeadParameters::Stream {
            aad: expected,
            nonce: StreamAeadNonce::ChaCha20([4; 8]),
        };
        let ClassicAeadParameters::Stream { aad, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(aad, expected);
    }
    let inputs: [StreamAeadNonce; 5] = [
        StreamAeadNonce::ChaCha20([4; 8]),
        StreamAeadNonce::ChaCha20Ietf([4; 12]),
        StreamAeadNonce::Salsa20([4; 8]),
        StreamAeadNonce::XChaCha20([4; 24]),
        StreamAeadNonce::XSalsa20([4; 24]),
    ];
    for expected in inputs {
        let candidate = ClassicAeadParameters::Stream {
            aad: &[],
            nonce: expected.clone(),
        };
        let ClassicAeadParameters::Stream { nonce, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(nonce, expected);
    }
}

#[test]
fn content_status_unavailable() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = ContentStatus::Unavailable {
            attribute: expected.clone(),
            cause: AttributeUnavailableCause::Sensitive,
        };
        let ContentStatus::Unavailable { attribute, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(attribute, expected);
    }
    let inputs: [AttributeUnavailableCause; 3] = [
        AttributeUnavailableCause::Sensitive,
        AttributeUnavailableCause::Unspecified,
        AttributeUnavailableCause::Unsupported,
    ];
    for expected in inputs {
        let candidate = ContentStatus::Unavailable {
            attribute: 3,
            cause: expected.clone(),
        };
        let ContentStatus::Unavailable { cause, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(cause, expected);
    }
}

#[test]
fn content_status_unusable() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = ContentStatus::Unusable {
            attribute: expected.clone(),
            issue: ContentIssue::EmptyPublicMaterial,
        };
        let ContentStatus::Unusable { attribute, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(attribute, expected);
    }
    let inputs: [ContentIssue; 4] = [
        ContentIssue::EmptyPublicMaterial,
        ContentIssue::IntegerEncoding,
        ContentIssue::NotPublicKey,
        ContentIssue::ObjectChanged,
    ];
    for expected in inputs {
        let candidate = ContentStatus::Unusable {
            attribute: 3,
            issue: expected.clone(),
        };
        let ContentStatus::Unusable { issue, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(issue, expected);
    }
}

#[test]
fn derivation_path_ecdh() {
    let inputs: [EcdhKdf; 4] = [
        EcdhKdf::ConcatSha256,
        EcdhKdf::Native(4),
        EcdhKdf::Null,
        EcdhKdf::X963Sha256,
    ];
    for expected in inputs {
        let candidate = DerivationPath::Ecdh(expected.clone());
        let DerivationPath::Ecdh(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn derivation_path_hkdf_expand_with_hash() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = DerivationPath::HkdfExpandWithHash(expected.clone());
        let DerivationPath::HkdfExpandWithHash(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn derivation_path_hkdf_extract_expand_with_hash() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = DerivationPath::HkdfExtractExpandWithHash(expected.clone());
        let DerivationPath::HkdfExtractExpandWithHash(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn derivation_path_hkdf_extract_with_hash() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = DerivationPath::HkdfExtractWithHash(expected.clone());
        let DerivationPath::HkdfExtractWithHash(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn dual_cipher_gcm() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = DualCipher::Gcm {
            aad: expected,
            nonce: AeadNonce::BackendRandom,
        };
        let DualCipher::Gcm { aad, .. } = candidate else {
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
        let candidate = DualCipher::Gcm {
            aad: &[],
            nonce: expected.clone(),
        };
        let DualCipher::Gcm { nonce, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(nonce, expected);
    }
}

#[test]
fn ecdh_kdf_native() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = EcdhKdf::Native(expected.clone());
        let EcdhKdf::Native(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}
