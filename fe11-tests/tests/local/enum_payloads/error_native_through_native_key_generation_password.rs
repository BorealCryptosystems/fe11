// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn flat_attribute_value_unavailable() {
    let inputs: [AttributeUnavailableCause; 3] = [
        AttributeUnavailableCause::Sensitive,
        AttributeUnavailableCause::Unspecified,
        AttributeUnavailableCause::Unsupported,
    ];
    for expected in inputs {
        let candidate = FlatAttributeValue::Unavailable(expected.clone());
        let FlatAttributeValue::Unavailable(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn foreign_scope_slot() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = ForeignScope::Slot(expected.clone());
        let ForeignScope::Slot(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn generation_observation_mechanism() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = GenerationObservation::Mechanism(expected.clone());
        let GenerationObservation::Mechanism(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn hash_provenance_executed() {
    let inputs: [HashExecution; 3] = [
        HashExecution::Pkcs11Combined,
        HashExecution::Pkcs11DigestThenPrimitive,
        HashExecution::RustSoftware,
    ];
    for expected in inputs {
        let candidate = HashProvenance::Executed(expected.clone());
        let HashProvenance::Executed(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn historical_profile_dsa() {
    let inputs: [DsaVerificationHash; 5] = [
        DsaVerificationHash::Sha1,
        DsaVerificationHash::Sha224,
        DsaVerificationHash::Sha256,
        DsaVerificationHash::Sha384,
        DsaVerificationHash::Sha512,
    ];
    for expected in inputs {
        let candidate = HistoricalProfile::Dsa(expected.clone());
        let HistoricalProfile::Dsa(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn historical_profile_rsa_pkcs1() {
    let inputs: [HistoricalHash; 2] = [HistoricalHash::Md5, HistoricalHash::Sha1];
    for expected in inputs {
        let candidate = HistoricalProfile::RsaPkcs1(expected.clone());
        let HistoricalProfile::RsaPkcs1(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn hkdf_salt_data() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = HkdfSalt::Data(expected);
        let HkdfSalt::Data(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn login_role_vendor_extension() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = LoginRole::VendorExtension(expected.clone());
        let LoginRole::VendorExtension(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn managed_class_other() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = ManagedClass::Other(expected.clone());
        let ManagedClass::Other(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn mechanism_request_explicit() {
    let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
    for expected in inputs {
        let candidate = MechanismRequest::Explicit {
            maximum_bytes: expected.clone(),
            mechanisms: &[],
        };
        let MechanismRequest::Explicit { maximum_bytes, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(maximum_bytes, expected);
    }
    let inputs: [&[u64]; 5] = [&[], &[0], &[1], &[u64::MAX], &[0, 1, u64::MAX]];
    for expected in inputs {
        let candidate = MechanismRequest::Explicit {
            maximum_bytes: 3,
            mechanisms: expected,
        };
        let MechanismRequest::Explicit { mechanisms, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(mechanisms, expected);
    }
}

#[test]
fn message_aead_parameters_gcm() {
    let inputs: [AeadNonce; 3] = [
        AeadNonce::BackendRandom,
        AeadNonce::Gcm {
            fixed_bits: 4,
            generator: 5,
            iv: std::sync::Arc::from(&[][..]),
            tag_bits: 7,
        },
        AeadNonce::Provided([3; 12]),
    ];
    for expected in inputs {
        let candidate = MessageAeadParameters::Gcm(expected.clone());
        let MessageAeadParameters::Gcm(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn message_aead_parameters_stream() {
    let inputs: [StreamAeadNonce; 5] = [
        StreamAeadNonce::ChaCha20([3; 8]),
        StreamAeadNonce::ChaCha20Ietf([3; 12]),
        StreamAeadNonce::Salsa20([3; 8]),
        StreamAeadNonce::XChaCha20([3; 24]),
        StreamAeadNonce::XSalsa20([3; 24]),
    ];
    for expected in inputs {
        let candidate = MessageAeadParameters::Stream(expected.clone());
        let MessageAeadParameters::Stream(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn module_integrity_sha256() {
    let inputs: [[u8; 32]; 4] = [
        [2; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = ModuleIntegrity::Sha256 {
            expected: expected.clone(),
            on_mismatch: ModuleDigestMismatch::Refuse,
        };
        let ModuleIntegrity::Sha256 { expected, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(expected, expected);
    }
    let inputs: [ModuleDigestMismatch; 2] =
        [ModuleDigestMismatch::Refuse, ModuleDigestMismatch::Report];
    for expected in inputs {
        let candidate = ModuleIntegrity::Sha256 {
            expected: [2; 32],
            on_mismatch: expected.clone(),
        };
        let ModuleIntegrity::Sha256 { on_mismatch, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(on_mismatch, expected);
    }
}

#[test]
fn native_derivation_output_wtls_version() {
    let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
    for expected in inputs {
        let candidate = NativeDerivationOutput::WtlsVersion(expected.clone());
        let NativeDerivationOutput::WtlsVersion(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_encrypt_data_aes_ecb() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeEncryptData::AesEcb(expected);
        let NativeEncryptData::AesEcb(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_encrypt_data_aria_ecb() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeEncryptData::AriaEcb(expected);
        let NativeEncryptData::AriaEcb(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_encrypt_data_camellia_ecb() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeEncryptData::CamelliaEcb(expected);
        let NativeEncryptData::CamelliaEcb(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_encrypt_data_des3_ecb() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeEncryptData::Des3Ecb(expected);
        let NativeEncryptData::Des3Ecb(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_encrypt_data_des_ecb() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeEncryptData::DesEcb(expected);
        let NativeEncryptData::DesEcb(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_encrypt_data_seed_ecb() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeEncryptData::SeedEcb(expected);
        let NativeEncryptData::SeedEcb(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_hkdf_salt_data() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeHkdfSalt::Data(expected);
        let NativeHkdfSalt::Data(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_key_derivation_concatenate_data() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeKeyDerivation::ConcatenateData {
            data: expected,
            placement: DerivationDataPlacement::AfterBase,
        };
        let NativeKeyDerivation::ConcatenateData { data, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(data, expected);
    }
    let inputs: [DerivationDataPlacement; 2] = [
        DerivationDataPlacement::AfterBase,
        DerivationDataPlacement::BeforeBase,
    ];
    for expected in inputs {
        let candidate = NativeKeyDerivation::ConcatenateData {
            data: &[],
            placement: expected.clone(),
        };
        let NativeKeyDerivation::ConcatenateData { placement, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(placement, expected);
    }
}

#[test]
fn native_key_derivation_null() {
    let inputs: [ManagedClass; 13] = [
        ManagedClass::Certificate,
        ManagedClass::Data,
        ManagedClass::DomainParameters,
        ManagedClass::HardwareFeature,
        ManagedClass::Mechanism,
        ManagedClass::Other(4),
        ManagedClass::OtpKey,
        ManagedClass::PrivateKey,
        ManagedClass::Profile,
        ManagedClass::PublicKey,
        ManagedClass::SecretKey,
        ManagedClass::Trust,
        ManagedClass::Validation,
    ];
    for expected in inputs {
        let candidate = NativeKeyDerivation::Null {
            class: expected.clone(),
        };
        let NativeKeyDerivation::Null { class, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(class, expected);
    }
}

#[test]
fn native_key_generation_password() {
    let inputs: [PasswordKeyGenerator; 13] = [
        PasswordKeyGenerator::Md2Des,
        PasswordKeyGenerator::Md5Cast,
        PasswordKeyGenerator::Md5Cast128,
        PasswordKeyGenerator::Md5Cast3,
        PasswordKeyGenerator::Md5Des,
        PasswordKeyGenerator::Sha1Cast128,
        PasswordKeyGenerator::Sha1Des2,
        PasswordKeyGenerator::Sha1Des3,
        PasswordKeyGenerator::Sha1Hmac,
        PasswordKeyGenerator::Sha1Rc2_128,
        PasswordKeyGenerator::Sha1Rc2_40,
        PasswordKeyGenerator::Sha1Rc4_128,
        PasswordKeyGenerator::Sha1Rc4_40,
    ];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Password {
            generator: expected.clone(),
            iterations: 4,
            password: &[],
            salt: &[],
        };
        let NativeKeyGeneration::Password { generator, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(generator, expected);
    }
    let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Password {
            generator: PasswordKeyGenerator::Md2Des,
            iterations: expected.clone(),
            password: &[],
            salt: &[],
        };
        let NativeKeyGeneration::Password { iterations, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iterations, expected);
    }
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Password {
            generator: PasswordKeyGenerator::Md2Des,
            iterations: 4,
            password: expected,
            salt: &[],
        };
        let NativeKeyGeneration::Password { password, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(password, expected);
    }
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[45]];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Password {
            generator: PasswordKeyGenerator::Md2Des,
            iterations: 4,
            password: &[],
            salt: expected,
        };
        let NativeKeyGeneration::Password { salt, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(salt, expected);
    }
}
