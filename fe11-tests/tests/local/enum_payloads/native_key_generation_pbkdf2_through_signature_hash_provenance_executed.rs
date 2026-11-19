// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn native_key_generation_pbkdf2() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Pbkdf2 {
            iterations: expected.clone(),
            layout: Pbkdf2Layout::Current,
            password: &[],
            prf: 6,
            prf_data: None,
            salt: &[],
        };
        let NativeKeyGeneration::Pbkdf2 { iterations, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(iterations, expected);
    }
    let inputs: [Pbkdf2Layout; 2] = [Pbkdf2Layout::Current, Pbkdf2Layout::Historical];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Pbkdf2 {
            iterations: 3,
            layout: expected.clone(),
            password: &[],
            prf: 6,
            prf_data: None,
            salt: &[],
        };
        let NativeKeyGeneration::Pbkdf2 { layout, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(layout, expected);
    }
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Pbkdf2 {
            iterations: 3,
            layout: Pbkdf2Layout::Current,
            password: expected,
            prf: 6,
            prf_data: None,
            salt: &[],
        };
        let NativeKeyGeneration::Pbkdf2 { password, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(password, expected);
    }
    let inputs: [u64; 4] = [6, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Pbkdf2 {
            iterations: 3,
            layout: Pbkdf2Layout::Current,
            password: &[],
            prf: expected.clone(),
            prf_data: None,
            salt: &[],
        };
        let NativeKeyGeneration::Pbkdf2 { prf, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(prf, expected);
    }
    let inputs: [Option<&[u8]>; 6] = [
        None,
        Some(&[]),
        Some(&[0]),
        Some(&[0xff]),
        Some(&[0, 1, 0xfe, 0xff]),
        Some(&[46]),
    ];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Pbkdf2 {
            iterations: 3,
            layout: Pbkdf2Layout::Current,
            password: &[],
            prf: 6,
            prf_data: expected.clone(),
            salt: &[],
        };
        let NativeKeyGeneration::Pbkdf2 { prf_data, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(prf_data, expected);
    }
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[47]];
    for expected in inputs {
        let candidate = NativeKeyGeneration::Pbkdf2 {
            iterations: 3,
            layout: Pbkdf2Layout::Current,
            password: &[],
            prf: 6,
            prf_data: None,
            salt: expected,
        };
        let NativeKeyGeneration::Pbkdf2 { salt, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(salt, expected);
    }
}

#[test]
fn native_mac_parameters_rc2() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeMacParameters::Rc2 {
            effective_bits: expected.clone(),
            output_bytes: None,
        };
        let NativeMacParameters::Rc2 { effective_bits, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(effective_bits, expected);
    }
    let inputs: [Option<u64>; 5] = [None, Some(4), Some(0), Some(1), Some(u64::MAX)];
    for expected in inputs {
        let candidate = NativeMacParameters::Rc2 {
            effective_bits: 3,
            output_bytes: expected.clone(),
        };
        let NativeMacParameters::Rc2 { output_bytes, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(output_bytes, expected);
    }
}

#[test]
fn native_mac_parameters_rc5() {
    let inputs: [Option<u64>; 5] = [None, Some(3), Some(0), Some(1), Some(u64::MAX)];
    for expected in inputs {
        let candidate = NativeMacParameters::Rc5 {
            output_bytes: expected.clone(),
            rounds: 4,
            word_bytes: 5,
        };
        let NativeMacParameters::Rc5 { output_bytes, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(output_bytes, expected);
    }
    let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeMacParameters::Rc5 {
            output_bytes: None,
            rounds: expected.clone(),
            word_bytes: 5,
        };
        let NativeMacParameters::Rc5 { rounds, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(rounds, expected);
    }
    let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeMacParameters::Rc5 {
            output_bytes: None,
            rounds: 4,
            word_bytes: expected.clone(),
        };
        let NativeMacParameters::Rc5 { word_bytes, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(word_bytes, expected);
    }
}

#[test]
fn native_otp_parameter_challenge() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeOtpParameter::Challenge(expected);
        let NativeOtpParameter::Challenge(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_counter() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeOtpParameter::Counter(expected);
        let NativeOtpParameter::Counter(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_flags() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeOtpParameter::Flags(expected.clone());
        let NativeOtpParameter::Flags(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_output_format() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeOtpParameter::OutputFormat(expected.clone());
        let NativeOtpParameter::OutputFormat(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_output_length() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = NativeOtpParameter::OutputLength(expected.clone());
        let NativeOtpParameter::OutputLength(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_pin() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeOtpParameter::Pin(expected);
        let NativeOtpParameter::Pin(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_time() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeOtpParameter::Time(expected);
        let NativeOtpParameter::Time(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_otp_parameter_value() {
    let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
    for expected in inputs {
        let candidate = NativeOtpParameter::Value(expected);
        let NativeOtpParameter::Value(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn notification_other() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = Notification::Other(expected.clone());
        let Notification::Other(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn observation_issue_content_interpretation() {
    let inputs: [ContentIssue; 4] = [
        ContentIssue::EmptyPublicMaterial,
        ContentIssue::IntegerEncoding,
        ContentIssue::NotPublicKey,
        ContentIssue::ObjectChanged,
    ];
    for expected in inputs {
        let candidate = ObservationIssue::ContentInterpretation(expected.clone());
        let ObservationIssue::ContentInterpretation(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn observation_issue_destination_operand_absent() {
    let inputs: [IdentityAttribute; 7] = [
        IdentityAttribute::Application,
        IdentityAttribute::Class,
        IdentityAttribute::Id,
        IdentityAttribute::KeyType,
        IdentityAttribute::Label,
        IdentityAttribute::ObjectId,
        IdentityAttribute::UniqueId,
    ];
    for expected in inputs {
        let candidate = ObservationIssue::DestinationOperandAbsent(expected.clone());
        let ObservationIssue::DestinationOperandAbsent(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn operation_progress_sha256() {
    let inputs: [[u8; 32]; 4] = [
        [2; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = OperationProgress::Sha256(expected.clone());
        let OperationProgress::Sha256(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn operation_progress_sha256_with_validation() {
    let inputs: [[u8; 32]; 4] = [
        [2; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 35),
    ];
    for expected in inputs {
        let candidate = OperationProgress::Sha256WithValidation {
            digest: expected.clone(),
            validation: SessionValidation::Reported(5),
        };
        let OperationProgress::Sha256WithValidation { digest, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(digest, expected);
    }
    let inputs: [SessionValidation; 2] = [
        SessionValidation::Reported(5),
        SessionValidation::Unavailable,
    ];
    for expected in inputs {
        let candidate = OperationProgress::Sha256WithValidation {
            digest: [2; 32],
            validation: expected.clone(),
        };
        let OperationProgress::Sha256WithValidation { validation, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(validation, expected);
    }
}

#[test]
fn pqc_algorithm_ml_dsa() {
    let inputs: [MlDsaParameterSet; 3] = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    for expected in inputs {
        let candidate = PqcAlgorithm::MlDsa(expected.clone());
        let PqcAlgorithm::MlDsa(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn pqc_algorithm_slh_dsa() {
    let inputs: [SlhDsaParameterSet; 12] = [
        SlhDsaParameterSet::Sha2_128f,
        SlhDsaParameterSet::Sha2_128s,
        SlhDsaParameterSet::Sha2_192f,
        SlhDsaParameterSet::Sha2_192s,
        SlhDsaParameterSet::Sha2_256f,
        SlhDsaParameterSet::Sha2_256s,
        SlhDsaParameterSet::Shake128f,
        SlhDsaParameterSet::Shake128s,
        SlhDsaParameterSet::Shake192f,
        SlhDsaParameterSet::Shake192s,
        SlhDsaParameterSet::Shake256f,
        SlhDsaParameterSet::Shake256s,
    ];
    for expected in inputs {
        let candidate = PqcAlgorithm::SlhDsa(expected.clone());
        let PqcAlgorithm::SlhDsa(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn pqc_private_key_algorithm_ml_dsa() {
    let inputs: [MlDsaParameterSet; 3] = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    for expected in inputs {
        let candidate = PqcPrivateKeyAlgorithm::MlDsa(expected.clone());
        let PqcPrivateKeyAlgorithm::MlDsa(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn pqc_private_key_algorithm_ml_kem() {
    let inputs: [MlKemParameterSet; 3] = [
        MlKemParameterSet::MlKem1024,
        MlKemParameterSet::MlKem512,
        MlKemParameterSet::MlKem768,
    ];
    for expected in inputs {
        let candidate = PqcPrivateKeyAlgorithm::MlKem(expected.clone());
        let PqcPrivateKeyAlgorithm::MlKem(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn pqc_signature_mode_hash_message() {
    let inputs: [PqcHash; 12] = [
        PqcHash::Sha224,
        PqcHash::Sha256,
        PqcHash::Sha384,
        PqcHash::Sha3_224,
        PqcHash::Sha3_256,
        PqcHash::Sha3_384,
        PqcHash::Sha3_512,
        PqcHash::Sha512,
        PqcHash::Sha512_224,
        PqcHash::Sha512_256,
        PqcHash::Shake128,
        PqcHash::Shake256,
    ];
    for expected in inputs {
        let candidate = PqcSignatureMode::HashMessage(expected.clone());
        let PqcSignatureMode::HashMessage(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn pqc_signature_mode_prehashed() {
    let inputs: [PqcHash; 12] = [
        PqcHash::Sha224,
        PqcHash::Sha256,
        PqcHash::Sha384,
        PqcHash::Sha3_224,
        PqcHash::Sha3_256,
        PqcHash::Sha3_384,
        PqcHash::Sha3_512,
        PqcHash::Sha512,
        PqcHash::Sha512_224,
        PqcHash::Sha512_256,
        PqcHash::Shake128,
        PqcHash::Shake256,
    ];
    for expected in inputs {
        let candidate = PqcSignatureMode::Prehashed(expected.clone());
        let PqcSignatureMode::Prehashed(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn protected_content_unavailable() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = ProtectedContent::Unavailable {
            attribute: expected.clone(),
            cause: AttributeUnavailableCause::Sensitive,
        };
        let ProtectedContent::Unavailable { attribute, .. } = candidate else {
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
        let candidate = ProtectedContent::Unavailable {
            attribute: 3,
            cause: expected.clone(),
        };
        let ProtectedContent::Unavailable { cause, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(cause, expected);
    }
}

#[test]
fn protected_content_unusable() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = ProtectedContent::Unusable {
            attribute: expected.clone(),
            issue: ContentIssue::EmptyPublicMaterial,
        };
        let ProtectedContent::Unusable { attribute, .. } = candidate else {
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
        let candidate = ProtectedContent::Unusable {
            attribute: 3,
            issue: expected.clone(),
        };
        let ProtectedContent::Unusable { issue, .. } = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(issue, expected);
    }
}

#[test]
fn recover_mechanism_parameterless() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = RecoverMechanism::Parameterless(expected.clone());
        let RecoverMechanism::Parameterless(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn rsa_signature_profile_pkcs1() {
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
        let candidate = RsaSignatureProfile::Pkcs1(expected.clone());
        let RsaSignatureProfile::Pkcs1(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn session_validation_reported() {
    let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
    for expected in inputs {
        let candidate = SessionValidation::Reported(expected.clone());
        let SessionValidation::Reported(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn signature_hash_provenance_executed() {
    let inputs: [HashExecution; 3] = [
        HashExecution::Pkcs11Combined,
        HashExecution::Pkcs11DigestThenPrimitive,
        HashExecution::RustSoftware,
    ];
    for expected in inputs {
        let candidate = SignatureHashProvenance::Executed(expected.clone());
        let SignatureHashProvenance::Executed(actual) = candidate else {
            panic!("unexpected variant")
        };
        assert_eq!(actual, expected);
    }
}
