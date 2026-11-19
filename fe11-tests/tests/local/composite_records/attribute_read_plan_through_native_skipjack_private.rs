// SPDX-License-Identifier: Apache-2.0
//! Construction and readback of independently varied public fields.
use fe11::*;

#[test]
fn attribute_read_plan() {
    let base = || AttributeReadPlan {
        clarification: AttributeClarification::BatchOnly,
        maximum_bytes: 4,
    };
    check_field!(base(), clarification, AttributeClarification, [
        AttributeClarification::BatchOnly,
        AttributeClarification::ClarifyIndeterminate,
    ]);
    check_field!(base(), maximum_bytes, usize, [
        4,
        0,
        1,
        usize::MAX,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn ccm_message_ciphertext() {
    let base = || CcmMessageCiphertext {
        ciphertext: &[],
        mac: &[],
        nonce: &[],
    };
    check_field!(base(), ciphertext, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), mac, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), nonce, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
}

#[test]
fn ccm_nonce() {
    let base = || CcmNonce {
        bytes: std::sync::Arc::from(&[][..]),
        fixed_bits: 4,
        generator: 5,
    };
    check_field!(base(), bytes, std::sync::Arc<[u8]>, [
        std::sync::Arc::from(&[][..]),
        std::sync::Arc::from(&[0u8][..]),
        std::sync::Arc::from(&[255u8][..]),
        std::sync::Arc::from(&[0u8, 1, 254, 255][..]),
    ]);
    check_field!(base(), fixed_bits, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), generator, u64, [
        5,
        0,
        1,
        u64::MAX,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn ccm_rejection() {
    let base = || CcmRejection {
        cleanup_code: 3,
        code: 4,
        function: "",
    };
    check_field!(base(), cleanup_code, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), code, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), function, &'static str, [
        "",
        "abc",
        "é",
        "a\0b",
        "field2",
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn cipher_buffer_request() {
    let base = || CipherBufferRequest {
        code: 3,
        function: "",
        previous_capacity: 5,
        required: 6,
    };
    check_field!(base(), code, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), function, &'static str, [
        "",
        "abc",
        "é",
        "a\0b",
        "field1",
    ]);
    check_field!(base(), previous_capacity, usize, [
        5,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), required, usize, [
        6,
        0,
        1,
        usize::MAX,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn declared_gcm_message() {
    let base = || DeclaredGcmMessage {
        data: &[],
        nonce: &[],
        tag: &[],
        tag_bits: 6,
    };
    check_field!(base(), data, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), nonce, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), tag, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
    check_field!(base(), tag_bits, u64, [
        6,
        0,
        1,
        u64::MAX,
    ]);
}

#[test]
fn edwards_options() {
    let base = || EdwardsOptions {
        key_size_units: EdwardsKeySizeUnits::EncodedPointBits,
        parameter_encoding: EdwardsParameterEncoding::CurveName,
        point_encoding: EdwardsPointEncoding::DerOctetString,
    };
    check_field!(base(), key_size_units, EdwardsKeySizeUnits, [
        EdwardsKeySizeUnits::EncodedPointBits,
        EdwardsKeySizeUnits::FieldBits,
    ]);
    check_field!(base(), parameter_encoding, EdwardsParameterEncoding, [
        EdwardsParameterEncoding::CurveName,
        EdwardsParameterEncoding::Oid,
    ]);
    check_field!(base(), point_encoding, EdwardsPointEncoding, [
        EdwardsPointEncoding::DerOctetString,
        EdwardsPointEncoding::Raw,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn extension_block() {
    let base = || ExtensionBlock {
        alignment: 3,
        direction: ExtensionDirection::InOut,
        initial: &[],
    };
    check_field!(base(), alignment, usize, [
        3,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), direction, ExtensionDirection, [
        ExtensionDirection::InOut,
        ExtensionDirection::Input,
        ExtensionDirection::Output,
    ]);
    check_field!(base(), initial, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
}

#[test]
fn gcm_ciphertext() {
    let base = || GcmCiphertext {
        ciphertext: &[],
        nonce: &[],
        tag: &[],
        tag_bits: 6,
    };
    check_field!(base(), ciphertext, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), nonce, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), tag, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
    check_field!(base(), tag_bits, u64, [
        6,
        0,
        1,
        u64::MAX,
    ]);
}

#[test]
fn gcm_rejection() {
    let base = || GcmRejection {
        cleanup_code: 3,
        code: 4,
        function: "",
    };
    check_field!(base(), cleanup_code, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), code, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), function, &'static str, [
        "",
        "abc",
        "é",
        "a\0b",
        "field2",
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn historical_pss_parameters() {
    let base = || HistoricalPssParameters {
        hash: HistoricalHash::Md5,
        mgf_hash: HistoricalHash::Md5,
        salt_length: 5,
    };
    check_field!(base(), hash, HistoricalHash, [
        HistoricalHash::Md5,
        HistoricalHash::Sha1,
    ]);
    check_field!(base(), mgf_hash, HistoricalHash, [
        HistoricalHash::Md5,
        HistoricalHash::Sha1,
    ]);
    check_field!(base(), salt_length, usize, [
        5,
        0,
        1,
        usize::MAX,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn initialization_options() {
    let base = || InitializationOptions {
        cannot_create_os_threads: true,
        concurrency: NativeConcurrency::ApplicationMutexes,
    };
    check_field!(base(), cannot_create_os_threads, bool, [
        true,
        false,
    ]);
    check_field!(base(), concurrency, NativeConcurrency, [
        NativeConcurrency::ApplicationMutexes,
        NativeConcurrency::Concurrent,
        NativeConcurrency::Serialized,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn kea_request() {
    let base = || KeaRequest {
        mechanism: KeaMechanism::Derive,
        peer_public: &[],
        random_a: &[],
        random_b: &[],
        sender: true,
    };
    check_field!(base(), mechanism, KeaMechanism, [
        KeaMechanism::Derive,
        KeaMechanism::KeyDerive,
    ]);
    check_field!(base(), peer_public, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), random_a, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
    check_field!(base(), random_b, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[45],
    ]);
    check_field!(base(), sender, bool, [
        true,
        false,
    ]);
}

#[test]
fn key_usage_request() {
    let base = || KeyUsageRequest {
        always_authenticate: None,
        decapsulate: None,
        decrypt: None,
        derive: None,
        encapsulate: None,
        encrypt: None,
        sign: None,
        sign_recover: None,
        trusted: None,
        unwrap: None,
        verify: None,
        verify_recover: None,
        wrap: None,
        wrap_with_trusted: None,
    };
    check_field!(base(), always_authenticate, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), decapsulate, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), decrypt, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), derive, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), encapsulate, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), encrypt, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), sign, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), sign_recover, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), trusted, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), unwrap, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), verify, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), verify_recover, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), wrap, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    check_field!(base(), wrap_with_trusted, Option<bool>, [
        None,
        Some(false),
        Some(true),
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn message_aead_rejection() {
    let base = || MessageAeadRejection {
        code: 3,
        function: "",
    };
    check_field!(base(), code, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), function, &'static str, [
        "",
        "abc",
        "é",
        "a\0b",
        "field1",
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn module_file_observation() {
    let base = || ModuleFileObservation {
        path: std::path::PathBuf::from(""),
        sha256: [3; 32],
    };
    check_field!(base(), path, std::path::PathBuf, [
        std::path::PathBuf::from(""),
        std::path::PathBuf::from("file"),
        std::path::PathBuf::from("é"),
        std::path::PathBuf::from("a\0b"),
    ]);
    check_field!(base(), sha256, [u8; 32], [
        [3; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 36),
    ]);
}

#[test]
fn native_ed_dsa_parameters() {
    let base = || NativeEdDsaParameters {
        context: None,
        prehash: true,
    };
    check_field!(base(), context, Option<&[u8]>, [
        None,
        Some(&[]),
        Some(&[0]),
        Some(&[0xff]),
        Some(&[0, 1, 0xfe, 0xff]),
        Some(&[42]),
    ]);
    check_field!(base(), prehash, bool, [
        true,
        false,
    ]);
}

#[test]
fn native_library_info() {
    let base = || NativeLibraryInfo {
        cryptoki_version: (2, 8),
        description: [3; 32],
        flags: 5,
        library_version: (5, 11),
        manufacturer: [6; 32],
    };
    check_field!(base(), cryptoki_version, (u8, u8), [
        (2, 8),
        (0, 0),
        (1, 255),
        (255, 1),
    ]);
    check_field!(base(), description, [u8; 32], [
        [3; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 36),
    ]);
    check_field!(base(), flags, u64, [
        5,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), library_version, (u8, u8), [
        (5, 11),
        (0, 0),
        (1, 255),
        (255, 1),
    ]);
    check_field!(base(), manufacturer, [u8; 32], [
        [6; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 39),
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn native_message_rejection() {
    let base = || NativeMessageRejection {
        code: 3,
        function: "",
    };
    check_field!(base(), code, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), function, &'static str, [
        "",
        "abc",
        "é",
        "a\0b",
        "field1",
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn native_oaep_parameters() {
    let base = || NativeOaepParameters {
        data: None,
        hash: 4,
        mgf: 5,
        source: 6,
    };
    check_field!(base(), data, Option<&[u8]>, [
        None,
        Some(&[]),
        Some(&[0]),
        Some(&[0xff]),
        Some(&[0, 1, 0xfe, 0xff]),
        Some(&[42]),
    ]);
    check_field!(base(), hash, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), mgf, u64, [
        5,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), source, u64, [
        6,
        0,
        1,
        u64::MAX,
    ]);
}

#[test]
fn native_otp_value() {
    let base = || NativeOtpValue {
        bytes: &[],
        kind: 4,
    };
    check_field!(base(), bytes, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), kind, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
}

#[test]
fn native_output_size() {
    let base = || NativeOutputSize {
        code: 3,
        function: "",
        limit: 5,
        reported: 6,
    };
    check_field!(base(), code, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), function, &'static str, [
        "",
        "abc",
        "é",
        "a\0b",
        "field1",
    ]);
    check_field!(base(), limit, usize, [
        5,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), reported, u64, [
        6,
        0,
        1,
        u64::MAX,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn native_pqc_context() {
    let base = || NativePqcContext {
        context: None,
        hedging: PqcHedging::DeterministicRequired,
    };
    check_field!(base(), context, Option<&[u8]>, [
        None,
        Some(&[]),
        Some(&[0]),
        Some(&[0xff]),
        Some(&[0, 1, 0xfe, 0xff]),
        Some(&[42]),
    ]);
    check_field!(base(), hedging, PqcHedging, [
        PqcHedging::DeterministicRequired,
        PqcHedging::Preferred,
        PqcHedging::Required,
    ]);
}

#[test]
fn native_skipjack_private() {
    let base = || NativeSkipjackPrivate {
        base: &[],
        password: &[],
        prime: &[],
        public_data: &[],
        random: &[],
        subprime: &[],
    };
    check_field!(base(), base, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), password, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), prime, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
    check_field!(base(), public_data, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[45],
    ]);
    check_field!(base(), random, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[46],
    ]);
    check_field!(base(), subprime, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[47],
    ]);
}

