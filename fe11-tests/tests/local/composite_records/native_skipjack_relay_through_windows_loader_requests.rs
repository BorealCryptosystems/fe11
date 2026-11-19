// SPDX-License-Identifier: Apache-2.0
//! Construction and readback of independently varied public fields.
use fe11::*;

#[test]
fn native_skipjack_relay() {
    let base = || NativeSkipjackRelay {
        new_password: &[],
        new_public_data: &[],
        new_random: &[],
        old_password: &[],
        old_public_data: &[],
        old_random: &[],
        wrapped: &[],
    };
    check_field!(base(), new_password, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), new_public_data, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), new_random, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[44],
    ]);
    check_field!(base(), old_password, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[45],
    ]);
    check_field!(base(), old_public_data, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[46],
    ]);
    check_field!(base(), old_random, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[47],
    ]);
    check_field!(base(), wrapped, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[48],
    ]);
}

#[test]
fn native_slot_info() {
    let base = || NativeSlotInfo {
        description: [2; 64],
        firmware_version: (3, 9),
        flags: 5,
        hardware_version: (5, 11),
        manufacturer: [6; 32],
    };
    check_field!(base(), description, [u8; 64], [
        [2; 64],
        [0; 64],
        [255; 64],
        std::array::from_fn(|i| i as u8 ^ 35),
    ]);
    check_field!(base(), firmware_version, (u8, u8), [
        (3, 9),
        (0, 0),
        (1, 255),
        (255, 1),
    ]);
    check_field!(base(), flags, u64, [
        5,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), hardware_version, (u8, u8), [
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
fn native_token_info() {
    let base = || NativeTokenInfo {
        firmware_version: (2, 8),
        flags: 4,
        free_private_memory: 5,
        free_public_memory: 6,
        hardware_version: (6, 12),
        label: [7; 32],
        manufacturer: [8; 32],
        maximum_pin_length: 10,
        maximum_read_write_sessions: 11,
        maximum_sessions: 12,
        minimum_pin_length: 13,
        model: [13; 16],
        read_write_sessions: 15,
        serial: [15; 16],
        sessions: 17,
        total_private_memory: 18,
        total_public_memory: 19,
        utc_time: [19; 16],
    };
    check_field!(base(), firmware_version, (u8, u8), [
        (2, 8),
        (0, 0),
        (1, 255),
        (255, 1),
    ]);
    check_field!(base(), flags, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), free_private_memory, u64, [
        5,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), free_public_memory, u64, [
        6,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), hardware_version, (u8, u8), [
        (6, 12),
        (0, 0),
        (1, 255),
        (255, 1),
    ]);
    check_field!(base(), label, [u8; 32], [
        [7; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 40),
    ]);
    check_field!(base(), manufacturer, [u8; 32], [
        [8; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 41),
    ]);
    check_field!(base(), maximum_pin_length, u64, [
        10,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), maximum_read_write_sessions, u64, [
        11,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), maximum_sessions, u64, [
        12,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), minimum_pin_length, u64, [
        13,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), model, [u8; 16], [
        [13; 16],
        [0; 16],
        [255; 16],
        std::array::from_fn(|i| i as u8 ^ 46),
    ]);
    check_field!(base(), read_write_sessions, u64, [
        15,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), serial, [u8; 16], [
        [15; 16],
        [0; 16],
        [255; 16],
        std::array::from_fn(|i| i as u8 ^ 48),
    ]);
    check_field!(base(), sessions, u64, [
        17,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), total_private_memory, u64, [
        18,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), total_public_memory, u64, [
        19,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), utc_time, [u8; 16], [
        [19; 16],
        [0; 16],
        [255; 16],
        std::array::from_fn(|i| i as u8 ^ 52),
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn oaep_params() {
    let base = || OaepParams {
        hash: 3,
        label: &[],
        mgf: 5,
    };
    check_field!(base(), hash, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), label, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
    check_field!(base(), mgf, u64, [
        5,
        0,
        1,
        u64::MAX,
    ]);
}

#[test]
fn object_limits() {
    let base = || ObjectLimits {
        destination_reservations: None,
        managed_references: None,
        object_references: None,
    };
    check_field!(base(), destination_reservations, Option<usize>, [
        None,
        Some(0),
        Some(1),
        Some(usize::MAX),
    ]);
    check_field!(base(), managed_references, Option<usize>, [
        None,
        Some(0),
        Some(1),
        Some(usize::MAX),
    ]);
    check_field!(base(), object_references, Option<usize>, [
        None,
        Some(0),
        Some(1),
        Some(usize::MAX),
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn ratchet_parameters() {
    let base = || RatchetParameters {
        aead: 3,
        curve: 4,
        encrypted_header: true,
        kdf: 6,
        shared_secret: &[],
    };
    check_field!(base(), aead, u64, [
        3,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), curve, u64, [
        4,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), encrypted_header, bool, [
        true,
        false,
    ]);
    check_field!(base(), kdf, u64, [
        6,
        0,
        1,
        u64::MAX,
    ]);
    check_field!(base(), shared_secret, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[46],
    ]);
}

#[test]
fn recovery_buffer_request() {
    let base = || RecoveryBufferRequest {
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
fn rsa_pss_parameters() {
    let base = || RsaPssParameters {
        hash: HashAlgorithm::Sha224,
        mgf_hash: HashAlgorithm::Sha224,
        salt_length: 5,
    };
    check_field!(base(), hash, HashAlgorithm, [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
    ]);
    check_field!(base(), mgf_hash, HashAlgorithm, [
        HashAlgorithm::Sha224,
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha3_224,
        HashAlgorithm::Sha3_256,
        HashAlgorithm::Sha3_384,
        HashAlgorithm::Sha3_512,
        HashAlgorithm::Sha512,
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
fn search_plan() {
    let base = || SearchPlan {
        batch_size: std::num::NonZeroUsize::new(1).unwrap(),
        maximum_objects: None,
    };
    check_field!(base(), batch_size, std::num::NonZeroUsize, [
        std::num::NonZeroUsize::new(1).unwrap(),
        std::num::NonZeroUsize::new(2).unwrap(),
        std::num::NonZeroUsize::new(usize::MAX).unwrap(),
    ]);
    check_field!(base(), maximum_objects, Option<usize>, [
        None,
        Some(0),
        Some(1),
        Some(usize::MAX),
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn signature_buffer_request() {
    let base = || SignatureBufferRequest {
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
fn stream_aead_ciphertext() {
    let base = || StreamAeadCiphertext {
        ciphertext: &[],
        nonce: &[],
        tag: &[],
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
}

#[test]
fn stream_aead_rejection() {
    let base = || StreamAeadRejection {
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
fn tls_randoms() {
    let base = || TlsRandoms {
        client: &[],
        server: &[],
    };
    check_field!(base(), client, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[42],
    ]);
    check_field!(base(), server, &[u8], [
        &[],
        &[0],
        &[0xff],
        &[0, 1, 0xfe, 0xff],
        &[43],
    ]);
}

#[test]
fn token_identity() {
    let base = || TokenIdentity {
        manufacturer: [2; 32],
        model: [3; 16],
        serial: [4; 16],
        slot: 6,
    };
    check_field!(base(), manufacturer, [u8; 32], [
        [2; 32],
        [0; 32],
        [255; 32],
        std::array::from_fn(|i| i as u8 ^ 35),
    ]);
    check_field!(base(), model, [u8; 16], [
        [3; 16],
        [0; 16],
        [255; 16],
        std::array::from_fn(|i| i as u8 ^ 36),
    ]);
    check_field!(base(), serial, [u8; 16], [
        [4; 16],
        [0; 16],
        [255; 16],
        std::array::from_fn(|i| i as u8 ^ 37),
    ]);
    check_field!(base(), slot, u64, [
        6,
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
fn windows_activation_file() {
    let base = || WindowsActivationFile {
        name: std::ffi::OsString::from(""),
        path: std::ffi::OsString::from(""),
    };
    check_field!(base(), name, std::ffi::OsString, [
        std::ffi::OsString::from(""),
        std::ffi::OsString::from("file"),
        std::ffi::OsString::from("é"),
        std::ffi::OsString::from("a\0b"),
    ]);
    check_field!(base(), path, std::ffi::OsString, [
        std::ffi::OsString::from(""),
        std::ffi::OsString::from("file"),
        std::ffi::OsString::from("é"),
        std::ffi::OsString::from("a\0b"),
    ]);
}

#[test]
fn windows_loader_observation_limits() {
    let base = || WindowsLoaderObservationLimits {
        maximum_activation_assemblies: 3,
        maximum_activation_files: 4,
        maximum_activation_query_bytes: std::num::NonZeroUsize::new(1).unwrap(),
        maximum_modules: 6,
        maximum_path_code_units: std::num::NonZeroUsize::new(1).unwrap(),
        maximum_registry_entries: 8,
        maximum_registry_value_bytes: std::num::NonZeroUsize::new(1).unwrap(),
    };
    check_field!(base(), maximum_activation_assemblies, usize, [
        3,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), maximum_activation_files, usize, [
        4,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), maximum_activation_query_bytes, std::num::NonZeroUsize, [
        std::num::NonZeroUsize::new(1).unwrap(),
        std::num::NonZeroUsize::new(2).unwrap(),
        std::num::NonZeroUsize::new(usize::MAX).unwrap(),
    ]);
    check_field!(base(), maximum_modules, usize, [
        6,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), maximum_path_code_units, std::num::NonZeroUsize, [
        std::num::NonZeroUsize::new(1).unwrap(),
        std::num::NonZeroUsize::new(2).unwrap(),
        std::num::NonZeroUsize::new(usize::MAX).unwrap(),
    ]);
    check_field!(base(), maximum_registry_entries, usize, [
        8,
        0,
        1,
        usize::MAX,
    ]);
    check_field!(base(), maximum_registry_value_bytes, std::num::NonZeroUsize, [
        std::num::NonZeroUsize::new(1).unwrap(),
        std::num::NonZeroUsize::new(2).unwrap(),
        std::num::NonZeroUsize::new(usize::MAX).unwrap(),
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

#[test]
fn windows_loader_path() {
    let base = || WindowsLoaderPath {
        kind: WindowsLoaderPathKind::Directory,
        path: std::path::PathBuf::from(""),
    };
    check_field!(base(), kind, WindowsLoaderPathKind, [
        WindowsLoaderPathKind::Directory,
        WindowsLoaderPathKind::File,
        WindowsLoaderPathKind::Missing,
        WindowsLoaderPathKind::Other,
    ]);
    check_field!(base(), path, std::path::PathBuf, [
        std::path::PathBuf::from(""),
        std::path::PathBuf::from("file"),
        std::path::PathBuf::from("é"),
        std::path::PathBuf::from("a\0b"),
    ]);
}

#[test]
fn windows_loader_registry_value() {
    let base = || WindowsLoaderRegistryValue {
        data: vec![],
        name: std::ffi::OsString::from(""),
        value_type: 5,
    };
    check_field!(base(), data, Vec<u8>, [
        vec![],
        vec![0],
        vec![0xff],
        vec![0, 1, 0xfe, 0xff],
        vec![42],
    ]);
    check_field!(base(), name, std::ffi::OsString, [
        std::ffi::OsString::from(""),
        std::ffi::OsString::from("file"),
        std::ffi::OsString::from("é"),
        std::ffi::OsString::from("a\0b"),
    ]);
    check_field!(base(), value_type, u32, [
        5,
        0,
        1,
        u32::MAX,
    ]);
}

#[test]
fn windows_loader_requests() {
    let base = || WindowsLoaderRequests {
        activation_context: WindowsLoaderRequest::NotRequested,
        api_sets: WindowsLoaderRequest::NotRequested,
        dev_override_effective: WindowsLoaderRequest::NotRequested,
        dev_override_registry: WindowsLoaderRequest::NotRequested,
        dot_local: WindowsLoaderRequest::NotRequested,
        global_search_state: WindowsLoaderRequest::NotRequested,
        known_dlls: WindowsLoaderRequest::NotRequested,
        loaded_modules: WindowsLoaderRequest::NotRequested,
        package_dependency_graph: WindowsLoaderRequest::NotRequested,
        packaged_dot_local: WindowsLoaderRequest::NotRequested,
        search_directories: WindowsLoaderRequest::NotRequested,
    };
    check_field!(base(), activation_context, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), api_sets, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), dev_override_effective, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), dev_override_registry, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), dot_local, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), global_search_state, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), known_dlls, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), loaded_modules, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), package_dependency_graph, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), packaged_dot_local, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    check_field!(base(), search_directories, WindowsLoaderRequest, [
        WindowsLoaderRequest::NotRequested,
        WindowsLoaderRequest::Report,
        WindowsLoaderRequest::RequireKnown,
    ]);
    let original = base();
    assert_eq!(original.clone(), original);
    let copied = original; assert_eq!(copied, original);
    assert!(!format!("{original:?}").is_empty());
    fn require_eq<T: Eq>(_: &T) {} require_eq(&original);
    assert_eq!(original, base());
}

