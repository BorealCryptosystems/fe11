// SPDX-License-Identifier: Apache-2.0
//! Check the identity and payload returned by matching public Rust variants.
use fe11::*;

#[test]
fn state_key_encoding() {
    assert!(matches!(StateKeyEncoding::Embedded, StateKeyEncoding::Embedded));
    assert!(matches!(StateKeyEncoding::Supplied, StateKeyEncoding::Supplied));
}

#[test]
fn state_restore_progress() {
    assert!(matches!(StateRestoreProgress::Pending, StateRestoreProgress::Pending));
    assert!(matches!(StateRestoreProgress::Ready, StateRestoreProgress::Ready));
}

#[test]
fn stream_cipher_parameters() {
    {
        let check = |counter: [u8; 8], nonce: [u8; 8]| {
            roundtrip_fields!(StreamCipherParameters::ChaCha20 { counter, nonce });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for counter in inputs {
            check(counter, [3; 8]);
        }
        let inputs: [[u8; 8]; 4] = [[3; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 36)];
        for nonce in inputs {
            check([2; 8], nonce);
        }
    }
    {
        let check = |counter: [u8; 8], nonce: [u8; 8]| {
            roundtrip_fields!(StreamCipherParameters::Salsa20 { counter, nonce });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for counter in inputs {
            check(counter, [3; 8]);
        }
        let inputs: [[u8; 8]; 4] = [[3; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 36)];
        for nonce in inputs {
            check([2; 8], nonce);
        }
    }
    {
        let check = |counter: [u8; 8], nonce: [u8; 24]| {
            roundtrip_fields!(StreamCipherParameters::XChaCha20 { counter, nonce });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for counter in inputs {
            check(counter, [3; 24]);
        }
        let inputs: [[u8; 24]; 4] = [[3; 24], [0; 24], [255; 24], std::array::from_fn(|i| i as u8 ^ 36)];
        for nonce in inputs {
            check([2; 8], nonce);
        }
    }
    {
        let check = |counter: [u8; 8], nonce: [u8; 24]| {
            roundtrip_fields!(StreamCipherParameters::XSalsa20 { counter, nonce });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for counter in inputs {
            check(counter, [3; 24]);
        }
        let inputs: [[u8; 24]; 4] = [[3; 24], [0; 24], [255; 24], std::array::from_fn(|i| i as u8 ^ 36)];
        for nonce in inputs {
            check([2; 8], nonce);
        }
    }
}

#[test]
fn symmetric_algorithm() {
    {
        let check = |key_length: usize| {
            roundtrip_fields!(SymmetricAlgorithm::HmacSha256 { key_length });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for key_length in inputs {
            check(key_length);
        }
    }
    {
        let check = |key_length: usize| {
            roundtrip_fields!(SymmetricAlgorithm::HmacSha384 { key_length });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for key_length in inputs {
            check(key_length);
        }
    }
    {
        let check = |key_length: usize| {
            roundtrip_fields!(SymmetricAlgorithm::HmacSha512 { key_length });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for key_length in inputs {
            check(key_length);
        }
    }
}

#[test]
fn template_attribute_read_plan() {
    assert!(matches!(TemplateAttributeReadPlan::LengthOnly, TemplateAttributeReadPlan::LengthOnly));
}

#[test]
fn template_attribute_slot() {
    assert!(matches!(TemplateAttributeSlot::Discover, TemplateAttributeSlot::Discover));
}

#[test]
fn template_attribute_value() {
    {
        let check = |required: Option<usize>, supplied: usize| {
            roundtrip_fields!(TemplateAttributeValue::BufferTooSmall { required, supplied });
        };
        let inputs: [Option<usize>; 4] = [None, Some(0), Some(1), Some(usize::MAX)];
        for required in inputs {
            check(required, 4);
        }
        let inputs: [usize; 4] = [4, 0, 1, usize::MAX];
        for supplied in inputs {
            check(None, supplied);
        }
    }
    {
        let check = |reported_bytes: usize| {
            roundtrip_fields!(TemplateAttributeValue::InvalidTemplateLength { reported_bytes });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for reported_bytes in inputs {
            check(reported_bytes);
        }
    }
    {
        let check = |required_bytes: usize| {
            roundtrip_fields!(TemplateAttributeValue::SizeKnown { required_bytes });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for required_bytes in inputs {
            check(required_bytes);
        }
    }
    {
        let check = |expected: u64, observed: u64| {
            roundtrip_fields!(TemplateAttributeValue::TypeChanged { expected, observed });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for expected in inputs {
            check(expected, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for observed in inputs {
            check(3, observed);
        }
    }
}

#[test]
fn tls_key_material_mechanism() {
    {
        let check = |hash: u64| {
            roundtrip_fields!(TlsKeyMaterialMechanism::Tls12 { hash });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash);
        }
    }
    {
        let check = |hash: u64| {
            roundtrip_fields!(TlsKeyMaterialMechanism::Tls12Safe { hash });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash);
        }
    }
    {
        let check = |digest: u64, sequence: u64| {
            roundtrip_fields!(TlsKeyMaterialMechanism::WtlsClient { digest, sequence });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for digest in inputs {
            check(digest, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for sequence in inputs {
            check(3, sequence);
        }
    }
    {
        let check = |digest: u64, sequence: u64| {
            roundtrip_fields!(TlsKeyMaterialMechanism::WtlsServer { digest, sequence });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for digest in inputs {
            check(digest, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for sequence in inputs {
            check(3, sequence);
        }
    }
}

#[test]
fn tls_master_derivation() {
    {
        let check = |dh: bool, hash: u64, session_hash: &[u8]| {
            roundtrip_fields!(TlsMasterDerivation::Tls12Extended { dh, hash, session_hash });
        };
        let inputs: [bool; 2] = [true, false];
        for dh in inputs {
            check(dh, 4, &[]);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for hash in inputs {
            check(true, hash, &[]);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
        for session_hash in inputs {
            check(true, 4, session_hash);
        }
    }
}

#[test]
fn tls_prf_mechanism() {
    assert!(matches!(TlsPrfMechanism::Tls, TlsPrfMechanism::Tls));
    {
        let check = |digest: u64| {
            roundtrip_fields!(TlsPrfMechanism::Wtls { digest });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for digest in inputs {
            check(digest);
        }
    }
}

#[test]
fn token_iv() {
    assert!(matches!(TokenIv::Generate, TokenIv::Generate));
}

#[test]
fn unwrap_parameters() {
    assert!(matches!(UnwrapParameters::AesKw, UnwrapParameters::AesKw));
    assert!(matches!(UnwrapParameters::AesKwp, UnwrapParameters::AesKwp));
    {
        let check = |hash: u64, label: &[u8], mgf: u64| {
            roundtrip_fields!(UnwrapParameters::RsaOaep { hash, label, mgf });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, &[], 5);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[43]];
        for label in inputs {
            check(3, label, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for mgf in inputs {
            check(3, &[], mgf);
        }
    }
}

#[test]
fn verification() {
    assert!(matches!(Verification::Invalid, Verification::Invalid));
    assert!(matches!(Verification::Valid, Verification::Valid));
}

#[test]
fn verification_profile() {
    assert!(matches!(VerificationProfile::Ed25519, VerificationProfile::Ed25519));
    assert!(matches!(VerificationProfile::Ed448, VerificationProfile::Ed448));
}

#[test]
fn windows_dependency_search() {
    assert!(matches!(WindowsDependencySearch::ApplicationConfigured, WindowsDependencySearch::ApplicationConfigured));
    {
        let check = |application_added_directories: bool, application_directory: bool, module_directory: bool, system32: bool| {
            roundtrip_fields!(WindowsDependencySearch::Directories { application_added_directories, application_directory, module_directory, system32 });
        };
        let inputs: [bool; 2] = [true, false];
        for application_added_directories in inputs {
            check(application_added_directories, true, true, true);
        }
        let inputs: [bool; 2] = [true, false];
        for application_directory in inputs {
            check(true, application_directory, true, true);
        }
        let inputs: [bool; 2] = [true, false];
        for module_directory in inputs {
            check(true, true, module_directory, true);
        }
        let inputs: [bool; 2] = [true, false];
        for system32 in inputs {
            check(true, true, true, system32);
        }
    }
}

#[test]
fn windows_file_pinning() {
    assert!(matches!(WindowsFilePinning::NotRequested, WindowsFilePinning::NotRequested));
}

#[test]
fn windows_image_consistency() {
    assert!(matches!(WindowsImageConsistency::NotRequested, WindowsImageConsistency::NotRequested));
}

#[test]
fn windows_loader_observations() {
    assert!(matches!(WindowsLoaderObservations::NotRequested, WindowsLoaderObservations::NotRequested));
}

#[test]
fn windows_loader_unavailable() {
    {
        let check = |code: u32, function: &'static str| {
            roundtrip_fields!(WindowsLoaderUnavailable::Os { code, function });
        };
        let inputs: [u32; 4] = [3, 0, 1, u32::MAX];
        for code in inputs {
            check(code, "");
        }
        let inputs: [&'static str; 5] = ["", "abc", "é", "a\0b", "field1"];
        for function in inputs {
            check(3, function);
        }
    }
    {
        let check = |function: &'static str| {
            roundtrip_fields!(WindowsLoaderUnavailable::OsErrorWithoutCode { function });
        };
        let inputs: [&'static str; 5] = ["", "abc", "é", "a\0b", "field0"];
        for function in inputs {
            check(function);
        }
    }
}

#[test]
fn wrap_parameters() {
    assert!(matches!(WrapParameters::AesKw, WrapParameters::AesKw));
    assert!(matches!(WrapParameters::AesKwp, WrapParameters::AesKwp));
    {
        let check = |hash: u64, label: &[u8], mgf: u64| {
            roundtrip_fields!(WrapParameters::RsaOaep { hash, label, mgf });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, &[], 5);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[43]];
        for label in inputs {
            check(3, label, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for mgf in inputs {
            check(3, &[], mgf);
        }
    }
}

