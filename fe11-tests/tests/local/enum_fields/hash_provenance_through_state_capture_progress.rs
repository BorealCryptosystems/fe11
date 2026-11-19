// SPDX-License-Identifier: Apache-2.0
//! Check the identity and payload returned by matching public Rust variants.
use fe11::*;

#[test]
fn hash_provenance() {
    assert!(matches!(HashProvenance::ConsumerAttested, HashProvenance::ConsumerAttested));
}

#[test]
fn historical_profile() {
    assert!(matches!(HistoricalProfile::EcdsaSha1, HistoricalProfile::EcdsaSha1));
}

#[test]
fn hkdf_salt() {
    assert!(matches!(HkdfSalt::Null, HkdfSalt::Null));
}

#[test]
fn interface_selection() {
    {
        let check = |required_flags: u64, version: (u8, u8)| {
            roundtrip_fields!(InterfaceSelection::Standard { required_flags, version });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for required_flags in inputs {
            check(required_flags, (3, 9));
        }
        let inputs: [(u8, u8); 4] = [(3, 9), (0, 0), (1, 255), (255, 1)];
        for version in inputs {
            check(3, version);
        }
    }
}

#[test]
fn mechanism_discovery() {
    assert!(matches!(MechanismDiscovery::Complete, MechanismDiscovery::Complete));
    assert!(matches!(MechanismDiscovery::NotRequested, MechanismDiscovery::NotRequested));
}

#[test]
fn mechanism_observation() {
    {
        let check = |code: u64| {
            roundtrip_fields!(MechanismObservation::Refused { code });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for code in inputs {
            check(code);
        }
    }
    assert!(matches!(MechanismObservation::Unavailable, MechanismObservation::Unavailable));
}

#[test]
fn mechanism_observation_plan() {
    assert!(matches!(MechanismObservationPlan::NotRequested, MechanismObservationPlan::NotRequested));
    {
        let check = |maximum_bytes: usize| {
            roundtrip_fields!(MechanismObservationPlan::Read { maximum_bytes });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for maximum_bytes in inputs {
            check(maximum_bytes);
        }
    }
}

#[test]
fn mechanism_request() {
    assert!(matches!(MechanismRequest::Omitted, MechanismRequest::Omitted));
}

#[test]
fn message_aead_init() {
    assert!(matches!(MessageAeadInit::WithoutParameters, MessageAeadInit::WithoutParameters));
}

#[test]
fn module_integrity() {
    assert!(matches!(ModuleIntegrity::NotRequested, ModuleIntegrity::NotRequested));
}

#[test]
fn native_derivation_output() {
    assert!(matches!(NativeDerivationOutput::None, NativeDerivationOutput::None));
    {
        let check = |major: u8, minor: u8| {
            roundtrip_fields!(NativeDerivationOutput::TlsVersion { major, minor });
        };
        let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
        for major in inputs {
            check(major, 4);
        }
        let inputs: [u8; 4] = [4, 0, 1, u8::MAX];
        for minor in inputs {
            check(3, minor);
        }
    }
}

#[test]
fn native_encrypt_data() {
    {
        let check = |data: &[u8], iv: [u8; 16]| {
            roundtrip_fields!(NativeEncryptData::AesCbc { data, iv });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data, [3; 16]);
        }
        let inputs: [[u8; 16]; 4] = [[3; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(&[], iv);
        }
    }
    {
        let check = |data: &[u8], iv: [u8; 16]| {
            roundtrip_fields!(NativeEncryptData::AriaCbc { data, iv });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data, [3; 16]);
        }
        let inputs: [[u8; 16]; 4] = [[3; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(&[], iv);
        }
    }
    {
        let check = |data: &[u8], iv: [u8; 16]| {
            roundtrip_fields!(NativeEncryptData::CamelliaCbc { data, iv });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data, [3; 16]);
        }
        let inputs: [[u8; 16]; 4] = [[3; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(&[], iv);
        }
    }
    {
        let check = |data: &[u8], iv: [u8; 8]| {
            roundtrip_fields!(NativeEncryptData::Des3Cbc { data, iv });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data, [3; 8]);
        }
        let inputs: [[u8; 8]; 4] = [[3; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(&[], iv);
        }
    }
    {
        let check = |data: &[u8], iv: [u8; 8]| {
            roundtrip_fields!(NativeEncryptData::DesCbc { data, iv });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data, [3; 8]);
        }
        let inputs: [[u8; 8]; 4] = [[3; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(&[], iv);
        }
    }
    {
        let check = |data: &[u8], iv: [u8; 16]| {
            roundtrip_fields!(NativeEncryptData::SeedCbc { data, iv });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data, [3; 16]);
        }
        let inputs: [[u8; 16]; 4] = [[3; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(&[], iv);
        }
    }
}

#[test]
fn native_generation_output() {
    assert!(matches!(NativeGenerationOutput::None, NativeGenerationOutput::None));
}

#[test]
fn native_hkdf_salt() {
    assert!(matches!(NativeHkdfSalt::Null, NativeHkdfSalt::Null));
}

#[test]
fn native_kem_parameters() {
    assert!(matches!(NativeKemParameters::DhPkcs3, NativeKemParameters::DhPkcs3));
    {
        let check = |kdf: u64, shared_data: Option<&[u8]>| {
            roundtrip_fields!(NativeKemParameters::Ecdh { kdf, shared_data });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for kdf in inputs {
            check(kdf, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[43])];
        for shared_data in inputs {
            check(3, shared_data);
        }
    }
    {
        let check = |kdf: u64, shared_data: Option<&[u8]>| {
            roundtrip_fields!(NativeKemParameters::EcdhCofactor { kdf, shared_data });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for kdf in inputs {
            check(kdf, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[43])];
        for shared_data in inputs {
            check(3, shared_data);
        }
    }
    assert!(matches!(NativeKemParameters::MlKem, NativeKemParameters::MlKem));
    assert!(matches!(NativeKemParameters::Null, NativeKemParameters::Null));
    assert!(matches!(NativeKemParameters::RsaPkcs1v15, NativeKemParameters::RsaPkcs1v15));
    assert!(matches!(NativeKemParameters::RsaX509, NativeKemParameters::RsaX509));
    {
        let check = |kdf: u64, other_info: Option<&[u8]>| {
            roundtrip_fields!(NativeKemParameters::X942Dh { kdf, other_info });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for kdf in inputs {
            check(kdf, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[43])];
        for other_info in inputs {
            check(3, other_info);
        }
    }
}

#[test]
fn native_key_derivation() {
    {
        let check = |peer_public: &[u8]| {
            roundtrip_fields!(NativeKeyDerivation::DhPkcs { peer_public });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for peer_public in inputs {
            check(peer_public);
        }
    }
    {
        let check = |cofactor: bool, kdf: u64, peer_public: &[u8], shared_data: Option<&[u8]>| {
            roundtrip_fields!(NativeKeyDerivation::Ecdh { cofactor, kdf, peer_public, shared_data });
        };
        let inputs: [bool; 2] = [true, false];
        for cofactor in inputs {
            check(cofactor, 4, &[], None);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for kdf in inputs {
            check(true, kdf, &[], None);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
        for peer_public in inputs {
            check(true, 4, peer_public, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[45])];
        for shared_data in inputs {
            check(true, 4, &[], shared_data);
        }
    }
    {
        let check = |start_bit: u64| {
            roundtrip_fields!(NativeKeyDerivation::Extract { start_bit });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for start_bit in inputs {
            check(start_bit);
        }
    }
    {
        let check = |kdf: u64, peer_public: &[u8], ukm: Option<&[u8]>| {
            roundtrip_fields!(NativeKeyDerivation::GostR3410 { kdf, peer_public, ukm });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for kdf in inputs {
            check(kdf, &[], None);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[43]];
        for peer_public in inputs {
            check(3, peer_public, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[44])];
        for ukm in inputs {
            check(3, &[], ukm);
        }
    }
    assert!(matches!(NativeKeyDerivation::PublicFromPrivate, NativeKeyDerivation::PublicFromPrivate));
    {
        let check = |kdf: u64, other_info: Option<&[u8]>, peer_public: &[u8]| {
            roundtrip_fields!(NativeKeyDerivation::X942Dh { kdf, other_info, peer_public });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for kdf in inputs {
            check(kdf, None, &[]);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[43])];
        for other_info in inputs {
            check(3, other_info, &[]);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
        for peer_public in inputs {
            check(3, None, peer_public);
        }
    }
    {
        let check = |data: &[u8]| {
            roundtrip_fields!(NativeKeyDerivation::XorData { data });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for data in inputs {
            check(data);
        }
    }
}

#[test]
fn native_key_generation() {
    {
        let check = |major: u8, minor: u8| {
            roundtrip_fields!(NativeKeyGeneration::Ssl3PreMaster { major, minor });
        };
        let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
        for major in inputs {
            check(major, 4);
        }
        let inputs: [u8; 4] = [4, 0, 1, u8::MAX];
        for minor in inputs {
            check(3, minor);
        }
    }
    {
        let check = |major: u8, minor: u8| {
            roundtrip_fields!(NativeKeyGeneration::TlsPreMaster { major, minor });
        };
        let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
        for major in inputs {
            check(major, 4);
        }
        let inputs: [u8; 4] = [4, 0, 1, u8::MAX];
        for minor in inputs {
            check(3, minor);
        }
    }
    {
        let check = |version: u8| {
            roundtrip_fields!(NativeKeyGeneration::WtlsPreMaster { version });
        };
        let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
        for version in inputs {
            check(version);
        }
    }
}

#[test]
fn native_mac_parameters() {
    {
        let check = |iv: &[u8], tag_bits: u64| {
            roundtrip_fields!(NativeMacParameters::AesGmac { iv, tag_bits });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for iv in inputs {
            check(iv, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for tag_bits in inputs {
            check(&[], tag_bits);
        }
    }
    {
        let check = |oid: Option<&[u8]>| {
            roundtrip_fields!(NativeMacParameters::GostR3411 { oid });
        };
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[42])];
        for oid in inputs {
            check(oid);
        }
    }
    {
        let check = |bits: u64| {
            roundtrip_fields!(NativeMacParameters::Sha512T { bits });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for bits in inputs {
            check(bits);
        }
    }
    {
        let check = |output_bytes: u64| {
            roundtrip_fields!(NativeMacParameters::Ssl3Md5 { output_bytes });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for output_bytes in inputs {
            check(output_bytes);
        }
    }
    {
        let check = |output_bytes: u64| {
            roundtrip_fields!(NativeMacParameters::Ssl3Sha1 { output_bytes });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for output_bytes in inputs {
            check(output_bytes);
        }
    }
    {
        let check = |hash: u64, output_bytes: u64, server_or_client: u64| {
            roundtrip_fields!(NativeMacParameters::Tls { hash, output_bytes, server_or_client });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, 4, 5);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for output_bytes in inputs {
            check(3, output_bytes, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for server_or_client in inputs {
            check(3, 4, server_or_client);
        }
    }
    {
        let check = |hash: u64, output_bytes: u64, server_or_client: u64| {
            roundtrip_fields!(NativeMacParameters::Tls12 { hash, output_bytes, server_or_client });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, 4, 5);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for output_bytes in inputs {
            check(3, output_bytes, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for server_or_client in inputs {
            check(3, 4, server_or_client);
        }
    }
}

#[test]
fn native_message_action() {
    {
        let check = |output_capacity: usize| {
            roundtrip_fields!(NativeMessageAction::Sign { output_capacity });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for output_capacity in inputs {
            check(output_capacity);
        }
    }
    {
        let check = |signature: &[u8]| {
            roundtrip_fields!(NativeMessageAction::Verify { signature });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for signature in inputs {
            check(signature);
        }
    }
}

#[test]
fn native_mqv_layout() {
    assert!(matches!(NativeMqvLayout::TwoPair, NativeMqvLayout::TwoPair));
}

#[test]
fn native_nested_mechanism() {
    {
        let check = |oid: Option<&[u8]>| {
            roundtrip_fields!(NativeNestedMechanism::GostDigest { oid });
        };
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[42])];
        for oid in inputs {
            check(oid);
        }
    }
}

#[test]
fn native_rsa_cipher_parameters() {
    assert!(matches!(NativeRsaCipherParameters::Pkcs1v15, NativeRsaCipherParameters::Pkcs1v15));
    assert!(matches!(NativeRsaCipherParameters::Tpm11Oaep, NativeRsaCipherParameters::Tpm11Oaep));
    assert!(matches!(NativeRsaCipherParameters::Tpm11Pkcs1, NativeRsaCipherParameters::Tpm11Pkcs1));
    assert!(matches!(NativeRsaCipherParameters::X509, NativeRsaCipherParameters::X509));
}

#[test]
fn native_signature_parameters() {
    {
        let check = |oid: Option<&[u8]>| {
            roundtrip_fields!(NativeSignatureParameters::GostWithDigest { oid });
        };
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[42])];
        for oid in inputs {
            check(oid);
        }
    }
    {
        let check = |hash: u64| {
            roundtrip_fields!(NativeSignatureParameters::XEdDsa { hash });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash);
        }
    }
}

#[test]
fn native_transport_parameters() {
    {
        let check = |counter_bits: u64, counter_block: [u8; 16]| {
            roundtrip_fields!(NativeTransportParameters::AesCtr { counter_bits, counter_block });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for counter_bits in inputs {
            check(counter_bits, [3; 16]);
        }
        let inputs: [[u8; 16]; 4] = [[3; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 36)];
        for counter_block in inputs {
            check(3, counter_block);
        }
    }
    {
        let check = |aad: Option<&[u8]>, data_bytes: u64, fixed_bits: u64, generator: u64, mac_bytes: u64, nonce: &[u8]| {
            roundtrip_fields!(NativeTransportParameters::CcmWrap { aad, data_bytes, fixed_bits, generator, mac_bytes, nonce });
        };
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[42])];
        for aad in inputs {
            check(aad, 4, 5, 6, 7, &[]);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for data_bytes in inputs {
            check(None, data_bytes, 5, 6, 7, &[]);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for fixed_bits in inputs {
            check(None, 4, fixed_bits, 6, 7, &[]);
        }
        let inputs: [u64; 4] = [6, 0, 1, u64::MAX];
        for generator in inputs {
            check(None, 4, 5, generator, 7, &[]);
        }
        let inputs: [u64; 4] = [7, 0, 1, u64::MAX];
        for mac_bytes in inputs {
            check(None, 4, 5, 6, mac_bytes, &[]);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[47]];
        for nonce in inputs {
            check(None, 4, 5, 6, 7, nonce);
        }
    }
    {
        let check = |aes_key_bits: u64, kdf: u64, shared: Option<&[u8]>| {
            roundtrip_fields!(NativeTransportParameters::EcdhAes { aes_key_bits, kdf, shared });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for aes_key_bits in inputs {
            check(aes_key_bits, 4, None);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for kdf in inputs {
            check(3, kdf, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[44])];
        for shared in inputs {
            check(3, 4, shared);
        }
    }
    {
        let check = |aes_key_bits: u64, kdf: u64, shared: Option<&[u8]>| {
            roundtrip_fields!(NativeTransportParameters::EcdhAesCofactor { aes_key_bits, kdf, shared });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for aes_key_bits in inputs {
            check(aes_key_bits, 4, None);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for kdf in inputs {
            check(3, kdf, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[44])];
        for shared in inputs {
            check(3, 4, shared);
        }
    }
    {
        let check = |aes_key_bits: u64, kdf: u64, shared: Option<&[u8]>| {
            roundtrip_fields!(NativeTransportParameters::EcdhAesMontgomery { aes_key_bits, kdf, shared });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for aes_key_bits in inputs {
            check(aes_key_bits, 4, None);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for kdf in inputs {
            check(3, kdf, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[44])];
        for shared in inputs {
            check(3, 4, shared);
        }
    }
    {
        let check = |aad: Option<&[u8]>, fixed_bits: u64, generator: u64, iv: &[u8], tag_bits: u64| {
            roundtrip_fields!(NativeTransportParameters::GcmWrap { aad, fixed_bits, generator, iv, tag_bits });
        };
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[42])];
        for aad in inputs {
            check(aad, 4, 5, &[], 7);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for fixed_bits in inputs {
            check(None, fixed_bits, 5, &[], 7);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for generator in inputs {
            check(None, 4, generator, &[], 7);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[45]];
        for iv in inputs {
            check(None, 4, 5, iv, 7);
        }
        let inputs: [u64; 4] = [7, 0, 1, u64::MAX];
        for tag_bits in inputs {
            check(None, 4, 5, &[], tag_bits);
        }
    }
    {
        let check = |block_contents: u8, extra: Option<&[u8]>| {
            roundtrip_fields!(NativeTransportParameters::SetOaep { block_contents, extra });
        };
        let inputs: [u8; 4] = [3, 0, 1, u8::MAX];
        for block_contents in inputs {
            check(block_contents, None);
        }
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[43])];
        for extra in inputs {
            check(3, extra);
        }
    }
}

#[test]
fn notification() {
    assert!(matches!(Notification::Surrender, Notification::Surrender));
}

#[test]
fn operation_progress() {
    assert!(matches!(OperationProgress::Pending, OperationProgress::Pending));
    assert!(matches!(OperationProgress::Ready, OperationProgress::Ready));
}

#[test]
fn pin_change() {
    assert!(matches!(PinChange::ProtectedPair, PinChange::ProtectedPair));
}

#[test]
fn pin_request() {
    assert!(matches!(PinRequest::ProtectedPath, PinRequest::ProtectedPath));
}

#[test]
fn pqc_signature_mode() {
    assert!(matches!(PqcSignatureMode::Pure, PqcSignatureMode::Pure));
}

#[test]
fn public_import_metadata() {
    {
        let check = |id: Vec<u8>, label: Vec<u8>| {
            roundtrip_fields!(PublicImportMetadata::Exact { id, label });
        };
        let inputs: [Vec<u8>; 5] = [vec![], vec![0], vec![0xff], vec![0, 1, 0xfe, 0xff], vec![42]];
        for id in inputs {
            check(id, vec![]);
        }
        let inputs: [Vec<u8>; 5] = [vec![], vec![0], vec![0xff], vec![0, 1, 0xfe, 0xff], vec![43]];
        for label in inputs {
            check(vec![], label);
        }
    }
    {
        let check = |label: Vec<u8>, prefix: Vec<u8>| {
            roundtrip_fields!(PublicImportMetadata::SpkiSha256 { label, prefix });
        };
        let inputs: [Vec<u8>; 5] = [vec![], vec![0], vec![0xff], vec![0, 1, 0xfe, 0xff], vec![42]];
        for label in inputs {
            check(label, vec![]);
        }
        let inputs: [Vec<u8>; 5] = [vec![], vec![0], vec![0xff], vec![0, 1, 0xfe, 0xff], vec![43]];
        for prefix in inputs {
            check(vec![], prefix);
        }
    }
}

#[test]
fn rc_cipher_parameters() {
    {
        let check = |effective_bits: u64, iv: [u8; 8]| {
            roundtrip_fields!(RcCipherParameters::Rc2Cbc { effective_bits, iv });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for effective_bits in inputs {
            check(effective_bits, [3; 8]);
        }
        let inputs: [[u8; 8]; 4] = [[3; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(3, iv);
        }
    }
    {
        let check = |effective_bits: u64, iv: [u8; 8]| {
            roundtrip_fields!(RcCipherParameters::Rc2CbcPad { effective_bits, iv });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for effective_bits in inputs {
            check(effective_bits, [3; 8]);
        }
        let inputs: [[u8; 8]; 4] = [[3; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 36)];
        for iv in inputs {
            check(3, iv);
        }
    }
    {
        let check = |effective_bits: u64| {
            roundtrip_fields!(RcCipherParameters::Rc2Ecb { effective_bits });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for effective_bits in inputs {
            check(effective_bits);
        }
    }
    {
        let check = |iv: &[u8], rounds: u64, word_bytes: u64| {
            roundtrip_fields!(RcCipherParameters::Rc5Cbc { iv, rounds, word_bytes });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for iv in inputs {
            check(iv, 4, 5);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for rounds in inputs {
            check(&[], rounds, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for word_bytes in inputs {
            check(&[], 4, word_bytes);
        }
    }
    {
        let check = |iv: &[u8], rounds: u64, word_bytes: u64| {
            roundtrip_fields!(RcCipherParameters::Rc5CbcPad { iv, rounds, word_bytes });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for iv in inputs {
            check(iv, 4, 5);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for rounds in inputs {
            check(&[], rounds, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for word_bytes in inputs {
            check(&[], 4, word_bytes);
        }
    }
    {
        let check = |rounds: u64, word_bytes: u64| {
            roundtrip_fields!(RcCipherParameters::Rc5Ecb { rounds, word_bytes });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for rounds in inputs {
            check(rounds, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for word_bytes in inputs {
            check(3, word_bytes);
        }
    }
}

#[test]
fn recover_output_plan() {
    {
        let check = |capacity: usize| {
            roundtrip_fields!(RecoverOutputPlan::Buffer { capacity });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for capacity in inputs {
            check(capacity);
        }
    }
    assert!(matches!(RecoverOutputPlan::LengthOnly, RecoverOutputPlan::LengthOnly));
}

#[test]
fn reference_search_plan() {
    assert!(matches!(ReferenceSearchPlan::NotRequested, ReferenceSearchPlan::NotRequested));
}

#[test]
fn reference_template() {
    assert!(matches!(ReferenceTemplate::Selector, ReferenceTemplate::Selector));
}

#[test]
fn rejoin_progress() {
    assert!(matches!(RejoinProgress::Pending, RejoinProgress::Pending));
    assert!(matches!(RejoinProgress::Ready, RejoinProgress::Ready));
}

#[test]
fn resource_admission() {
    assert!(matches!(ResourceAdmission::Immediate, ResourceAdmission::Immediate));
}

#[test]
fn session_validation() {
    assert!(matches!(SessionValidation::Unavailable, SessionValidation::Unavailable));
}

#[test]
fn signature_output_plan() {
    {
        let check = |capacity: usize| {
            roundtrip_fields!(SignatureOutputPlan::Buffer { capacity });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for capacity in inputs {
            check(capacity);
        }
    }
    assert!(matches!(SignatureOutputPlan::LengthOnly, SignatureOutputPlan::LengthOnly));
}

#[test]
fn signature_profile() {
    assert!(matches!(SignatureProfile::Ed25519, SignatureProfile::Ed25519));
    assert!(matches!(SignatureProfile::Ed448, SignatureProfile::Ed448));
}

#[test]
fn slot_event() {
    assert!(matches!(SlotEvent::InterruptedByFinalization, SlotEvent::InterruptedByFinalization));
    assert!(matches!(SlotEvent::NoEvent, SlotEvent::NoEvent));
}

#[test]
fn sp800_data() {
    assert!(matches!(Sp800Data::Iteration, Sp800Data::Iteration));
}

#[test]
fn sp800_mode() {
    assert!(matches!(Sp800Mode::Counter, Sp800Mode::Counter));
    assert!(matches!(Sp800Mode::DoublePipeline, Sp800Mode::DoublePipeline));
    {
        let check = |iv: Option<&[u8]>| {
            roundtrip_fields!(Sp800Mode::Feedback { iv });
        };
        let inputs: [Option<&[u8]>; 6] = [None, Some(&[]), Some(&[0]), Some(&[0xff]), Some(&[0, 1, 0xfe, 0xff]), Some(&[42])];
        for iv in inputs {
            check(iv);
        }
    }
}

#[test]
fn state_capture_progress() {
    assert!(matches!(StateCaptureProgress::Pending, StateCaptureProgress::Pending));
    assert!(matches!(StateCaptureProgress::Ready, StateCaptureProgress::Ready));
}

