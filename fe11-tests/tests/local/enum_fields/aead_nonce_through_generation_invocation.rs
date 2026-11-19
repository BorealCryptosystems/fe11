// SPDX-License-Identifier: Apache-2.0
//! Check the identity and payload returned by matching public Rust variants.
use fe11::*;

#[test]
fn aead_nonce() {
    assert!(matches!(AeadNonce::BackendRandom, AeadNonce::BackendRandom));
}

#[test]
fn aes_cipher_parameters() {
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::Cbc { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::CbcPad { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::Cfb128 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::Cfb64 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::Cfb8 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |counter_bits: u64, counter_block: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::Ctr { counter_bits, counter_block });
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
    assert!(matches!(AesCipherParameters::Ecb, AesCipherParameters::Ecb));
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(AesCipherParameters::Ofb { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
}

#[test]
fn attribute_batch_calls() {
    assert!(matches!(AttributeBatchCalls::None, AttributeBatchCalls::None));
}

#[test]
fn attribute_read_calls() {
    {
        let check = |code: u64| {
            roundtrip_fields!(AttributeReadCalls::Direct { code });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for code in inputs {
            check(code);
        }
    }
    {
        let check = |code: u64| {
            roundtrip_fields!(AttributeReadCalls::Size { code });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for code in inputs {
            check(code);
        }
    }
    {
        let check = |code: u64, size_code: u64| {
            roundtrip_fields!(AttributeReadCalls::Value { code, size_code });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for code in inputs {
            check(code, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for size_code in inputs {
            check(3, size_code);
        }
    }
}

#[test]
fn attribute_value() {
    assert!(matches!(AttributeValue::Indeterminate, AttributeValue::Indeterminate));
    assert!(matches!(AttributeValue::NotRequested, AttributeValue::NotRequested));
    assert!(matches!(AttributeValue::Sensitive, AttributeValue::Sensitive));
    assert!(matches!(AttributeValue::Unsupported, AttributeValue::Unsupported));
}

#[test]
fn cancellation_progress() {
    assert!(matches!(CancellationProgress::Pending, CancellationProgress::Pending));
}

#[test]
fn cipher_key_reference() {
    assert!(matches!(CipherKeyReference::NoKey, CipherKeyReference::NoKey));
}

#[test]
fn cipher_output_plan() {
    {
        let check = |capacity: usize| {
            roundtrip_fields!(CipherOutputPlan::Buffer { capacity });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for capacity in inputs {
            check(capacity);
        }
    }
}

#[test]
fn cipher_parameters() {
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::AesCfb1 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::AesCts { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::AesXts { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::AriaCbc { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::AriaCbcPad { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::BlowfishCbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::BlowfishCbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::CamelliaCbc { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::CamelliaCbcPad { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |counter_bits: u64, counter_block: [u8; 16]| {
            roundtrip_fields!(CipherParameters::CamelliaCtr { counter_bits, counter_block });
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
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::Cast3Cbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::Cast3CbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::Cast5Cbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::Cast5CbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::CastCbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::CastCbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::CdmfCbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::CdmfCbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::Des3Cbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::Des3CbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::DesCbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::DesCbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::DesCfb64 { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::DesCfb8 { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::DesOfb64 { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::DesOfb8 { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::IdeaCbc { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 8]| {
            roundtrip_fields!(CipherParameters::IdeaCbcPad { iv });
        };
        let inputs: [[u8; 8]; 4] = [[2; 8], [0; 8], [255; 8], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::SeedCbc { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::SeedCbcPad { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::TwofishCbc { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(CipherParameters::TwofishCbcPad { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
}

#[test]
fn classic_aead_parameters() {
    {
        let check = |aad: &[u8], mac_length: u64, nonce: &[u8]| {
            roundtrip_fields!(ClassicAeadParameters::Ccm { aad, mac_length, nonce });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for aad in inputs {
            check(aad, 4, &[]);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for mac_length in inputs {
            check(&[], mac_length, &[]);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
        for nonce in inputs {
            check(&[], 4, nonce);
        }
    }
    {
        let check = |aad: &[u8], nonce: [u8; 12]| {
            roundtrip_fields!(ClassicAeadParameters::ChaCha20IetfBytes { aad, nonce });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for aad in inputs {
            check(aad, [3; 12]);
        }
        let inputs: [[u8; 12]; 4] = [[3; 12], [0; 12], [255; 12], std::array::from_fn(|i| i as u8 ^ 36)];
        for nonce in inputs {
            check(&[], nonce);
        }
    }
    {
        let check = |aad: &[u8], iv: &[u8], tag_bits: u64| {
            roundtrip_fields!(ClassicAeadParameters::Gcm { aad, iv, tag_bits });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for aad in inputs {
            check(aad, &[], 5);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[43]];
        for iv in inputs {
            check(&[], iv, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for tag_bits in inputs {
            check(&[], &[], tag_bits);
        }
    }
    {
        let check = |aad: &[u8], iv: &[u8], tag_bits: u64| {
            roundtrip_fields!(ClassicAeadParameters::GcmWithoutIvBits { aad, iv, tag_bits });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for aad in inputs {
            check(aad, &[], 5);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[43]];
        for iv in inputs {
            check(&[], iv, 5);
        }
        let inputs: [u64; 4] = [5, 0, 1, u64::MAX];
        for tag_bits in inputs {
            check(&[], &[], tag_bits);
        }
    }
}

#[test]
fn classical_key_algorithm() {
    {
        let check = |bits: usize| {
            roundtrip_fields!(ClassicalKeyAlgorithm::Rsa { bits });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for bits in inputs {
            check(bits);
        }
    }
}

#[test]
fn content_observation() {
    assert!(matches!(ContentObservation::NotRequested, ContentObservation::NotRequested));
}

#[test]
fn content_read_plan() {
    {
        let check = |maximum_bytes: usize| {
            roundtrip_fields!(ContentReadPlan::Value { maximum_bytes });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for maximum_bytes in inputs {
            check(maximum_bytes);
        }
    }
}

#[test]
fn copy_target() {
    {
        let check = |application: String, label: String, persistent: bool| {
            roundtrip_fields!(CopyTarget::Data { application, label, persistent });
        };
        let inputs: [String; 5] = ["".to_owned(), "abc".to_owned(), "é".to_owned(), "a\0b".to_owned(), "field0".to_owned()];
        for application in inputs {
            check(application, "".to_owned(), true);
        }
        let inputs: [String; 5] = ["".to_owned(), "abc".to_owned(), "é".to_owned(), "a\0b".to_owned(), "field1".to_owned()];
        for label in inputs {
            check("".to_owned(), label, true);
        }
        let inputs: [bool; 2] = [true, false];
        for persistent in inputs {
            check("".to_owned(), "".to_owned(), persistent);
        }
    }
    {
        let check = |id: Vec<u8>, label: String, persistent: bool| {
            roundtrip_fields!(CopyTarget::KeyOrCertificate { id, label, persistent });
        };
        let inputs: [Vec<u8>; 5] = [vec![], vec![0], vec![0xff], vec![0, 1, 0xfe, 0xff], vec![42]];
        for id in inputs {
            check(id, "".to_owned(), true);
        }
        let inputs: [String; 5] = ["".to_owned(), "abc".to_owned(), "é".to_owned(), "a\0b".to_owned(), "field1".to_owned()];
        for label in inputs {
            check(vec![], label, true);
        }
        let inputs: [bool; 2] = [true, false];
        for persistent in inputs {
            check(vec![], "".to_owned(), persistent);
        }
    }
}

#[test]
fn destination_search_plan() {
    assert!(matches!(DestinationSearchPlan::NotRequested, DestinationSearchPlan::NotRequested));
}

#[test]
fn destination_user_observation() {
    assert!(matches!(DestinationUserObservation::NotRequested, DestinationUserObservation::NotRequested));
    assert!(matches!(DestinationUserObservation::Read, DestinationUserObservation::Read));
}

#[test]
fn detachment_progress() {
    assert!(matches!(DetachmentProgress::Pending, DetachmentProgress::Pending));
    assert!(matches!(DetachmentProgress::Ready, DetachmentProgress::Ready));
}

#[test]
fn discovery_selection() {
    assert!(matches!(DiscoverySelection::AllPresentSlots, DiscoverySelection::AllPresentSlots));
    assert!(matches!(DiscoverySelection::Deferred, DiscoverySelection::Deferred));
}

#[test]
fn dsa_domain_generation() {
    {
        let check = |hash: u64, index: u64, seed: &[u8]| {
            roundtrip_fields!(DsaDomainGeneration::Base { hash, index, seed });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, 4, &[]);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for index in inputs {
            check(3, index, &[]);
        }
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[44]];
        for seed in inputs {
            check(3, 4, seed);
        }
    }
    {
        let check = |hash: u64, index: u64, seed_capacity: usize| {
            roundtrip_fields!(DsaDomainGeneration::Probabilistic { hash, index, seed_capacity });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, 4, 5);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for index in inputs {
            check(3, index, 5);
        }
        let inputs: [usize; 4] = [5, 0, 1, usize::MAX];
        for seed_capacity in inputs {
            check(3, 4, seed_capacity);
        }
    }
    {
        let check = |hash: u64, index: u64, seed_capacity: usize| {
            roundtrip_fields!(DsaDomainGeneration::ShaweTaylor { hash, index, seed_capacity });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for hash in inputs {
            check(hash, 4, 5);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for index in inputs {
            check(3, index, 5);
        }
        let inputs: [usize; 4] = [5, 0, 1, usize::MAX];
        for seed_capacity in inputs {
            check(3, 4, seed_capacity);
        }
    }
}

#[test]
fn dual_cipher() {
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(DualCipher::Cbc { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(DualCipher::CbcPad { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(DualCipher::Cfb128 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(DualCipher::Cfb64 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(DualCipher::Cfb8 { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
    {
        let check = |counter_bits: u64, counter_block: [u8; 16]| {
            roundtrip_fields!(DualCipher::Ctr { counter_bits, counter_block });
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
    assert!(matches!(DualCipher::Ecb, DualCipher::Ecb));
    {
        let check = |iv: [u8; 16]| {
            roundtrip_fields!(DualCipher::Ofb { iv });
        };
        let inputs: [[u8; 16]; 4] = [[2; 16], [0; 16], [255; 16], std::array::from_fn(|i| i as u8 ^ 35)];
        for iv in inputs {
            check(iv);
        }
    }
}

#[test]
fn dual_result() {
    assert!(matches!(DualResult::Invalid, DualResult::Invalid));
}

#[test]
fn extension_input() {
    {
        let check = |input: &[u8], output_capacity: usize| {
            roundtrip_fields!(ExtensionInput::Digest { input, output_capacity });
        };
        let inputs: [&[u8]; 5] = [&[], &[0], &[0xff], &[0, 1, 0xfe, 0xff], &[42]];
        for input in inputs {
            check(input, 4);
        }
        let inputs: [usize; 4] = [4, 0, 1, usize::MAX];
        for output_capacity in inputs {
            check(&[], output_capacity);
        }
    }
}

#[test]
fn extension_output_length() {
    assert!(matches!(ExtensionOutputLength::Fixed, ExtensionOutputLength::Fixed));
    {
        let check = |block: usize, offset: usize| {
            roundtrip_fields!(ExtensionOutputLength::NativeUnsigned { block, offset });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for block in inputs {
            check(block, 4);
        }
        let inputs: [usize; 4] = [4, 0, 1, usize::MAX];
        for offset in inputs {
            check(3, offset);
        }
    }
}

#[test]
fn extension_pointer_target() {
    {
        let check = |block: usize, offset: usize| {
            roundtrip_fields!(ExtensionPointerTarget::Block { block, offset });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for block in inputs {
            check(block, 4);
        }
        let inputs: [usize; 4] = [4, 0, 1, usize::MAX];
        for offset in inputs {
            check(3, offset);
        }
    }
    assert!(matches!(ExtensionPointerTarget::Null, ExtensionPointerTarget::Null));
}

#[test]
fn flat_attribute_read_plan() {
    {
        let check = |capacity: usize| {
            roundtrip_fields!(FlatAttributeReadPlan::Buffer { capacity });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for capacity in inputs {
            check(capacity);
        }
    }
    assert!(matches!(FlatAttributeReadPlan::LengthOnly, FlatAttributeReadPlan::LengthOnly));
    {
        let check = |maximum_bytes: usize| {
            roundtrip_fields!(FlatAttributeReadPlan::Value { maximum_bytes });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for maximum_bytes in inputs {
            check(maximum_bytes);
        }
    }
}

#[test]
fn flat_attribute_value() {
    {
        let check = |remaining_bytes: usize, required: usize| {
            roundtrip_fields!(FlatAttributeValue::AggregateAllocationLimit { remaining_bytes, required });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for remaining_bytes in inputs {
            check(remaining_bytes, 4);
        }
        let inputs: [usize; 4] = [4, 0, 1, usize::MAX];
        for required in inputs {
            check(3, required);
        }
    }
    {
        let check = |maximum_bytes: usize, required: usize| {
            roundtrip_fields!(FlatAttributeValue::AllocationLimit { maximum_bytes, required });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for maximum_bytes in inputs {
            check(maximum_bytes, 4);
        }
        let inputs: [usize; 4] = [4, 0, 1, usize::MAX];
        for required in inputs {
            check(3, required);
        }
    }
    {
        let check = |required: Option<usize>, supplied: usize| {
            roundtrip_fields!(FlatAttributeValue::BufferTooSmall { required, supplied });
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
        let check = |required: usize| {
            roundtrip_fields!(FlatAttributeValue::SizeKnown { required });
        };
        let inputs: [usize; 4] = [3, 0, 1, usize::MAX];
        for required in inputs {
            check(required);
        }
    }
}

#[test]
fn foreign_scope() {
    assert!(matches!(ForeignScope::Module, ForeignScope::Module));
    {
        let check = |handle: u64, slot: u64| {
            roundtrip_fields!(ForeignScope::Session { handle, slot });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for handle in inputs {
            check(handle, 4);
        }
        let inputs: [u64; 4] = [4, 0, 1, u64::MAX];
        for slot in inputs {
            check(3, slot);
        }
    }
}

#[test]
fn generation_invocation() {
    {
        let check = |mechanism: u64| {
            roundtrip_fields!(GenerationInvocation::GeneratedByThisCall { mechanism });
        };
        let inputs: [u64; 4] = [3, 0, 1, u64::MAX];
        for mechanism in inputs {
            check(mechanism);
        }
    }
    assert!(matches!(GenerationInvocation::NotGeneratedByThisCall, GenerationInvocation::NotGeneratedByThisCall));
}

