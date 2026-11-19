// SPDX-License-Identifier: Apache-2.0
//! Public stream tuples preserve caller bytes; native support is a separate fact.
use fe11::{
    ClassicAeadParameters, StreamAeadAlgorithm, StreamAeadNonce, StreamAeadParameters,
    StreamCipherParameters,
};
use fe11_sys::{CKM_CHACHA20, CKM_CHACHA20_POLY1305, CKM_SALSA20, CKM_SALSA20_POLY1305};

#[test]
fn counter_boundaries_and_all_nonce_variants_preserve_exact_bytes() {
    for counter in [0u64, 1, u64::MAX] {
        for byte in [0u8, 0x81, 0xff] {
            let c64 = counter.to_le_bytes();
            let c32 = (counter as u32).to_le_bytes();
            let n8 = [byte; 8];
            let n12 = [byte; 12];
            let n24 = [byte; 24];
            let values = [
                StreamCipherParameters::ChaCha20 {
                    counter: c64,
                    nonce: n8,
                },
                StreamCipherParameters::ChaCha20Ietf {
                    counter: c32,
                    nonce: n12,
                },
                StreamCipherParameters::XChaCha20 {
                    counter: c64,
                    nonce: n24,
                },
                StreamCipherParameters::Salsa20 {
                    counter: c64,
                    nonce: n8,
                },
                StreamCipherParameters::XSalsa20 {
                    counter: c64,
                    nonce: n24,
                },
            ];
            for (index, value) in values.into_iter().enumerate() {
                assert_eq!(
                    value.mechanism_number(),
                    if index < 3 { CKM_CHACHA20 } else { CKM_SALSA20 } as u64
                );
                match value {
                    StreamCipherParameters::ChaCha20 { counter, nonce } => {
                        assert_eq!(counter, c64);
                        assert_eq!(nonce, n8);
                        assert_eq!(index, 0);
                    }
                    StreamCipherParameters::ChaCha20Ietf { counter, nonce } => {
                        assert_eq!(counter, c32);
                        assert_eq!(nonce, n12);
                        assert_eq!(index, 1);
                    }
                    StreamCipherParameters::XChaCha20 { counter, nonce } => {
                        assert_eq!(counter, c64);
                        assert_eq!(nonce, n24);
                        assert_eq!(index, 2);
                    }
                    StreamCipherParameters::Salsa20 { counter, nonce } => {
                        assert_eq!(counter, c64);
                        assert_eq!(nonce, n8);
                        assert_eq!(index, 3);
                    }
                    StreamCipherParameters::XSalsa20 { counter, nonce } => {
                        assert_eq!(counter, c64);
                        assert_eq!(nonce, n24);
                        assert_eq!(index, 4);
                    }
                }
            }
        }
    }
}

#[test]
fn poly1305_nonce_accessors_and_aad_preserve_empty_and_binary_inputs() {
    let n8 = [0x00, 0xff, 0x01, 0xfe, 0x02, 0xfd, 0x03, 0xfc];
    let n12 = [0x81; 12];
    let n24 = [0xff; 24];
    let variants = [
        StreamAeadNonce::ChaCha20(n8),
        StreamAeadNonce::ChaCha20Ietf(n12),
        StreamAeadNonce::XChaCha20(n24),
        StreamAeadNonce::Salsa20(n8),
        StreamAeadNonce::XSalsa20(n24),
    ];
    let expected_bytes: [&[u8]; 5] = [&n8, &n12, &n24, &n8, &n24];
    let binary = [0, 255, 0, 128];
    for (index, nonce) in variants.into_iter().enumerate() {
        let mechanism = if index < 3 {
            CKM_CHACHA20_POLY1305
        } else {
            CKM_SALSA20_POLY1305
        } as u64;
        let algorithm = if index < 3 {
            StreamAeadAlgorithm::ChaCha20
        } else {
            StreamAeadAlgorithm::Salsa20
        };
        assert_eq!(nonce.as_bytes(), expected_bytes[index]);
        assert_eq!(nonce.algorithm(), algorithm);
        assert_eq!(nonce.mechanism_number(), mechanism);
        assert_eq!(algorithm.mechanism_number(), mechanism);
        for aad in [&[][..], binary.as_slice()] {
            let parameters = StreamAeadParameters { nonce, aad };
            assert_eq!(parameters.nonce, nonce);
            assert_eq!(parameters.aad, aad);
            assert_eq!(parameters.aad.as_ptr(), aad.as_ptr());
            assert_eq!(
                ClassicAeadParameters::Stream { nonce, aad }.mechanism_number(),
                mechanism
            );
        }
    }
}

#[test]
fn explicit_ietf_byte_encoding_keeps_the_standard_mechanism_identity() {
    let nonce = [0x81; 12];
    let aad = [0, 255, 128];
    assert_eq!(
        ClassicAeadParameters::ChaCha20IetfBytes { nonce, aad: &aad }.mechanism_number(),
        CKM_CHACHA20_POLY1305 as u64
    );
}
