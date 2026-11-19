// SPDX-License-Identifier: Apache-2.0
//! Public selector identities and widths, independent of module availability.
use fe11::*;

#[test]
fn modern_and_historical_digest_widths() {
    for (hash, bytes) in [
        (HashAlgorithm::Sha224, 28),
        (HashAlgorithm::Sha256, 32),
        (HashAlgorithm::Sha384, 48),
        (HashAlgorithm::Sha512, 64),
        (HashAlgorithm::Sha3_224, 28),
        (HashAlgorithm::Sha3_256, 32),
        (HashAlgorithm::Sha3_384, 48),
        (HashAlgorithm::Sha3_512, 64),
    ] {
        assert_eq!(hash.output_length(), bytes);
    }
    assert_eq!(HistoricalHash::Md5.output_length(), 16);
    assert_eq!(HistoricalHash::Sha1.output_length(), 20);
    for (hash, bytes) in [
        (DsaVerificationHash::Sha1, 20),
        (DsaVerificationHash::Sha224, 28),
        (DsaVerificationHash::Sha256, 32),
        (DsaVerificationHash::Sha384, 48),
        (DsaVerificationHash::Sha512, 64),
    ] {
        assert_eq!(hash.output_length(), bytes);
    }
}

#[test]
fn pqc_prehash_widths_are_fixed_including_xofs() {
    for (hash, bytes) in [
        (PqcHash::Sha224, 28),
        (PqcHash::Sha256, 32),
        (PqcHash::Sha384, 48),
        (PqcHash::Sha512, 64),
        (PqcHash::Sha512_224, 28),
        (PqcHash::Sha512_256, 32),
        (PqcHash::Sha3_224, 28),
        (PqcHash::Sha3_256, 32),
        (PqcHash::Sha3_384, 48),
        (PqcHash::Sha3_512, 64),
        (PqcHash::Shake128, 32),
        (PqcHash::Shake256, 64),
    ] {
        assert_eq!(hash.output_length(), bytes);
    }
}

#[test]
fn ecdh_and_hkdf_selectors_preserve_their_identifiers() {
    for curve in [
        AgreementCurve::P256,
        AgreementCurve::P384,
        AgreementCurve::BrainpoolP256,
        AgreementCurve::BrainpoolP384,
    ] {
        assert_eq!(
            curve.derivation_mechanism_number(),
            fe11_sys::CKM_ECDH1_DERIVE as u64
        );
    }
    for kind in [HkdfKeyType::Generic, HkdfKeyType::Dedicated] {
        assert_eq!(
            kind.derivation_mechanism_number(),
            fe11_sys::CKM_HKDF_DERIVE as u64
        );
    }
    for (kdf, expected) in [
        (EcdhKdf::Null, fe11_sys::CKD_NULL as u64),
        (EcdhKdf::X963Sha256, fe11_sys::CKD_SHA256_KDF as u64),
        (EcdhKdf::ConcatSha256, fe11_sys::CKD_SHA256_KDF_SP800 as u64),
    ] {
        assert_eq!(kdf.identifier(), expected);
    }
    // This public carrier stores a u64; conversion for a native call is a
    // separate ABI boundary. In particular, unknown high bits stay intact here.
    for raw in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
        assert_eq!(EcdhKdf::Native(raw).identifier(), raw);
    }
}

#[test]
fn montgomery_domains_keep_their_distinct_native_encodings() {
    let expected: [(MontgomeryDomain, &[u8], usize); 4] = [
        (MontgomeryDomain::Curve25519, b"\x13\x0acurve25519", 32),
        (MontgomeryDomain::Curve448, b"\x13\x08curve448", 56),
        (MontgomeryDomain::X25519, &[6, 3, 0x2b, 0x65, 0x6e], 32),
        (MontgomeryDomain::X448, &[6, 3, 0x2b, 0x65, 0x6f], 56),
    ];
    for (domain, der, width) in expected {
        assert_eq!(domain.parameters_der(), der);
        assert_eq!(domain.public_key_length(), width);
        assert_eq!(
            domain.generation_mechanism_number(),
            fe11_sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN as u64
        );
    }
}

#[test]
fn aes_mode_identity_is_independent_of_iv_and_counter_bytes() {
    for fill in [0, 0xa5, 0xff] {
        for (parameters, expected) in [
            (AesCipherParameters::Ecb, fe11_sys::CKM_AES_ECB),
            (
                AesCipherParameters::Cbc { iv: [fill; 16] },
                fe11_sys::CKM_AES_CBC,
            ),
            (
                AesCipherParameters::CbcPad { iv: [fill; 16] },
                fe11_sys::CKM_AES_CBC_PAD,
            ),
            (
                AesCipherParameters::Ctr {
                    counter_bits: 128,
                    counter_block: [fill; 16],
                },
                fe11_sys::CKM_AES_CTR,
            ),
            (
                AesCipherParameters::Ofb { iv: [fill; 16] },
                fe11_sys::CKM_AES_OFB,
            ),
            (
                AesCipherParameters::Cfb8 { iv: [fill; 16] },
                fe11_sys::CKM_AES_CFB8,
            ),
            (
                AesCipherParameters::Cfb64 { iv: [fill; 16] },
                fe11_sys::CKM_AES_CFB64,
            ),
            (
                AesCipherParameters::Cfb128 { iv: [fill; 16] },
                fe11_sys::CKM_AES_CFB128,
            ),
        ] {
            assert_eq!(parameters.mechanism_number(), expected as u64);
        }
    }
}

#[test]
fn symmetric_algorithm_identity_does_not_select_a_key_length() {
    for (algorithm, expected) in [
        (SymmetricAlgorithm::Aes128, fe11_sys::CKM_AES_GCM),
        (SymmetricAlgorithm::Aes192, fe11_sys::CKM_AES_GCM),
        (SymmetricAlgorithm::Aes256, fe11_sys::CKM_AES_GCM),
        (
            SymmetricAlgorithm::ChaCha20,
            fe11_sys::CKM_CHACHA20_POLY1305,
        ),
    ] {
        assert_eq!(algorithm.mechanism_number(), expected as u64);
    }
    for length in [0, 1, 32, usize::MAX] {
        for (algorithm, expected) in [
            (
                SymmetricAlgorithm::HmacSha256 { key_length: length },
                fe11_sys::CKM_SHA256_HMAC,
            ),
            (
                SymmetricAlgorithm::HmacSha384 { key_length: length },
                fe11_sys::CKM_SHA384_HMAC,
            ),
            (
                SymmetricAlgorithm::HmacSha512 { key_length: length },
                fe11_sys::CKM_SHA512_HMAC,
            ),
        ] {
            assert_eq!(algorithm.mechanism_number(), expected as u64);
        }
    }
}

#[test]
fn native_truncation_metadata_is_present_only_for_sha512_t() {
    for algorithm in NativeDigestAlgorithm::ALL {
        if !matches!(algorithm, NativeDigestAlgorithm::Sha512T(_)) {
            assert_eq!(algorithm.truncation_bits(), None);
        }
    }
    for bits in [0, 1, 7, 8, 224, 256, 511, 512] {
        let value = NativeDigestTruncation::new(bits).expect("representable bit count");
        assert_eq!(
            NativeDigestAlgorithm::Sha512T(value).truncation_bits(),
            Some(bits)
        );
    }
}

#[test]
fn token_generated_iv_mechanisms_keep_all_named_identifiers() {
    for (kind, expected) in [
        (TokenIvCipher::SkipjackEcb64, fe11_sys::CKM_SKIPJACK_ECB64),
        (TokenIvCipher::SkipjackCbc64, fe11_sys::CKM_SKIPJACK_CBC64),
        (TokenIvCipher::SkipjackOfb64, fe11_sys::CKM_SKIPJACK_OFB64),
        (TokenIvCipher::SkipjackCfb64, fe11_sys::CKM_SKIPJACK_CFB64),
        (TokenIvCipher::SkipjackCfb32, fe11_sys::CKM_SKIPJACK_CFB32),
        (TokenIvCipher::SkipjackCfb16, fe11_sys::CKM_SKIPJACK_CFB16),
        (TokenIvCipher::SkipjackCfb8, fe11_sys::CKM_SKIPJACK_CFB8),
        (TokenIvCipher::BatonEcb128, fe11_sys::CKM_BATON_ECB128),
        (TokenIvCipher::BatonEcb96, fe11_sys::CKM_BATON_ECB96),
        (TokenIvCipher::BatonCbc128, fe11_sys::CKM_BATON_CBC128),
        (TokenIvCipher::BatonCounter, fe11_sys::CKM_BATON_COUNTER),
        (TokenIvCipher::BatonShuffle, fe11_sys::CKM_BATON_SHUFFLE),
        (TokenIvCipher::JuniperEcb128, fe11_sys::CKM_JUNIPER_ECB128),
        (TokenIvCipher::JuniperCbc128, fe11_sys::CKM_JUNIPER_CBC128),
        (TokenIvCipher::JuniperCounter, fe11_sys::CKM_JUNIPER_COUNTER),
        (TokenIvCipher::JuniperShuffle, fe11_sys::CKM_JUNIPER_SHUFFLE),
    ] {
        assert_eq!(kind.mechanism_number(), expected as u64);
    }
}
