// SPDX-License-Identifier: Apache-2.0
//! Public algorithm metadata and transparent type aliases.
use fe11::*;

#[test]
fn symmetric_lengths_and_key_generation() {
    use fe11_sys::*;
    use SymmetricAlgorithm::*;
    for (algorithm, length, mechanism) in [
        (Aes128, 16, CKM_AES_KEY_GEN),
        (Aes192, 24, CKM_AES_KEY_GEN),
        (Aes256, 32, CKM_AES_KEY_GEN),
        (ChaCha20, 32, CKM_CHACHA20_KEY_GEN),
    ] {
        assert_eq!(algorithm.key_length(), length);
        assert_eq!(algorithm.mac_length(), None);
        assert_eq!(algorithm.generation_mechanism(None), Ok(mechanism as u64));
        for kind in [HmacKeyType::Dedicated, HmacKeyType::Generic] {
            assert!(matches!(
                algorithm.generation_mechanism(Some(kind)),
                Err(Error::Rejected(RejectionReason::SymmetricParameters(
                    SymmetricParametersRejection::HmacKeyTypeOnAead
                )))
            ));
        }
    }
    for key_length in [0, 1, 32, usize::MAX] {
        for (algorithm, digest_bytes, generate) in [
            (HmacSha256 { key_length }, 32, CKM_SHA256_KEY_GEN),
            (HmacSha384 { key_length }, 48, CKM_SHA384_KEY_GEN),
            (HmacSha512 { key_length }, 64, CKM_SHA512_KEY_GEN),
        ] {
            assert_eq!(algorithm.key_length(), key_length);
            assert_eq!(algorithm.mac_length(), Some(digest_bytes));
            assert!(matches!(
                algorithm.generation_mechanism(None),
                Err(Error::Rejected(RejectionReason::SymmetricParameters(
                    SymmetricParametersRejection::HmacKeyTypeRequired
                )))
            ));
            assert_eq!(
                algorithm.generation_mechanism(Some(HmacKeyType::Generic)),
                Ok(CKM_GENERIC_SECRET_KEY_GEN as u64)
            );
            assert_eq!(
                algorithm.generation_mechanism(Some(HmacKeyType::Dedicated)),
                Ok(generate as u64)
            );
        }
    }
}

#[test]
fn edwards_field_and_encoding_sizes() {
    use EdwardsKeySizeUnits::*;
    for (ed448, field, encoded) in [(false, 255, 256), (true, 448, 456)] {
        assert_eq!(FieldBits.bits(ed448), field);
        assert_eq!(EncodedPointBits.bits(ed448), encoded);
    }
}

#[test]
fn hkdf_hash_is_specific_to_the_requested_path() {
    use DerivationPath::*;
    for path in [HkdfExtractExpand, HkdfExtract, HkdfExpand] {
        assert_eq!(path.hkdf_hash(), Some(fe11_sys::CKM_SHA256 as u64));
    }
    for hash in [0, 1, fe11_sys::CKM_SHA384 as u64, u64::MAX] {
        for path in [
            HkdfExtractExpandWithHash(hash),
            HkdfExtractWithHash(hash),
            HkdfExpandWithHash(hash),
        ] {
            assert_eq!(path.hkdf_hash(), Some(hash));
        }
    }
    for kdf in [
        EcdhKdf::Null,
        EcdhKdf::X963Sha256,
        EcdhKdf::ConcatSha256,
        EcdhKdf::Native(u64::MAX),
    ] {
        assert_eq!(Ecdh(kdf).hkdf_hash(), None);
    }
}

// Passing the identity function in both type positions checks alias equality
// without constructing opaque ciphertext or giving a borrowed value a longer life.
#[test]
fn aliases_accept_their_canonical_type_in_both_directions() {
    macro_rules! equivalent {
        ($alias:ty, $canonical:ty) => {{
            let _: fn($alias) -> $canonical = std::convert::identity;
            let _: fn($canonical) -> $alias = std::convert::identity;
        }};
    }
    equivalent!(AesBufferRequest, CipherBufferRequest);
    equivalent!(AesCiphertext, Ciphertext);
    equivalent!(AesOutputPlan, CipherOutputPlan);
    equivalent!(HistoricalBoolean, Observation<bool>);
    fn check_borrow<'a>(value: MacMessage<'a>) -> SignatureMessage<'a> {
        let _: fn(SignatureMessage<'a>) -> MacMessage<'a> = std::convert::identity;
        value
    }
    let _: for<'a> fn(MacMessage<'a>) -> SignatureMessage<'a> = check_borrow;
    fn result_alias<T>(value: Result<T>) -> std::result::Result<T, Error> {
        let _: fn(std::result::Result<T, Error>) -> Result<T> = std::convert::identity;
        value
    }
    assert_eq!(result_alias::<u32>(Ok(42)), Ok(42));
    equivalent!(SessionAdmission, ResourceAdmission);
    equivalent!(TransportHistoricalAttributes, HistoricalAttributes);
    equivalent!(TransportProtection, BaseProtection);
    equivalent!(UnauthenticatedAesPlaintext, UnauthenticatedCipherPlaintext);
}

// RFC 9881 and RFC 9909 identify each parameter set. Signature lengths
// are checked against the raw signatures of the published NIST vectors.
#[test]
fn standard_signature_metadata() {
    use MlDsaParameterSet::*;
    use SlhDsaParameterSet::*;
    let parameters = [
        (
            PqcAlgorithm::MlDsa(MlDsa44),
            "ML-DSA-44",
            "2.16.840.1.101.3.4.3.17",
            2420,
        ),
        (
            PqcAlgorithm::MlDsa(MlDsa65),
            "ML-DSA-65",
            "2.16.840.1.101.3.4.3.18",
            3309,
        ),
        (
            PqcAlgorithm::MlDsa(MlDsa87),
            "ML-DSA-87",
            "2.16.840.1.101.3.4.3.19",
            4627,
        ),
        (
            PqcAlgorithm::SlhDsa(Sha2_128s),
            "SLH-DSA-SHA2-128s",
            "2.16.840.1.101.3.4.3.20",
            7856,
        ),
        (
            PqcAlgorithm::SlhDsa(Sha2_128f),
            "SLH-DSA-SHA2-128f",
            "2.16.840.1.101.3.4.3.21",
            17088,
        ),
        (
            PqcAlgorithm::SlhDsa(Sha2_192s),
            "SLH-DSA-SHA2-192s",
            "2.16.840.1.101.3.4.3.22",
            16224,
        ),
        (
            PqcAlgorithm::SlhDsa(Sha2_192f),
            "SLH-DSA-SHA2-192f",
            "2.16.840.1.101.3.4.3.23",
            35664,
        ),
        (
            PqcAlgorithm::SlhDsa(Sha2_256s),
            "SLH-DSA-SHA2-256s",
            "2.16.840.1.101.3.4.3.24",
            29792,
        ),
        (
            PqcAlgorithm::SlhDsa(Sha2_256f),
            "SLH-DSA-SHA2-256f",
            "2.16.840.1.101.3.4.3.25",
            49856,
        ),
        (
            PqcAlgorithm::SlhDsa(Shake128s),
            "SLH-DSA-SHAKE-128s",
            "2.16.840.1.101.3.4.3.26",
            7856,
        ),
        (
            PqcAlgorithm::SlhDsa(Shake128f),
            "SLH-DSA-SHAKE-128f",
            "2.16.840.1.101.3.4.3.27",
            17088,
        ),
        (
            PqcAlgorithm::SlhDsa(Shake192s),
            "SLH-DSA-SHAKE-192s",
            "2.16.840.1.101.3.4.3.28",
            16224,
        ),
        (
            PqcAlgorithm::SlhDsa(Shake192f),
            "SLH-DSA-SHAKE-192f",
            "2.16.840.1.101.3.4.3.29",
            35664,
        ),
        (
            PqcAlgorithm::SlhDsa(Shake256s),
            "SLH-DSA-SHAKE-256s",
            "2.16.840.1.101.3.4.3.30",
            29792,
        ),
        (
            PqcAlgorithm::SlhDsa(Shake256f),
            "SLH-DSA-SHAKE-256f",
            "2.16.840.1.101.3.4.3.31",
            49856,
        ),
    ];
    for (algorithm, name, oid, signature_bytes) in parameters {
        assert_eq!(algorithm.name(), name);
        assert_eq!(algorithm.oid().to_string(), oid);
        assert_eq!(algorithm.signature_length(), signature_bytes);
    }
}
