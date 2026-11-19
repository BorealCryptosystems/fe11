// SPDX-License-Identifier: Apache-2.0
//! Identifier, byte ownership and adjacent invalid sizes of caller-supplied encodings.
use fe11::*;

fn distinct_bytes(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}

#[test]
fn pqc_signature_bytes_keep_the_supplied_parameter_set() {
    use MlDsaParameterSet::*;
    use PqcAlgorithm::*;
    use SlhDsaParameterSet::*;

    // FIPS 204 and FIPS 205, Table 2 in each standard. Equal encoded lengths
    // for different parameter sets still identify distinct signature types.
    for algorithm in PqcAlgorithm::ALL {
        let width = match algorithm {
            MlDsa(MlDsa44) => 2420,
            MlDsa(MlDsa65) => 3309,
            MlDsa(MlDsa87) => 4627,
            SlhDsa(Sha2_128s | Shake128s) => 7856,
            SlhDsa(Sha2_128f | Shake128f) => 17088,
            SlhDsa(Sha2_192s | Shake192s) => 16224,
            SlhDsa(Sha2_192f | Shake192f) => 35664,
            SlhDsa(Sha2_256s | Shake256s) => 29792,
            SlhDsa(Sha2_256f | Shake256f) => 49856,
        };
        let expected = distinct_bytes(width);
        let mut supplied = expected.clone();
        let value = PqcSignature::from_bytes(algorithm, &supplied).unwrap();
        supplied.fill(0);
        assert_eq!(value.algorithm(), algorithm);
        assert_eq!(value.as_bytes(), expected);
        for invalid in [0, 1, width - 1, width + 1] {
            assert!(
                matches!(
                    PqcSignature::from_bytes(algorithm, &distinct_bytes(invalid)),
                    Err(Error::Rejected(RejectionReason::PostQuantumKeys(
                        PostQuantumKeysRejection::PqcSignatureLength
                    )))
                ),
                "{algorithm:?} at {invalid}"
            );
        }
    }
}

#[test]
fn historical_digest_preserves_declared_hash_and_input() {
    for (algorithm, width) in [(HistoricalHash::Md5, 16), (HistoricalHash::Sha1, 20)] {
        let expected = distinct_bytes(width);
        let mut supplied = expected.clone();
        let value = HistoricalDigest::from_bytes(algorithm, &supplied).unwrap();
        supplied.fill(0);
        assert_eq!(value.algorithm(), algorithm);
        assert_eq!(value.as_bytes(), expected);
        for invalid in [0, 1, width - 1, width + 1] {
            assert!(matches!(
                HistoricalDigest::from_bytes(algorithm, &distinct_bytes(invalid)),
                Err(Error::Rejected(RejectionReason::ClassicalSignatures(
                    ClassicalSignaturesRejection::HistoricalDigestWidth
                )))
            ));
        }
    }
}

#[test]
fn dsa_verification_digest_preserves_declared_hash_and_input() {
    use DsaVerificationHash::*;
    for (algorithm, width) in [
        (Sha1, 20),
        (Sha224, 28),
        (Sha256, 32),
        (Sha384, 48),
        (Sha512, 64),
    ] {
        let expected = distinct_bytes(width);
        let mut supplied = expected.clone();
        let value = DsaVerificationDigest::from_bytes(algorithm, &supplied).unwrap();
        supplied.fill(0);
        assert_eq!(value.algorithm(), algorithm);
        assert_eq!(value.as_bytes(), expected);
        for invalid in [0, 1, width - 1, width + 1] {
            assert!(matches!(
                DsaVerificationDigest::from_bytes(algorithm, &distinct_bytes(invalid)),
                Err(Error::Rejected(RejectionReason::ClassicalSignatures(
                    ClassicalSignaturesRejection::DsaDigestWidth
                )))
            ));
        }
    }
}
