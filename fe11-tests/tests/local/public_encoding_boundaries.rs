// SPDX-License-Identifier: Apache-2.0
//! Public encoding boundaries use fixed malformed operands and valid controls.
//! These checks establish representation contracts, not module interoperability.
use fe11::*;
const ALGORITHM: PqcAlgorithm = PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44);
fn valid_public_control() {
    let raw = include_bytes!("../vectors/public-encoding/mldsa44-public.bin");
    let key = PqcPublicKey::from_spki(include_bytes!(
        "../vectors/public-encoding/mldsa44-spki.der"
    ))
    .expect("canonical public ACVP key");
    assert_eq!(key.algorithm(), ALGORITHM);
    assert_eq!(key.as_raw(), raw);
    assert_eq!(
        key.to_spki().expect("canonical public encoding").as_slice(),
        include_bytes!("../vectors/public-encoding/mldsa44-spki.der").as_slice()
    );
}
fn rejected<T>(value: Result<T>, reason: PostQuantumKeysRejection) {
    match value {
        Err(Error::Rejected(RejectionReason::PostQuantumKeys(actual))) => {
            assert_eq!(actual, reason)
        }
        Err(error) => panic!("unexpected public encoding error: {error}"),
        Ok(_) => panic!("malformed public encoding accepted"),
    }
}
#[test]
fn pqc_public_algorithm() {
    valid_public_control();
    let input = include_bytes!("../vectors/public-encoding/pqc_public_algorithm.bin");
    rejected(
        PqcPublicKey::from_spki(input),
        PostQuantumKeysRejection::PqcPublicAlgorithm,
    );
    valid_public_control();
}

#[test]
fn pqc_public_key_length() {
    valid_public_control();
    let input = include_bytes!("../vectors/public-encoding/pqc_public_key_length.bin");
    rejected(
        PqcPublicKey::from_raw(ALGORITHM, input),
        PostQuantumKeysRejection::PqcPublicKeyLength,
    );
    valid_public_control();
}

#[test]
fn pqc_public_parameters_must_be_absent() {
    valid_public_control();
    let input =
        include_bytes!("../vectors/public-encoding/pqc_public_parameters_must_be_absent.bin");
    rejected(
        PqcPublicKey::from_spki(input),
        PostQuantumKeysRejection::PqcPublicParametersMustBeAbsent,
    );
    valid_public_control();
}

#[test]
fn pqc_public_spki_der() {
    valid_public_control();
    let input = include_bytes!("../vectors/public-encoding/pqc_public_spki_der.bin");
    rejected(
        PqcPublicKey::from_spki(input),
        PostQuantumKeysRejection::PqcPublicSpkiDer,
    );
    valid_public_control();
}

#[test]
fn pqc_public_unused_bits() {
    valid_public_control();
    let input = include_bytes!("../vectors/public-encoding/pqc_public_unused_bits.bin");
    rejected(
        PqcPublicKey::from_spki(input),
        PostQuantumKeysRejection::PqcPublicUnusedBits,
    );
    valid_public_control();
}

#[test]
fn pqc_signature_length() {
    valid_public_control();
    let input = include_bytes!("../vectors/public-encoding/pqc_signature_length.bin");
    rejected(
        PqcSignature::from_bytes(ALGORITHM, input),
        PostQuantumKeysRejection::PqcSignatureLength,
    );
    valid_public_control();
    assert!(PqcSignature::from_bytes(ALGORITHM, &[0; 2420]).is_ok());
}

#[test]
fn sha256_digest_length() {
    assert!(Digest32::from_bytes(&[0; 32]).is_ok());
    let input = include_bytes!("../vectors/public-encoding/sha256_digest_length.bin");
    assert!(matches!(
        Digest32::from_bytes(input),
        Err(Error::Rejected(RejectionReason::SessionLifecycle(
            SessionLifecycleRejection::Sha256DigestLength
        )))
    ));
    assert!(Digest32::from_bytes(&[0; 32]).is_ok());
}

#[test]
fn pqc_public_spki_bound() {
    valid_public_control();
    let input = include_bytes!("../vectors/public-encoding/pqc_public_spki_bound.bin");
    rejected(
        PqcPublicKey::from_spki(input),
        PostQuantumKeysRejection::PqcPublicSpkiBound,
    );
    valid_public_control();
}
