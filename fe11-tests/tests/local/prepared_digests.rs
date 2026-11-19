// SPDX-License-Identifier: Apache-2.0
//! Public constructor boundaries and owned-value observations.
use fe11::*;

#[test]
fn prepared_digest_sha224_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha224, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha224_27() {
    let input = vec![0xa5; 27];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha224, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha224_28() {
    let mut input = vec![0xa5; 28];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha224, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha224);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha224_29() {
    let input = vec![0xa5; 29];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha224, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha256_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha256, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha256_31() {
    let input = vec![0xa5; 31];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha256, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha256_32() {
    let mut input = vec![0xa5; 32];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha256, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha256);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha256_33() {
    let input = vec![0xa5; 33];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha256, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha384_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha384, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha384_47() {
    let input = vec![0xa5; 47];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha384, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha384_48() {
    let mut input = vec![0xa5; 48];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha384, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha384);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha384_49() {
    let input = vec![0xa5; 49];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha384, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha512_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha512_63() {
    let input = vec![0xa5; 63];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha512_64() {
    let mut input = vec![0xa5; 64];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha512, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha512);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha512_65() {
    let input = vec![0xa5; 65];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_224_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_224, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_224_27() {
    let input = vec![0xa5; 27];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_224, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_224_28() {
    let mut input = vec![0xa5; 28];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_224, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha3_224);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha3_224_29() {
    let input = vec![0xa5; 29];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_224, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_256_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_256, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_256_31() {
    let input = vec![0xa5; 31];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_256, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_256_32() {
    let mut input = vec![0xa5; 32];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_256, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha3_256);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha3_256_33() {
    let input = vec![0xa5; 33];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_256, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_384_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_384, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_384_47() {
    let input = vec![0xa5; 47];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_384, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_384_48() {
    let mut input = vec![0xa5; 48];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_384, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha3_384);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha3_384_49() {
    let input = vec![0xa5; 49];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_384, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_512_0() {
    let input = Vec::<u8>::new();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_512_63() {
    let input = vec![0xa5; 63];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}

#[test]
fn prepared_digest_sha3_512_64() {
    let mut input = vec![0xa5; 64];
    let original = input.clone();
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_512, &input);
    let actual = actual.expect("exact digest width");
    input.fill(0xff);
    assert_eq!(actual.algorithm(), HashAlgorithm::Sha3_512);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn prepared_digest_sha3_512_65() {
    let input = vec![0xa5; 65];
    let actual = PreparedDigest::from_bytes(HashAlgorithm::Sha3_512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::ClassicalSignatures(
        ClassicalSignaturesRejection::DigestLength
    )))));
}
