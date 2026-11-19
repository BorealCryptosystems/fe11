// SPDX-License-Identifier: Apache-2.0
//! Public constructor boundaries and owned-value observations.
use fe11::*;

#[test]
fn kem_key_width_mlkem512_0() {
    let input = Vec::<u8>::new();
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_key_width_mlkem512_799() {
    let input = vec![0x00; 799];
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_key_width_mlkem512_800() {
    let mut input = vec![0x00; 800];
    let original = input.clone();
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem512, &input);
    let actual = actual.expect("structurally valid public input");
    input.fill(0xff);
    assert_eq!(actual.parameter_set(), MlKemParameterSet::MlKem512);
    assert_eq!(actual.as_raw(), original);
}

#[test]
fn kem_key_width_mlkem512_801() {
    let input = vec![0x00; 801];
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem512_0() {
    let input = Vec::<u8>::new();
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem512_767() {
    let input = vec![0x00; 767];
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem512_768() {
    let mut input = vec![0x00; 768];
    let original = input.clone();
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem512, &input);
    let actual = actual.expect("structurally valid public input");
    input.fill(0xff);
    assert_eq!(actual.parameter_set(), MlKemParameterSet::MlKem512);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn kem_cipher_width_mlkem512_769() {
    let input = vec![0x00; 769];
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem512, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_key_width_mlkem768_0() {
    let input = Vec::<u8>::new();
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem768, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_key_width_mlkem768_1183() {
    let input = vec![0x00; 1183];
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem768, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_key_width_mlkem768_1184() {
    let mut input = vec![0x00; 1184];
    let original = input.clone();
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem768, &input);
    let actual = actual.expect("structurally valid public input");
    input.fill(0xff);
    assert_eq!(actual.parameter_set(), MlKemParameterSet::MlKem768);
    assert_eq!(actual.as_raw(), original);
}

#[test]
fn kem_key_width_mlkem768_1185() {
    let input = vec![0x00; 1185];
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem768, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem768_0() {
    let input = Vec::<u8>::new();
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem768, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem768_1087() {
    let input = vec![0x00; 1087];
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem768, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem768_1088() {
    let mut input = vec![0x00; 1088];
    let original = input.clone();
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem768, &input);
    let actual = actual.expect("structurally valid public input");
    input.fill(0xff);
    assert_eq!(actual.parameter_set(), MlKemParameterSet::MlKem768);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn kem_cipher_width_mlkem768_1089() {
    let input = vec![0x00; 1089];
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem768, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_key_width_mlkem1024_0() {
    let input = Vec::<u8>::new();
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem1024, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_key_width_mlkem1024_1567() {
    let input = vec![0x00; 1567];
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem1024, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_key_width_mlkem1024_1568() {
    let mut input = vec![0x00; 1568];
    let original = input.clone();
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem1024, &input);
    let actual = actual.expect("structurally valid public input");
    input.fill(0xff);
    assert_eq!(actual.parameter_set(), MlKemParameterSet::MlKem1024);
    assert_eq!(actual.as_raw(), original);
}

#[test]
fn kem_key_width_mlkem1024_1569() {
    let input = vec![0x00; 1569];
    let actual = KemPublicKey::from_raw(MlKemParameterSet::MlKem1024, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemPublicKeyLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem1024_0() {
    let input = Vec::<u8>::new();
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem1024, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem1024_1567() {
    let input = vec![0x00; 1567];
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem1024, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}

#[test]
fn kem_cipher_width_mlkem1024_1568() {
    let mut input = vec![0x00; 1568];
    let original = input.clone();
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem1024, &input);
    let actual = actual.expect("structurally valid public input");
    input.fill(0xff);
    assert_eq!(actual.parameter_set(), MlKemParameterSet::MlKem1024);
    assert_eq!(actual.as_bytes(), original);
}

#[test]
fn kem_cipher_width_mlkem1024_1569() {
    let input = vec![0x00; 1569];
    let actual = KemCiphertext::from_bytes(MlKemParameterSet::MlKem1024, &input);
    assert!(matches!(actual, Err(Error::Rejected(RejectionReason::KeyEncapsulation(
        KeyEncapsulationRejection::MlKemCiphertextLength
    )))));
}
