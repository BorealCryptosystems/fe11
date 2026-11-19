// SPDX-License-Identifier: Apache-2.0
//! Canonical public SPKI controls with one structural mutation at a time.
//! The public values and independently assembled wrappers are documented with
//! the fixtures. No private material or native operation is involved.
use fe11::*;

fn malformed_encodings(valid: &[u8], oid_last: usize) -> Vec<Vec<u8>> {
    assert_eq!(valid[0], 0x30);
    assert!(valid[oid_last] < 0x80);
    let mut wrong_tag = valid.to_vec();
    wrong_tag[0] = 0x31;
    let mut trailing = valid.to_vec();
    trailing.push(0);
    let mut bad_oid = valid.to_vec();
    bad_oid[oid_last] |= 0x80;
    // Add a redundant leading length octet, without changing the content.
    let overlong = if valid[1] < 0x80 {
        [vec![0x30, 0x81, valid[1]], valid[2..].to_vec()].concat()
    } else {
        let octets = usize::from(valid[1] & 0x7f);
        assert!(matches!(octets, 1 | 2));
        [
            vec![0x30, 0x80 | (octets as u8 + 1), 0],
            valid[2..].to_vec(),
        ]
        .concat()
    };
    vec![
        wrong_tag,
        vec![0x30],
        vec![0x30, 0x82, 0x01],
        valid[..valid.len() - 1].to_vec(),
        overlong,
        trailing,
        bad_oid,
    ]
}

#[test]
fn agreement_spki_framing_partitions() {
    let valid = include_bytes!("../vectors/der-framing/p256.der");
    assert!(AgreementPeer::from_spki(AgreementCurve::P256, valid).is_ok());
    for (index, bad) in malformed_encodings(valid, 12).iter().enumerate() {
        assert!(
            matches!(
                AgreementPeer::from_spki(AgreementCurve::P256, bad),
                Err(Error::Rejected(RejectionReason::KeyEncoding(
                    KeyEncodingRejection::SpkiDer
                )))
            ),
            "structural partition {index}"
        );
    }
    assert!(AgreementPeer::from_spki(AgreementCurve::P256, valid).is_ok());
}

#[test]
fn montgomery_spki_framing_partitions() {
    let valid = include_bytes!("../vectors/der-framing/x25519.der");
    let key = MontgomeryPublicKey::from_spki(valid).unwrap();
    assert_eq!(key.domain(), MontgomeryDomain::X25519);
    assert_eq!(key.to_spki().unwrap(), valid);
    assert_eq!(key.native_bytes(), &valid[12..]);
    for (index, bad) in malformed_encodings(valid, 8).iter().enumerate() {
        assert!(
            matches!(
                MontgomeryPublicKey::from_spki(bad),
                Err(Error::Rejected(RejectionReason::KeyDerivation(
                    KeyDerivationRejection::MontgomerySpkiDer
                )))
            ),
            "structural partition {index}"
        );
    }
    assert_eq!(
        MontgomeryPublicKey::from_spki(valid)
            .unwrap()
            .to_spki()
            .unwrap(),
        valid
    );
}

#[test]
fn kem_spki_framing_partitions() {
    let valid = include_bytes!("../vectors/der-framing/mlkem512.der");
    let key = KemPublicKey::from_spki(valid).unwrap();
    assert_eq!(key.parameter_set(), MlKemParameterSet::MlKem512);
    assert_eq!(key.to_spki().unwrap(), valid);
    assert_eq!(key.as_raw(), &valid[22..]);
    for (index, bad) in malformed_encodings(valid, 16).iter().enumerate() {
        assert!(
            matches!(
                KemPublicKey::from_spki(bad),
                Err(Error::Rejected(RejectionReason::KeyEncapsulation(
                    KeyEncapsulationRejection::MlKemSpkiDer
                )))
            ),
            "structural partition {index}"
        );
    }
    assert_eq!(
        KemPublicKey::from_spki(valid).unwrap().to_spki().unwrap(),
        valid
    );
}

#[test]
fn pqc_signature_spki_framing_partitions() {
    let valid = include_bytes!("../vectors/der-framing/mldsa44.der");
    let key = PqcPublicKey::from_spki(valid).unwrap();
    assert_eq!(
        key.algorithm(),
        PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44)
    );
    assert_eq!(key.to_spki().unwrap(), valid);
    assert_eq!(key.as_raw(), &valid[22..]);
    for (index, bad) in malformed_encodings(valid, 16).iter().enumerate() {
        assert!(
            matches!(
                PqcPublicKey::from_spki(bad),
                Err(Error::Rejected(RejectionReason::PostQuantumKeys(
                    PostQuantumKeysRejection::PqcPublicSpkiDer
                )))
            ),
            "structural partition {index}"
        );
    }
    assert_eq!(
        PqcPublicKey::from_spki(valid).unwrap().to_spki().unwrap(),
        valid
    );
}
