// SPDX-License-Identifier: Apache-2.0
//! Named-domain mismatch with the same canonical public P-384 SPKI.
use fe11::{AgreementCurve, AgreementPeer, Error, KeyDerivationRejection, RejectionReason};

#[test]
fn declared_curve_must_match_the_public_spki() {
    // Public Wycheproof ECDH point; provenance accompanies the numerical fixture.
    let spki = include_bytes!("../vectors/spki/p384.der");
    assert!(AgreementPeer::from_spki(AgreementCurve::P384, spki).is_ok());
    assert!(matches!(
        AgreementPeer::from_spki(AgreementCurve::P256, spki),
        Err(Error::Rejected(RejectionReason::KeyDerivation(
            KeyDerivationRejection::AgreementPeerDomain
        )))
    ));
    assert!(AgreementPeer::from_spki(AgreementCurve::P384, spki).is_ok());
}
