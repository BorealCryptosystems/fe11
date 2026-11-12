// SPDX-License-Identifier: Apache-2.0
//! Public encoding conversions for the typed native key interfaces.
//! Native admission does not impose a local mathematical key policy.
use super::curves::WeierstrassCurve;
use crate::{Error, Result};

pub(super) enum CurvePublicKey<'a> {
    Weierstrass(WeierstrassCurve, &'a [u8]),
    Edwards(EdwardsCurve, &'a [u8]),
}

/// Strict, public-only SPKI decoding for the closed EC/Edwards catalogue.
/// RSA/DSA dispatch belongs to the separate integer-key decoder. This identifies
/// the representation; it does not attest point or subgroup validity. The native
/// module decides whether the supplied public value is usable for its operation.
pub(super) fn curve_spki(der: &[u8]) -> Result<CurvePublicKey<'_>> {
    use x509_cert::{
        der::{asn1::ObjectIdentifier, Decode},
        spki::SubjectPublicKeyInfoRef,
    };
    if der.is_empty() {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::SpkiSize,
            ),
        ));
    }
    let spki = SubjectPublicKeyInfoRef::from_der(der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::SpkiDer,
        ))
    })?;
    if !super::canonical::matches(&spki, der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::SpkiEncoding,
        ))
    })? {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::NoncanonicalSpki,
        )));
    }
    let point = spki.subject_public_key.as_bytes().ok_or(Error::Rejected(
        crate::RejectionReason::KeyEncoding(crate::KeyEncodingRejection::SpkiUnusedBits),
    ))?;
    match spki.algorithm.oid {
        oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
            let params = spki.algorithm.parameters.ok_or(Error::Rejected(
                crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::EcNamedCurveRequired,
                ),
            ))?;
            let oid = params.decode_as::<ObjectIdentifier>().map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::EcParameters,
                ))
            })?;
            let mut selected = None;
            for curve in [
                WeierstrassCurve::P256,
                WeierstrassCurve::P384,
                WeierstrassCurve::P521,
                WeierstrassCurve::BrainpoolP256,
                WeierstrassCurve::BrainpoolP384,
                WeierstrassCurve::BrainpoolP512,
                WeierstrassCurve::Secp256k1,
            ] {
                if super::canonical::matches(&oid, curve.domain().oid_der).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::EcCurveEncoding,
                    ))
                })? {
                    selected = Some(curve);
                    break;
                }
            }
            let curve = selected.ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::EcCurveOutsideCatalogue,
            )))?;
            validate_weierstrass_encoding(curve, point)?;
            Ok(CurvePublicKey::Weierstrass(curve, point))
        }
        oid if oid == ObjectIdentifier::new_unwrap("1.3.101.112")
            || oid == ObjectIdentifier::new_unwrap("1.3.101.113") =>
        {
            if spki.algorithm.parameters.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::EdwardsParametersMustBeAbsent,
                )));
            }
            let curve = if oid == ObjectIdentifier::new_unwrap("1.3.101.112") {
                EdwardsCurve::Ed25519
            } else {
                EdwardsCurve::Ed448
            };
            validate_edwards_encoding(curve, point)?;
            Ok(CurvePublicKey::Edwards(curve, point))
        }
        _ => Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::CurveSpkiAlgorithm,
        ))),
    }
}

/// Width and format needed to expose the selected fixed-domain representation.
pub(super) fn validate_weierstrass_encoding(curve: WeierstrassCurve, encoded: &[u8]) -> Result<()> {
    if encoded.len() != 1 + 2 * curve.domain().width || encoded.first() != Some(&4) {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::EcPublicEncoding,
        )));
    }
    Ok(())
}

fn validate_edwards_encoding(curve: EdwardsCurve, encoded: &[u8]) -> Result<()> {
    let (width, error) = match curve {
        EdwardsCurve::Ed25519 => (
            32,
            crate::RejectionReason::KeyEncoding(crate::KeyEncodingRejection::Ed25519PublicWidth),
        ),
        EdwardsCurve::Ed448 => (
            57,
            crate::RejectionReason::KeyEncoding(crate::KeyEncodingRejection::Ed448PublicWidth),
        ),
    };
    if encoded.len() != width {
        return Err(Error::Rejected(error));
    }
    Ok(())
}

/// Closed pure Edwards curve catalogue for explicit path admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdwardsCurve {
    /// Ed25519, RFC8032 pure mode.
    Ed25519,
    /// Ed448, RFC8032 pure mode with empty context.
    Ed448,
}
