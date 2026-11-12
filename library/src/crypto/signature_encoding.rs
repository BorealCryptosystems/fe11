// SPDX-License-Identifier: Apache-2.0
//! Public ECDSA/DSA signature encodings with explicit conversion boundaries.
//! Verification accepts the short ECDSA form specified by PKCS#11 §6.3.1;
//! native ECDSA signing results retain the full width of the curve order.
use super::{curves::WeierstrassCurve, VerificationKey};
use crate::{Error, Result};

use x509_cert::der::{asn1::UintRef, Decode, Encode, Sequence};

#[derive(Sequence)]
struct Scalars<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

fn dsa_raw_width(order: &[u8]) -> Result<usize> {
    order
        .len()
        .checked_mul(2)
        .filter(|n| *n != 0)
        .ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaSignatureWidth,
            ),
        ))
}

/// Shape needed to split r||s for an explicit DER conversion. Short equal
/// halves are representable; zero and values outside the curve order remain
/// encodable and are left to the native verifier. This is not an admission gate.
pub(super) fn valid_ecdsa_verification(curve: WeierstrassCurve, raw: &[u8]) -> bool {
    !raw.is_empty() && raw.len() % 2 == 0 && raw.len() <= 2 * curve.domain().width
}

/// The token must create the full-width encoding, even when both scalars fit
/// a shorter representation accepted for verification.
pub(super) fn valid_ecdsa_output(curve: WeierstrassCurve, raw: &[u8]) -> bool {
    raw.len() == 2 * curve.domain().width && valid_ecdsa_verification(curve, raw)
}

pub(super) fn to_der(curve: WeierstrassCurve, raw: &[u8]) -> Result<Vec<u8>> {
    if !valid_ecdsa_verification(curve, raw) {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::EcdsaSignatureWidth,
            ),
        ));
    }
    let width = raw.len() / 2;
    let r = UintRef::new(&raw[..width]).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::EcdsaREncoding,
        ))
    })?;
    let s = UintRef::new(&raw[width..]).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::EcdsaSEncoding,
        ))
    })?;
    Scalars { r, s }.to_der().map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::EcdsaDerEncoding,
        ))
    })
}
pub(super) fn from_der(curve: WeierstrassCurve, der: &[u8]) -> Result<Vec<u8>> {
    let width = curve.domain().width;
    if der.len() > 2 * width + 10 {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::EcdsaDerSize,
            ),
        ));
    }
    let scalars = Scalars::from_der(der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::EcdsaDer,
        ))
    })?;
    if !super::canonical::matches(&scalars, der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::EcdsaDerEncoding,
        ))
    })? {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::NoncanonicalEcdsaDer,
            ),
        ));
    }
    let mut out = vec![0; 2 * width];
    for (bytes, dst) in [scalars.r.as_bytes(), scalars.s.as_bytes()]
        .into_iter()
        .zip(out.chunks_exact_mut(width))
    {
        if bytes.len() > width {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::EcdsaScalarWidth,
                ),
            ));
        }
        dst[width - bytes.len()..].copy_from_slice(bytes);
    }
    Ok(out)
}
impl VerificationKey {
    /// Decode canonical DSA DER into PKCS11 r||s using the encoded width of q.
    /// Refuses negative, nonminimal, over-width and trailing encodings.
    /// Scalar values, including zero, are left to the native verifier.
    pub fn dsa_signature_from_der(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let order = &self
            .dsa
            .as_ref()
            .ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NotADsaReference,
                ),
            ))?
            .order;
        let width = order.len();
        let raw_width = dsa_raw_width(order)?;
        let scalars = Scalars::from_der(bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaSignatureDer,
            ))
        })?;
        if !super::canonical::matches(&scalars, bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaSignatureEncoding,
            ))
        })? {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NoncanonicalDsaSignature,
                ),
            ));
        }
        let mut out = Vec::new();
        out.try_reserve_exact(raw_width).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaSignatureAllocation,
            ))
        })?;
        out.resize(raw_width, 0);
        for (v, dst) in [scalars.r.as_bytes(), scalars.s.as_bytes()]
            .into_iter()
            .zip(out.chunks_exact_mut(width))
        {
            if v.len() > width {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::DsaScalarWidth,
                    ),
                ));
            }
            dst[width - v.len()..].copy_from_slice(v);
        }
        Ok(out)
    }
    /// Encode an exact-width DSA r||s signature in canonical DER; no normalization.
    pub fn dsa_signature_to_der(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let order = &self
            .dsa
            .as_ref()
            .ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NotADsaReference,
                ),
            ))?
            .order;
        if raw.len() != dsa_raw_width(order)? {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::DsaSignatureWidth,
                ),
            ));
        }
        Scalars {
            r: UintRef::new(&raw[..order.len()]).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::DsaREncoding,
                ))
            })?,
            s: UintRef::new(&raw[order.len()..]).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::DsaSEncoding,
                ))
            })?,
        }
        .to_der()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaSignatureEncoding,
            ))
        })
    }
    /// Convert PKCS#11 r||s to canonical DER using the selected curve's width.
    /// Equally sized short halves are accepted, as for native verification.
    /// This conversion alone does not verify a signature.
    pub fn ecdsa_signature_to_der(&self, raw: &[u8]) -> Result<Vec<u8>> {
        to_der(
            self.curve.ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NotAnEcdsaReference,
                ),
            ))?,
            raw,
        )
    }
    /// Decode canonical DER to exact-width native r||s. Negative/nonminimal
    /// INTEGERs, oversized halves, extra fields and trailing bytes are rejected.
    /// Zero and other representable scalar values are left to the native verifier.
    pub fn ecdsa_signature_from_der(&self, der: &[u8]) -> Result<Vec<u8>> {
        from_der(
            self.curve.ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NotAnEcdsaReference,
                ),
            ))?,
            der,
        )
    }
}
