// SPDX-License-Identifier: Apache-2.0
//! Borrowed public input validation, separated from attribute materialization.

use super::{public_algorithm_oid, EdwardsOptions};
use crate::crypto::{
    dsa::{self, DsaPublic},
    integer_key::{self, RsaPublic},
    public_key::{curve_spki, CurvePublicKey, EdwardsCurve},
    EdwardsPointEncoding,
};
use crate::{EcCurve, Error, Result};
use der::{
    asn1::{ObjectIdentifier, OctetStringRef},
    Encode,
};
use fe11_sys::{
    CKA_BASE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS, CKA_PRIME, CKA_PUBLIC_EXPONENT,
    CKA_SUBPRIME, CKA_VALUE, CKK_DSA, CKK_EC, CKK_EC_EDWARDS, CKK_RSA, CK_KEY_TYPE,
};

pub(super) enum VerificationInput<'a> {
    Rsa(RsaPublic<'a>),
    Dsa(DsaPublic<'a>),
    Curve(CurveInput<'a>),
}

pub(super) enum PublicMaterial {
    Rsa,
    Dsa,
    Weierstrass(EcCurve),
    Edwards(EdwardsCurve),
}

#[derive(Clone, Copy)]
enum CurveFamily {
    Weierstrass(EcCurve),
    Edwards(EdwardsCurve),
}

pub(super) struct CurveInput<'a> {
    family: CurveFamily,
    parameters: &'static [u8],
    point: &'a [u8],
    octet_string: bool,
    encoding_error: crate::RejectionReason,
}

impl<'a> CurveInput<'a> {
    pub(super) fn parse(spki: &'a [u8], semantics: EdwardsOptions) -> Result<Self> {
        let (family, parameters, point, octet_string, encoding_error) = match curve_spki(spki)? {
            CurvePublicKey::Weierstrass(curve, point) => (
                CurveFamily::Weierstrass(curve),
                curve.domain().oid_der,
                point,
                true,
                crate::RejectionReason::PublicVerification(
                    crate::PublicVerificationRejection::EcPointEncoding,
                ),
            ),
            CurvePublicKey::Edwards(curve, point) => {
                let parameters = semantics.parameter_encoding.bytes(curve);
                (
                    CurveFamily::Edwards(curve),
                    parameters,
                    point,
                    semantics.point_encoding == EdwardsPointEncoding::DerOctetString,
                    crate::RejectionReason::PublicVerification(
                        crate::PublicVerificationRejection::EdwardsPointEncoding,
                    ),
                )
            }
        };
        if octet_string {
            OctetStringRef::new(point)
                .and_then(|point| point.encoded_len())
                .map_err(|_| Error::Rejected(encoding_error))?;
        }
        Ok(Self {
            family,
            parameters,
            point,
            octet_string,
            encoding_error,
        })
    }
}

impl<'a> VerificationInput<'a> {
    pub(super) fn kind(&self) -> CK_KEY_TYPE {
        match self {
            Self::Rsa(_) => CKK_RSA,
            Self::Dsa(_) => CKK_DSA,
            Self::Curve(curve) => match curve.family {
                CurveFamily::Weierstrass(_) => CKK_EC,
                CurveFamily::Edwards(_) => CKK_EC_EDWARDS,
            },
        }
    }

    /// Only Template materializes components. TemplateSize visits the same
    /// borrowed slices without allocating public attributes or a DER point.
    pub(super) fn template<T: crate::attributes::TemplateSink>(
        &self,
        id: crate::attributes::ByteParts<'_>,
        label: &[u8],
        options: &crate::PublicKeyImportOptions,
    ) -> Result<T> {
        let metadata = Some((id, label));
        Ok(match self {
            Self::Rsa(key) => super::super::public_import::template_with(
                self.kind(),
                metadata,
                options,
                |t: &mut T| {
                    t.bytes(CKA_MODULUS, key.modulus);
                    t.bytes(CKA_PUBLIC_EXPONENT, key.exponent);
                },
            ),
            Self::Dsa(key) => super::super::public_import::template_with(
                self.kind(),
                metadata,
                options,
                |t: &mut T| {
                    t.bytes(CKA_PRIME, key.p);
                    t.bytes(CKA_SUBPRIME, key.q);
                    t.bytes(CKA_BASE, key.g);
                    t.bytes(CKA_VALUE, key.y);
                },
            ),
            Self::Curve(curve) => {
                // One short tag, one length-of-length byte and usize's bytes
                // cover the DER header of any slice representable on this host.
                // RustCrypto emits the header; no alternate DER encoder is used.
                let mut header = [0u8; 2 + std::mem::size_of::<usize>()];
                let point = if curve.octet_string {
                    let encoded = der::Header::new(der::Tag::OctetString, curve.point.len())
                        .and_then(|value| value.encode_to_slice(&mut header))
                        .map_err(|_| Error::Rejected(curve.encoding_error))?;
                    crate::attributes::ByteParts::joined(encoded, curve.point)?
                } else {
                    curve.point.into()
                };
                super::super::public_import::template_with(
                    self.kind(),
                    metadata,
                    options,
                    |t: &mut T| {
                        t.bytes(CKA_EC_PARAMS, curve.parameters);
                        t.byte_parts(CKA_EC_POINT, point);
                    },
                )
            }
        })
    }

    pub(super) fn material(&self) -> PublicMaterial {
        match self {
            Self::Rsa(_) => PublicMaterial::Rsa,
            Self::Dsa(_) => PublicMaterial::Dsa,
            Self::Curve(curve) => match curve.family {
                CurveFamily::Weierstrass(curve) => PublicMaterial::Weierstrass(curve),
                CurveFamily::Edwards(curve) => PublicMaterial::Edwards(curve),
            },
        }
    }

    pub(super) fn parse(spki: &'a [u8], semantics: EdwardsOptions) -> Result<Self> {
        let oid = public_algorithm_oid(spki)?;
        if oid == ObjectIdentifier::new_unwrap("1.2.840.10040.4.1") {
            Ok(Self::Dsa(dsa::dsa_der(spki)?))
        } else if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
            Ok(Self::Rsa(integer_key::rsa_der(spki)?))
        } else {
            CurveInput::parse(spki, semantics).map(Self::Curve)
        }
    }
}
