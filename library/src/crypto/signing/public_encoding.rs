// SPDX-License-Identifier: Apache-2.0
//! Borrowed encoding recipe for an already returned public-attribute response.
//! No recipe owns bytes, reserves credit or makes a native call.
use super::ClassicalKeyAlgorithm;
use crate::{attributes::RequiredAttributes, Error, Result};
use der::{
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef},
    Decode, Encode, EncodeValue, FixedTag, Length, Tag, Writer,
};
use fe11_sys::{CKA_EC_POINT, CKA_MODULUS, CKA_PUBLIC_EXPONENT};
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

pub(super) enum PublicEncoding<'a> {
    Rsa {
        spki: crate::crypto::integer_key::RsaSpki<'a>,
    },
    Curve {
        algorithm: ClassicalKeyAlgorithm,
        point: &'a [u8],
    },
}
impl<'a> PublicEncoding<'a> {
    pub(super) fn new(
        values: &'a RequiredAttributes,
        algorithm: ClassicalKeyAlgorithm,
        semantics: crate::EdwardsOptions,
    ) -> Result<Self> {
        if let ClassicalKeyAlgorithm::Rsa { .. } = algorithm {
            let modulus = values.bytes(CKA_MODULUS)?;
            let exponent = values.bytes(CKA_PUBLIC_EXPONENT)?;
            return Ok(Self::Rsa {
                spki: crate::crypto::integer_key::RsaSpki::new(modulus, exponent)?,
            });
        }
        let encoded = values.bytes(CKA_EC_POINT)?;
        let point = if algorithm.curve().is_some()
            || semantics.point_encoding == crate::EdwardsPointEncoding::DerOctetString
        {
            let point = OctetStringRef::from_der(encoded).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NativePointDer,
                ))
            })?;
            if !crate::crypto::canonical::matches(&point, encoded).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NativePointEncoding,
                ))
            })? {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::NoncanonicalNativePoint,
                    ),
                ));
            }
            point.as_bytes()
        } else {
            encoded
        };
        // Validate the immutable identifier and bit-string representation at
        // the same frontier as the former allocating encoder.
        curve_oid(algorithm).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::CurveOid,
            ))
        })?;
        BitStringRef::from_bytes(point).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::PublicPointBitString,
            ))
        })?;
        Ok(Self::Curve { algorithm, point })
    }

    pub(super) fn length(&self) -> Result<usize> {
        usize::try_from(self.encoded_len().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerLength,
            ))
        })?)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerWidth,
            ))
        })
    }
}

fn curve_oid(algorithm: ClassicalKeyAlgorithm) -> der::Result<ObjectIdentifier> {
    ObjectIdentifier::from_der(match algorithm {
        ClassicalKeyAlgorithm::Ed25519 => &[6, 3, 0x2b, 0x65, 0x70],
        ClassicalKeyAlgorithm::Ed448 => &[6, 3, 0x2b, 0x65, 0x71],
        _ => algorithm.params(crate::EdwardsParameterEncoding::Oid),
    })
}

fn curve_info<T>(
    algorithm: ClassicalKeyAlgorithm,
    point: &[u8],
    encode: impl FnOnce(SubjectPublicKeyInfoRef<'_>) -> der::Result<T>,
) -> der::Result<T> {
    let oid = curve_oid(algorithm)?;
    let identifier = if algorithm.curve().is_some() {
        AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(AnyRef::from(&oid)),
        }
    } else {
        AlgorithmIdentifierRef {
            oid,
            parameters: None,
        }
    };
    encode(SubjectPublicKeyInfoRef {
        algorithm: identifier,
        subject_public_key: BitStringRef::from_bytes(point)?,
    })
}

impl FixedTag for PublicEncoding<'_> {
    const TAG: Tag = Tag::Sequence;
}
impl EncodeValue for PublicEncoding<'_> {
    fn value_len(&self) -> der::Result<Length> {
        match self {
            Self::Rsa { spki, .. } => spki.value_len(),
            Self::Curve { algorithm, point } => {
                curve_info(*algorithm, point, |spki| spki.value_len())
            }
        }
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        match self {
            Self::Rsa { spki, .. } => spki.encode_value(writer),
            Self::Curve { algorithm, point } => {
                curve_info(*algorithm, point, |spki| spki.encode_value(writer))
            }
        }
    }
}
