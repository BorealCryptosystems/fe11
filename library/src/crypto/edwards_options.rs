// SPDX-License-Identifier: Apache-2.0
//! Explicit Edwards attribute encodings, independent of interface version policy.
use super::EdwardsCurve;
use crate::{Error, Result};

/// Representation of CKA_EC_POINT for Edwards keys, independent of size units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdwardsPointEncoding {
    /// RFC8032 bytes directly, PKCS11 3.2 section6.3.5.
    Raw,
    /// Canonical DER OCTET STRING envelope; explicitly selected interoperability.
    DerOctetString,
}
/// Exact ASN.1 representation of Edwards CKA_EC_PARAMS on an existing object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdwardsParameterEncoding {
    /// RFC8410 object identifier for Ed25519 or Ed448.
    Oid,
    /// RFC8032 curve name as an ASN.1 PrintableString.
    CurveName,
}
impl EdwardsParameterEncoding {
    pub(super) fn bytes(self, curve: EdwardsCurve) -> &'static [u8] {
        match (self, curve) {
            (Self::Oid, EdwardsCurve::Ed25519) => b"\x06\x03\x2b\x65\x70",
            (Self::Oid, EdwardsCurve::Ed448) => b"\x06\x03\x2b\x65\x71",
            (Self::CurveName, EdwardsCurve::Ed25519) => b"\x13\x0cedwards25519",
            (Self::CurveName, EdwardsCurve::Ed448) => b"\x13\x0aedwards448",
        }
    }
    pub(super) fn read(curve: EdwardsCurve, bytes: &[u8]) -> Result<Self> {
        for encoding in [Self::Oid, Self::CurveName] {
            if bytes == encoding.bytes(curve) {
                return Ok(encoding);
            }
        }
        Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::VerificationSelectorPublicIdentity,
            ),
        ))
    }
}
/// Units in CK_MECHANISM_INFO min/max, independent of point encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdwardsKeySizeUnits {
    /// Normative field sizes255/448 (PKCS11 3.2 sections6.3.10 and6.3.14).
    FieldBits,
    /// Interoperability convention256/456, excluding the DER envelope; not normative.
    EncodedPointBits,
}
impl EdwardsKeySizeUnits {
    /// Interpret a curve size for a caller-selected check of announced bounds.
    /// This calculation does not prefilter native operations.
    pub fn bits(self, ed448: bool) -> u64 {
        match (self, ed448) {
            (Self::FieldBits, false) => 255,
            (Self::FieldBits, true) => 448,
            (Self::EncodedPointBits, false) => 256,
            (Self::EncodedPointBits, true) => 456,
        }
    }
}
/// Edwards representations actually observed and matched on an admitted object.
/// These are attribute encodings, not compliance or possession attestations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdwardsEncodingReport {
    parameters: EdwardsParameterEncoding,
    point: Option<EdwardsPointEncoding>,
}
impl EdwardsEncodingReport {
    /// Actual CKA_EC_PARAMS representation, compared with the selected encoding.
    pub fn parameters(&self) -> EdwardsParameterEncoding {
        self.parameters
    }
    /// Actual decoded CKA_EC_POINT representation. None means that this report
    /// has no decoded point observation, including for a public lookup that only
    /// interprets EC_PARAMS. It never borrows a companion's observation.
    pub fn point(&self) -> Option<EdwardsPointEncoding> {
        self.point
    }
    pub(crate) fn parameters_only(parameters: EdwardsParameterEncoding) -> Self {
        Self {
            parameters,
            point: None,
        }
    }
    pub(crate) fn public(
        parameters: EdwardsParameterEncoding,
        point: EdwardsPointEncoding,
    ) -> Self {
        Self {
            parameters,
            point: Some(point),
        }
    }
}

/// Immutable module configuration. These properties are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdwardsOptions {
    /// Exact native CKA_EC_PARAMS representation for typed key operations.
    /// The SPKI wire format remains RFC8410, independently of this choice.
    pub parameter_encoding: EdwardsParameterEncoding,
    /// Exact point representation, never auto-detected or retried.
    pub point_encoding: EdwardsPointEncoding,
    /// Caller-selected interpretation of advertised bounds; native operations
    /// are not filtered by these bounds.
    pub key_size_units: EdwardsKeySizeUnits,
}
impl EdwardsOptions {
    /// Explicit curve-name/raw-point selection for PKCS11 3.2.
    /// This choice is not evidence of native support or interoperability.
    pub const PKCS11_32: Self = Self {
        parameter_encoding: EdwardsParameterEncoding::CurveName,
        point_encoding: EdwardsPointEncoding::Raw,
        key_size_units: EdwardsKeySizeUnits::FieldBits,
    };
}
