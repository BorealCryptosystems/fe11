// SPDX-License-Identifier: Apache-2.0
//! Declarations decoded from a private-key encoding, without correspondence checks.
use crate::ClassicalKeyAlgorithm;
use der::asn1::ObjectIdentifier;

/// Metadata declared by a decoded private-key encoding, without private bytes.
/// These declarations do not attest native acceptance or public/private matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateEncodingReport {
    pub(crate) destination: ClassicalKeyAlgorithm,
    pub(crate) encoded_algorithm: ObjectIdentifier,
    pub(crate) outer_curve: Option<ObjectIdentifier>,
    pub(crate) inner_curve: Option<ObjectIdentifier>,
    pub(crate) scalar_bytes: Option<usize>,
    pub(crate) embedded_public: bool,
    pub(crate) supplied_spki_bytes: usize,
}
impl PrivateEncodingReport {
    /// Explicit destination selection, never silently replaced by encoded metadata.
    pub fn destination(&self) -> ClassicalKeyAlgorithm {
        self.destination
    }
    /// Algorithm OID value octets declared by the private encoding (without tag/length).
    pub fn encoded_algorithm_oid(&self) -> &[u8] {
        self.encoded_algorithm.as_bytes()
    }
    /// Outer EC named-curve OID value octets, as declared in PKCS#8.
    pub fn outer_curve_oid(&self) -> Option<&[u8]> {
        self.outer_curve.as_ref().map(ObjectIdentifier::as_bytes)
    }
    /// Inner EC named-curve OID value octets, if declared in ECPrivateKey.
    pub fn inner_curve_oid(&self) -> Option<&[u8]> {
        self.inner_curve.as_ref().map(ObjectIdentifier::as_bytes)
    }
    /// Encoded scalar/seed width, not evidence of a usable private value.
    pub fn scalar_bytes(&self) -> Option<usize> {
        self.scalar_bytes
    }
    /// Whether ECPrivateKey carried a public BIT STRING; not a native observation.
    pub fn has_embedded_public(&self) -> bool {
        self.embedded_public
    }
    /// Length of the supplied public declaration, without a validity claim.
    pub fn supplied_spki_bytes(&self) -> usize {
        self.supplied_spki_bytes
    }
}
