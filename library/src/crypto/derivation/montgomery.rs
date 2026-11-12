// SPDX-License-Identifier: Apache-2.0
//! Explicit PKCS#11 Montgomery domains and public native encodings.
use super::BaseProtection;

use crate::{Error, ManagedObjectRef, Result};
use der::{
    asn1::{BitStringRef, ObjectIdentifier},
    Decode, Encode,
};
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// Exact CKA_EC_PARAMS representation selected by the caller.
/// PKCS#11 3.2 sections 6.3.7 and 6.3.11 distinguish RFC7748 curve names
/// from RFC8410 algorithm identifiers; this type never substitutes one for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MontgomeryDomain {
    /// PrintableString "curve25519", with RFC7748 native public bytes.
    Curve25519,
    /// PrintableString "curve448", with RFC7748 native public bytes.
    Curve448,
    /// RFC8410 id-X25519 OBJECT IDENTIFIER.
    X25519,
    /// RFC8410 id-X448 OBJECT IDENTIFIER.
    X448,
}
impl MontgomeryDomain {
    /// Exact DER value sent as CKA_EC_PARAMS; no module-dependent translation.
    pub fn parameters_der(self) -> &'static [u8] {
        match self {
            Self::Curve25519 => b"\x13\x0acurve25519",
            Self::Curve448 => b"\x13\x08curve448",
            Self::X25519 => &[0x06, 0x03, 0x2b, 0x65, 0x6e],
            Self::X448 => &[0x06, 0x03, 0x2b, 0x65, 0x6f],
        }
    }
    /// Width of the native little-endian public coordinate in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::Curve25519 | Self::X25519 => 32,
            Self::Curve448 | Self::X448 => 56,
        }
    }
    /// Native generation mechanism, without asserting module support.
    pub fn generation_mechanism_number(self) -> u64 {
        fe11_sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN as u64
    }
    fn spki_oid(self) -> Result<ObjectIdentifier> {
        match self {
            Self::X25519 => Ok(ObjectIdentifier::new_unwrap("1.3.101.110")),
            Self::X448 => Ok(ObjectIdentifier::new_unwrap("1.3.101.111")),
            Self::Curve25519 | Self::Curve448 => {
                Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::Rfc7748NamedDomainHasNoImplicitRfc8410Conversion,
                )))
            }
        }
    }
}

/// Public native bytes bound to an exact domain, without peer authentication.
/// Coordinates are not rewritten, masked, or tested by an implicit application
/// policy. The native derivation applies its specified RFC7748 processing.
pub struct MontgomeryPublicKey {
    domain: MontgomeryDomain,
    bytes: Vec<u8>,
}
impl MontgomeryPublicKey {
    /// Receive storage owned only by the unpublished pair-admission state.
    /// No caller can obtain it before observe_native replaces the full value.
    pub(super) fn observation_storage(domain: MontgomeryDomain) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(domain.public_key_length())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::MontgomeryPublicAllocation,
                ))
            })?;
        bytes.resize(domain.public_key_length(), 0);
        Ok(Self { domain, bytes })
    }

    pub(super) fn observe_native(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != self.domain.public_key_length() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomeryPublicCoordinateWidth,
            )));
        }
        self.bytes.copy_from_slice(bytes);
        Ok(())
    }

    /// Preserve the exact public coordinate after checking its normative width.
    /// This does not attest the peer, its private key, or an agreement result.
    pub fn from_native(domain: MontgomeryDomain, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != domain.public_key_length() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomeryPublicCoordinateWidth,
            )));
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomeryPublicAllocation,
            ))
        })?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            domain,
            bytes: owned,
        })
    }
    /// Parse canonical RFC8410 SPKI with absent algorithm parameters.
    /// The result selects X25519 or X448, never an RFC7748 curve-name variant.
    pub fn from_spki(encoded: &[u8]) -> Result<Self> {
        let spki = SubjectPublicKeyInfoRef::from_der(encoded).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomerySpkiDer,
            ))
        })?;
        if spki.algorithm.parameters.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomerySpkiParametersMustBeAbsent,
            )));
        }
        let domain = match spki.algorithm.oid {
            oid if oid == MontgomeryDomain::X25519.spki_oid()? => MontgomeryDomain::X25519,
            oid if oid == MontgomeryDomain::X448.spki_oid()? => MontgomeryDomain::X448,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::MontgomerySpkiAlgorithm,
                )))
            }
        };
        let bytes = spki.subject_public_key.as_bytes().ok_or(Error::Rejected(
            crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomerySpkiUnusedBits,
            ),
        ))?;
        let key = Self::from_native(domain, bytes)?;
        if key.to_spki()? != encoded {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomerySpkiNoncanonical,
            )));
        }
        Ok(key)
    }
    /// Encode RFC8410 SPKI for an explicitly selected X25519/X448 domain.
    /// Curve-name domains are refused rather than silently reinterpreted.
    pub fn to_spki(&self) -> Result<Vec<u8>> {
        SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: self.domain.spki_oid()?,
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(&self.bytes).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::MontgomeryPublicBitString,
                ))
            })?,
        }
        .to_der()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::MontgomerySpkiEncoding,
            ))
        })
    }
    /// Exact domain and native representation selected for this key.
    pub fn domain(&self) -> MontgomeryDomain {
        self.domain
    }
    /// Raw little-endian CKA_EC_POINT / ECDH public data, without DER wrapping.
    pub fn native_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn retained_bytes(&self) -> usize {
        self.bytes.capacity()
    }
}

/// Explicit native requests and independent observations for a Montgomery pair.
pub struct MontgomeryKeySpec {
    /// Public usage bits sent to the module.
    pub public_usages: crate::KeyUsageRequest,
    /// Private usage bits sent to the module.
    pub private_usages: crate::KeyUsageRequest,
    /// Native public visibility request.
    pub public_visibility: crate::ObjectVisibility,
    /// Native private visibility request.
    pub private_visibility: crate::ObjectVisibility,
    /// Independent public observations.
    pub public_admission: crate::ObjectAdmission,
    /// Independent private observations.
    pub private_admission: crate::ObjectAdmission,
    /// Private allowed-mechanism observation and comparison.
    pub mechanisms: crate::MechanismObservationPlan,
    /// Exact parameter representation, without implicit normalization.
    pub domain: MontgomeryDomain,
    /// Native CKA_ID; destination checks are independently selected.
    pub id: Vec<u8>,
    /// Native UTF-8 label.
    pub label: String,
    /// True requests token objects; false requests session objects.
    pub persistent: bool,
}
/// Opaque native Montgomery private key with caller-requested native observations.
pub struct MontgomeryKey {
    pub(super) managed: ManagedObjectRef,
    pub(super) spec: MontgomeryKeySpec,
    pub(super) protection: BaseProtection,

    pub(super) mechanism_report: crate::MechanismObservationReport,
}
impl MontgomeryKey {
    /// Administrative alias; mutations revoke cryptographic aliases.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
    /// Exact domain supplied at admission.
    pub fn domain(&self) -> MontgomeryDomain {
        self.spec.domain
    }
    /// Admission-time native observations, without rereading the module.
    pub fn protection(&self) -> BaseProtection {
        self.protection
    }

    /// Explicit allowed-mechanism observation and evaluation.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.mechanism_report
    }
}
/// Two references produced by the same native Montgomery generation call.
/// Association is generation provenance, not an additional private-key proof.
pub struct MontgomeryKeyPair {
    /// Opaque native private key.
    pub private: MontgomeryKey,
    /// Administrative public reference.
    pub public: ManagedObjectRef,
    /// Public coordinate and its exact parameter representation.
    pub public_key: MontgomeryPublicKey,
}
