// SPDX-License-Identifier: Apache-2.0
//! Generation, explicit pair proof and controlled message signing.
use super::{
    ecdsa, public_key::curve_spki, signature_encoding, EcCurve, HashAlgorithm, HashExecution,
    InputLimits, VerificationKey, VerificationProfile,
};
use crate::{
    attributes::{self, Template},
    bounds, Error, ManagedClass, ManagedObjectRef, Result, SecretBytes, Session,
};
use der::asn1::ObjectIdentifier;
use fe11_sys::*;
mod introduced;
mod owned;
mod public_encoding;
pub(crate) use introduced::PreparedSigningRestore;
pub use introduced::{IntroducedSigningKey, SigningIntroductionSpec, TransportSigningKeyPair};
pub(crate) use owned::{
    ClassicalPairOwnerStorage, ClassicalPairPlan, ClassicalPairStorage, PreparedClassicalPair,
};
use sha2::{Digest, Sha256};

/// Algorithm for native generation, independent of signing permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassicalKeyAlgorithm {
    /// Named ECDSA curve from the closed catalogue.
    Ecdsa(EcCurve),
    /// Requested native RSA modulus size; supported sizes are decided by the module.
    Rsa {
        /// Exact native modulus-size request.
        bits: usize,
    },
    /// Pure Ed25519; no external hash or context.
    Ed25519,
    /// Pure Ed448; empty context, no prehash.
    Ed448,
}
/// Typed signature parameter selectors for an optional caller membership comparison.
/// These variants do not constitute or attest a standards compliance profile.
#[derive(Clone, Copy, Debug, Eq)]
pub enum SignatureProfile {
    /// ECDSA with this exact modern hash.
    Ecdsa(HashAlgorithm),
    /// PKCS1v1.5 with the exact modern hash.
    RsaPkcs1(HashAlgorithm),
    /// PSS with explicit hash/MGF/salt.
    RsaPss(super::RsaPssParameters),
    /// Pure Ed25519 signing permission.
    Ed25519,
    /// Pure Ed448 signing permission.
    Ed448,
    /// Exact EdDSA instance and binary context; equivalent pure aliases compare equally.
    EdDsa(super::EdDsaParameters),
}
impl SignatureProfile {
    fn canonical(self) -> Self {
        match self {
            Self::EdDsa(p) if p.pure_ed25519() => Self::Ed25519,
            Self::EdDsa(p) if p.pure_ed448() => Self::Ed448,
            _ => self,
        }
    }
}
impl PartialEq for SignatureProfile {
    fn eq(&self, other: &Self) -> bool {
        match (self.canonical(), other.canonical()) {
            (Self::Ecdsa(a), Self::Ecdsa(b)) | (Self::RsaPkcs1(a), Self::RsaPkcs1(b)) => a == b,
            (Self::RsaPss(a), Self::RsaPss(b)) => a == b,
            (Self::Ed25519, Self::Ed25519) | (Self::Ed448, Self::Ed448) => true,
            (Self::EdDsa(a), Self::EdDsa(b)) => a == b,
            _ => false,
        }
    }
}
/// Signing profiles available to the RSA-only prepared-digest entry.
/// No ECDSA or Edwards variant exists in this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaSignatureProfile {
    /// PKCS1v1.5; the library constructs DigestInfo for this exact modern hash.
    Pkcs1(HashAlgorithm),
    /// Explicit PSS parameters, validated before any native effect.
    Pss(super::RsaPssParameters),
}
/// Mandatory per-request signing parameters; no module default or fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningRequest {
    /// Original message hashed under library control using the explicit route.
    Ecdsa {
        /// Exact modern hash.
        hash: HashAlgorithm,
        /// Explicit software/native hashing route.
        execution: HashExecution,
    },
    /// PKCS1v1.5 over a message, with library-controlled hashing.
    RsaPkcs1 {
        /// Exact modern hash.
        hash: HashAlgorithm,
        /// Mandatory hashing route.
        execution: HashExecution,
    },
    /// PSS over a message with explicit parameters and hashing route.
    RsaPss {
        /// Exact hash, MGF1 hash and salt length.
        parameters: super::RsaPssParameters,
        /// Mandatory hashing route.
        execution: HashExecution,
    },
    /// Pure Ed25519 over the original message, with no hash choice.
    Ed25519,
    /// Pure Ed448 over the original message, with empty context.
    Ed448,
    /// Exact EdDSA instance/context over the original message; ph is performed by the module.
    EdDsa(super::EdDsaParameters),
}
impl SigningRequest {
    pub(crate) fn profile(self) -> SignatureProfile {
        match self {
            Self::Ecdsa { hash, .. } => SignatureProfile::Ecdsa(hash),
            Self::RsaPkcs1 { hash, .. } => SignatureProfile::RsaPkcs1(hash),
            Self::RsaPss { parameters, .. } => SignatureProfile::RsaPss(parameters),
            Self::Ed25519 => SignatureProfile::Ed25519,
            Self::Ed448 => SignatureProfile::Ed448,
            Self::EdDsa(p) => SignatureProfile::EdDsa(p).canonical(),
        }
    }
    fn hash_request(self) -> Option<(HashAlgorithm, HashExecution)> {
        match self {
            Self::Ecdsa { hash, execution } | Self::RsaPkcs1 { hash, execution } => {
                Some((hash, execution))
            }
            Self::RsaPss {
                parameters,
                execution,
            } => Some((parameters.hash, execution)),
            _ => None,
        }
    }
    fn mechanism(self) -> Result<CK_MECHANISM_TYPE> {
        Ok(match self {
            Self::Ecdsa {
                hash,
                execution: HashExecution::Pkcs11Combined,
            } => ecdsa::combined(hash),
            Self::Ecdsa { .. } => CKM_ECDSA,
            Self::RsaPkcs1 { hash, execution } => {
                let combined = super::rsa::combined(hash)?;
                if execution == HashExecution::Pkcs11Combined {
                    combined
                } else {
                    CKM_RSA_PKCS
                }
            }
            Self::RsaPss {
                parameters,
                execution,
            } => parameters.mechanism(execution)?,
            _ => CKM_EDDSA,
        })
    }
    pub(super) fn signature_parameters(&self) -> Result<super::SignatureParameters<'_>> {
        use super::SignatureParameters;
        Ok(match self {
            Self::Ed25519 => SignatureParameters::None,
            Self::Ed448 => SignatureParameters::Edwards {
                prehash: false,
                context: &[],
            },
            Self::EdDsa(p) => p.native(),
            _ => match self.pss()? {
                Some(p) => SignatureParameters::pss(p),
                None => SignatureParameters::None,
            },
        })
    }

    fn pss(self) -> Result<Option<CK_RSA_PKCS_PSS_PARAMS>> {
        match self {
            Self::RsaPss { parameters, .. } => Ok(Some(parameters.checked()?)),
            _ => Ok(None),
        }
    }
    fn encode_digest_into(
        self,
        digest: &super::PreparedDigest,
        target: &mut SecretBytes,
    ) -> Result<()> {
        if matches!(self, Self::RsaPkcs1 { .. }) {
            super::rsa::digest_info_into(digest, target.as_mut_slice())
        } else {
            if target.len() != digest.as_bytes().len() {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::PreparedDigestEncodingLength,
                    ),
                ));
            }
            target.as_mut_slice().copy_from_slice(digest.as_bytes());
            Ok(())
        }
    }
}
/// Exact native key generation specification, without private input material.
pub struct ClassicalKeySpec {
    /// Native RSA generation exponent bytes, or omission for the module to decide.
    /// Inactive outside RSA generation; imported/located keys use their actual exponent.
    pub rsa_public_exponent: Option<Vec<u8>>,
    /// Exact native usage requests for the public object.
    pub public_usages: crate::KeyUsageRequest,
    /// Exact native usage requests for the private object.
    pub private_usages: crate::KeyUsageRequest,
    /// Exact public-object CKA_PRIVATE request.
    pub public_visibility: crate::ObjectVisibility,
    /// Exact private-object CKA_PRIVATE request.
    pub private_visibility: crate::ObjectVisibility,
    /// Native SENSITIVE/EXTRACTABLE request, not an observation or comparison.
    pub private_protection: crate::CurrentKeyProtection,
    /// Independent observations for the public object, when produced.
    pub public_admission: crate::ObjectAdmission,
    /// Independent observations for the private object, when produced.
    pub private_admission: crate::ObjectAdmission,
    /// Explicit private-key mechanism observation and admission.
    pub mechanisms: crate::MechanismObservationPlan,
    /// Closed algorithm/curve choice.
    pub algorithm: ClassicalKeyAlgorithm,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Persistent token objects or session objects.
    pub persistent: bool,
    /// Descriptive signing profiles; an empty list is allowed. Signing selects
    /// its profile per call, so this metadata is not an authorization list.
    pub profiles: Vec<SignatureProfile>,
}
/// Opaque managed private reference with public metadata and an explicit witness report.
pub struct SigningKey {
    edwards_encoding: Option<crate::EdwardsEncodingReport>,

    managed: ManagedObjectRef,
    algorithm: ClassicalKeyAlgorithm,
    fingerprint: [u8; 32],
    // Retain the prepared allocation through publication and reference lifetime.
    // Signing selects its profile per call; this metadata is not an allowlist.
    _profiles: Vec<SignatureProfile>,
    mechanism_report: crate::MechanismObservationReport,
    // Rust drops fields in order: release the credit after the retained profiles.
    _profiles_credit: crate::symmetric::memory::Credit,
}
struct SigningKeyView<'a> {
    managed: &'a ManagedObjectRef,
    algorithm: ClassicalKeyAlgorithm,
}
impl SigningKey {
    /// Actual private-object Edwards parameter encoding; no private point is read.
    pub fn edwards_encoding(&self) -> Option<crate::EdwardsEncodingReport> {
        self.edwards_encoding
    }

    /// Actual native mechanism observation and its explicit read selection.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.mechanism_report
    }
    fn view(&self) -> SigningKeyView<'_> {
        SigningKeyView {
            managed: &self.managed,
            algorithm: self.algorithm,
        }
    }
    /// Fingerprint of the retained public SPKI; it does not attest private-key correspondence.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    /// Administrative view; mutations revoke this signing alias too.
    pub fn management_reference(&self) -> &ManagedObjectRef {
        &self.managed
    }
    pub(crate) fn message_pss_bits(&self, _parameters: super::RsaPssParameters) -> Result<usize> {
        let ClassicalKeyAlgorithm::Rsa { bits } = self.algorithm else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::MessageRsaSigningKeyRequired,
                ),
            ));
        };

        Ok(bits)
    }
}
/// Native pair with the requested object observations.
/// No proof of private/public correspondence is produced.
pub struct ClassicalKeyPair {
    /// Public verification reference; cannot sign.
    pub public: VerificationKey,
    /// Private signing reference; no private bytes or handle export.
    pub private: SigningKey,
    /// Canonical public SPKI for an independent verifier.
    pub public_der: Vec<u8>,
}
/// Native signature and the exact declared profile/executed hashing route.
pub struct ClassicalSignature {
    bytes: SecretBytes,
    algorithm: ClassicalKeyAlgorithm,
    profile: SignatureProfile,
    provenance: SignatureHashProvenance,
}
/// Actual signature input processing; a prepared digest is never reported as
/// a hash executed by this library or by the provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureHashProvenance {
    /// The library executed the requested hash route over the original message.
    Executed(HashExecution),
    /// RSA-only digest supplied by the consumer; its origin is not attested.
    CallerPrepared,
    /// Pure Edwards over original message bytes, no separate hash request.
    PureEdwards,
    /// Original message supplied to the native Ed25519ph/Ed448ph instance.
    NativeEdwardsPrehash,
}
impl ClassicalSignature {
    /// Exact native signature: RSA modulus width, ECDSA r||s or RFC8032 bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Canonical DER; no implicit format normalization or low-S transformation.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        match self.algorithm {
            ClassicalKeyAlgorithm::Ecdsa(curve) => {
                signature_encoding::to_der(curve, self.bytes.as_slice())
            }
            _ => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::SignatureHasNoDerConversion,
                ),
            )),
        }
    }
    /// Exact profile actually used.
    pub fn profile(&self) -> SignatureProfile {
        self.profile
    }
    /// Explicit hashing route actually executed, with no retry or fallback.
    /// Pure Edwards and caller-prepared RSA return None; hash_provenance
    /// distinguishes them without claiming any hash was executed here.
    pub fn hash_execution(&self) -> Option<HashExecution> {
        match self.provenance {
            SignatureHashProvenance::Executed(e) => Some(e),
            _ => None,
        }
    }
    /// Executed route, caller-prepared digest or pure Edwards, explicitly.
    pub fn hash_provenance(&self) -> SignatureHashProvenance {
        self.provenance
    }
}

impl ClassicalKeyAlgorithm {
    /// Native signature representation width, independent of cryptographic
    /// policy. The module remains responsible for key/algorithm viability.
    fn signature_width(self) -> usize {
        match self {
            Self::Rsa { bits } => bits / 8 + usize::from(bits % 8 != 0),
            Self::Ecdsa(curve) => 2 * curve.domain().width,
            Self::Ed25519 => 64,
            Self::Ed448 => 114,
        }
    }
    fn key_type(self) -> CK_KEY_TYPE {
        match self {
            Self::Rsa { .. } => CKK_RSA,
            Self::Ecdsa(_) => CKK_EC,
            _ => CKK_EC_EDWARDS,
        }
    }
    fn params(self, encoding: crate::EdwardsParameterEncoding) -> &'static [u8] {
        match self {
            Self::Rsa { .. } => &[],
            Self::Ecdsa(c) => c.domain().oid_der,
            Self::Ed25519 => encoding.bytes(super::EdwardsCurve::Ed25519),
            Self::Ed448 => encoding.bytes(super::EdwardsCurve::Ed448),
        }
    }
    fn edwards_curve(self) -> Option<super::EdwardsCurve> {
        match self {
            Self::Ed25519 => Some(super::EdwardsCurve::Ed25519),
            Self::Ed448 => Some(super::EdwardsCurve::Ed448),
            Self::Rsa { .. } | Self::Ecdsa(_) => None,
        }
    }
    fn generation(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Rsa { .. } => CKM_RSA_PKCS_KEY_PAIR_GEN,
            Self::Ecdsa(_) => CKM_EC_KEY_PAIR_GEN,
            _ => CKM_EC_EDWARDS_KEY_PAIR_GEN,
        }
    }
    fn curve(self) -> Option<EcCurve> {
        match self {
            Self::Ecdsa(c) => Some(c),
            _ => None,
        }
    }
    // This typed convenience returns a family-specific signature representation:
    // RSA uses its declared width, ECDSA converts the curve-sized native pair,
    // and Edwards selects its fixed output width. Check that representation,
    // not membership in an application-approved profile list. Native signature
    // routes take NativeObjectRef and an independent output plan instead.
    fn validate_profiles(self, profiles: &[SignatureProfile]) -> Result<()> {
        if let Self::Rsa { bits } = self {
            bounds::ck_length(bits)?;
            for profile in profiles {
                match profile {
                    SignatureProfile::RsaPkcs1(h) => {
                        super::rsa::combined(*h)?;
                    }
                    SignatureProfile::RsaPss(p) => {
                        p.checked()?;
                    }
                    _ => {
                        return Err(Error::Rejected(
                            crate::RejectionReason::ClassicalSignatures(
                                crate::ClassicalSignaturesRejection::RsaSigningProfileFamily,
                            ),
                        ))
                    }
                }
            }
            return Ok(());
        }
        let valid = match self {
            Self::Rsa { .. } => unreachable!(),
            Self::Ecdsa(_) => profiles
                .iter()
                .all(|p| matches!(p, SignatureProfile::Ecdsa(_))),
            Self::Ed25519 => profiles.iter().all(|p| match p {
                SignatureProfile::Ed25519 => true,
                SignatureProfile::EdDsa(p) => p.curve() == super::EdwardsCurve::Ed25519,
                _ => false,
            }),
            Self::Ed448 => profiles.iter().all(|p| match p {
                SignatureProfile::Ed448 => true,
                SignatureProfile::EdDsa(p) => p.curve() == super::EdwardsCurve::Ed448,
                _ => false,
            }),
        };
        if !valid {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::SigningProfileFamily,
                ),
            ));
        }
        Ok(())
    }
}
/// Determine the family from a canonical public representation, without a
/// local mathematical admission policy.
fn classical_public_algorithm(expected_spki: &[u8]) -> Result<ClassicalKeyAlgorithm> {
    if super::verification::public_algorithm_oid(expected_spki)?
        == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
    {
        let key = super::integer_key::rsa_der(expected_spki)?;
        return Ok(ClassicalKeyAlgorithm::Rsa { bits: key.bits });
    }
    Ok(match curve_spki(expected_spki)? {
        super::public_key::CurvePublicKey::Weierstrass(curve, _) => {
            ClassicalKeyAlgorithm::Ecdsa(curve)
        }
        super::public_key::CurvePublicKey::Edwards(super::public_key::EdwardsCurve::Ed25519, _) => {
            ClassicalKeyAlgorithm::Ed25519
        }
        super::public_key::CurvePublicKey::Edwards(super::public_key::EdwardsCurve::Ed448, _) => {
            ClassicalKeyAlgorithm::Ed448
        }
    })
}

fn generation_templates_as<T: crate::attributes::TemplateSink>(
    spec: &ClassicalKeySpec,
    semantics: crate::EdwardsOptions,
) -> Result<(T, T)> {
    let algorithm = spec.algorithm;
    // CK_ULONG is narrower than usize on 64-bit Windows. This checks only
    // representation, before template planning or native dispatch; the module
    // decides which representable RSA sizes it supports.
    let modulus_bits = match algorithm {
        ClassicalKeyAlgorithm::Rsa { bits } => Some(bounds::ck_length(bits)?),
        _ => None,
    };
    let template = |class| {
        let mut t = T::empty();
        t.integer(CKA_CLASS, class);
        t.integer(CKA_KEY_TYPE, algorithm.key_type());
        t.bytes(CKA_ID, &spec.id);
        t.bytes(CKA_LABEL, spec.label.as_bytes());
        t.boolean(CKA_TOKEN, spec.persistent);
        if class == CKO_PUBLIC_KEY {
            t.boolean(CKA_PRIVATE, spec.public_visibility.is_private());
            spec.public_usages.apply(&mut t);
            match modulus_bits {
                Some(bits) => {
                    t.integer(CKA_MODULUS_BITS, bits);
                    if let Some(exponent) = &spec.rsa_public_exponent {
                        t.bytes(CKA_PUBLIC_EXPONENT, exponent);
                    }
                }
                None => t.bytes(
                    CKA_EC_PARAMS,
                    algorithm.params(semantics.parameter_encoding),
                ),
            };
        } else {
            t.boolean(CKA_PRIVATE, spec.private_visibility.is_private());
            spec.private_usages.apply(&mut t);
            t.boolean(CKA_SENSITIVE, spec.private_protection.sensitive);
            t.boolean(CKA_EXTRACTABLE, spec.private_protection.extractable);
        }
        t
    };
    Ok((template(CKO_PUBLIC_KEY), template(CKO_PRIVATE_KEY)))
}
// Both classes use the same attribute kinds; validate_identity_fields checks
// the returned class separately. Retain the shared recipe signature.
fn identity_fields(
    _class: CK_OBJECT_CLASS,
    algorithm: ClassicalKeyAlgorithm,
) -> ([CK_ATTRIBUTE_TYPE; 20], usize) {
    // Structural identity is read separately from caller-selected boolean controls.
    let mut fields = [0; 20];
    let mut count = 0;
    for field in [CKA_CLASS, CKA_KEY_TYPE] {
        fields[count] = field;
        count += 1;
    }
    if matches!(algorithm, ClassicalKeyAlgorithm::Rsa { .. }) {
        fields[count] = CKA_PUBLIC_EXPONENT;
        count += 1;
    } else {
        fields[count] = CKA_EC_PARAMS;
        count += 1;
    }
    (fields, count)
}
fn validate_identity_fields(
    values: &attributes::RequiredAttributes,
    class: CK_OBJECT_CLASS,
    algorithm: ClassicalKeyAlgorithm,
    semantics: crate::EdwardsOptions,
) -> Result<()> {
    values.integer(CKA_CLASS, class)?;
    values.integer(CKA_KEY_TYPE, algorithm.key_type())?;
    if !matches!(algorithm, ClassicalKeyAlgorithm::Rsa { .. })
        && values.bytes(CKA_EC_PARAMS)? != algorithm.params(semantics.parameter_encoding)
    {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::GeneratedCurveParameters,
            ),
        ));
    }
    Ok(())
}

mod signatures;
