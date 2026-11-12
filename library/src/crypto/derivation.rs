// SPDX-License-Identifier: Apache-2.0
//! Native derivation: current protection, native history and propagation stay distinct.
use crate::{Error, ManagedObjectRef, Observation, Result, SymmetricKey};
use fe11_sys::*;
mod base;
pub(crate) mod history;
mod keys;
pub(crate) use base::{
    DerivationBaseOwnerStorage, DerivationBasePlan, DerivationBaseRequest, DerivationBaseResult,
    PreparedDerivationBase,
};
mod montgomery;
mod owned;
pub use history::{DerivationObservationPlan, HistoryObservationPlan};
pub use montgomery::{
    MontgomeryDomain, MontgomeryKey, MontgomeryKeyPair, MontgomeryKeySpec, MontgomeryPublicKey,
};
pub(crate) use owned::{
    AgreementPairOwnerStorage, AgreementPairPlan, AgreementPairResult, AgreementPairStorage,
    AgreementRequest, PreparedAgreementPair,
};
mod introduced;
mod introduced_operations;
pub(crate) mod kem_output;
mod observation;
mod operations;
pub(crate) mod output_observation;
pub(crate) mod resident;
pub(crate) use introduced::PreparedAgreementRestore;
pub use introduced::{
    AgreementIntroductionSpec, IntroducedAgreementKey, TransportAgreementKeyPair,
};
pub use introduced_operations::{IntroducedDerivationProvenance, IntroducedDerivedSymmetricKey};

/// Named cofactor-one domains represented by the agreement API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgreementCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// RFC5639 brainpoolP256r1.
    BrainpoolP256,
    /// RFC5639 brainpoolP384r1.
    BrainpoolP384,
}
impl AgreementCurve {
    /// Native derivation mechanism number; not a capability or permission claim.
    pub fn derivation_mechanism_number(self) -> u64 {
        CKM_ECDH1_DERIVE as u64
    }
    fn curve(self) -> super::EcCurve {
        match self {
            Self::P256 => super::EcCurve::P256,
            Self::P384 => super::EcCurve::P384,
            Self::BrainpoolP256 => super::EcCurve::BrainpoolP256,
            Self::BrainpoolP384 => super::EcCurve::BrainpoolP384,
        }
    }
}
/// Explicit native KDF; refusal never changes its identity or input representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcdhKdf {
    /// CKD_NULL: take the requested bytes from the agreed value, as specified by PKCS#11.
    Null,
    /// Exact CK_EC_KDF_TYPE supplied by the caller. Native integer width is checked
    /// before dispatch; the module decides support and parameter compatibility.
    Native(u64),
    /// X9.63 SHA256, counter after Z, starting at one.
    X963Sha256,
    /// SP800 concatenation SHA256, counter before Z, starting at one.
    ConcatSha256,
}
impl EcdhKdf {
    /// Exact PKCS#11 KDF identifier, without asserting native availability.
    pub fn identifier(self) -> u64 {
        match self {
            Self::Null => CKD_NULL as u64,
            Self::Native(value) => value,
            Self::X963Sha256 => CKD_SHA256_KDF as u64,
            Self::ConcatSha256 => CKD_SHA256_KDF_SP800 as u64,
        }
    }
    fn raw(self) -> Result<CK_EC_KDF_TYPE> {
        CK_EC_KDF_TYPE::try_from(self.identifier()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::EcdhKdfIdentifierWidth,
            ))
        })
    }
}
/// Public peer geometry only; caller must authenticate its protocol identity.
pub struct AgreementPeer {
    curve: AgreementCurve,
    point: Vec<u8>,
}
impl AgreementPeer {
    /// Parse canonical SPKI and validate the exact named domain and finite point.
    /// No native operation, format retry or peer authentication is performed.
    pub fn from_spki(curve: AgreementCurve, spki: &[u8]) -> Result<Self> {
        match super::public_key::curve_spki(spki)? {
            super::public_key::CurvePublicKey::Weierstrass(c, p) if c == curve.curve() => {
                Ok(Self {
                    curve,
                    point: p.to_vec(),
                })
            }
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPeerDomain,
            ))),
        }
    }
}
/// Exact identity and domain of a derive-only private key.
pub struct AgreementKeySpec {
    /// Public native usage requests, independent of admission.
    pub public_usages: crate::KeyUsageRequest,
    /// Private native usage requests, independent of admission.
    pub private_usages: crate::KeyUsageRequest,
    /// Native public-object visibility.
    pub public_visibility: crate::ObjectVisibility,
    /// Native private-object visibility.
    pub private_visibility: crate::ObjectVisibility,
    /// Independent observations for the public object, when produced.
    pub public_admission: crate::ObjectAdmission,
    /// Independent observations for the private object, when produced.
    pub private_admission: crate::ObjectAdmission,
    /// Explicit observation of the native allowed-mechanism attribute.
    pub mechanisms: crate::MechanismObservationPlan,
    /// Named domain, never selected by the provider name.
    pub curve: AgreementCurve,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Token object if true, otherwise creator-session object.
    pub persistent: bool,
}
/// Exact current native protection values, separately observed from history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentKeyProtection {
    /// CKA_SENSITIVE.
    pub sensitive: bool,
    /// CKA_EXTRACTABLE.
    pub extractable: bool,
}
/// Current native observations, distinct from a requested CurrentKeyProtection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedCurrentKeyProtection {
    /// Actual SENSITIVE or its observed absence/encoding issue.
    pub sensitive: Observation<bool>,
    /// Actual EXTRACTABLE or its observed absence/encoding issue.
    pub extractable: Observation<bool>,
}
/// Native historical observations, never expected values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalAttributes {
    /// CKA_ALWAYS_SENSITIVE, including absence or invalid encoding.
    pub always_sensitive: Observation<bool>,
    /// CKA_NEVER_EXTRACTABLE, including absence or invalid encoding.
    pub never_extractable: Observation<bool>,
}
/// Exact generation-mechanism observation; unsupported is not a sentinel value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationObservation {
    /// The native CK_ULONG value is CK_UNAVAILABLE_INFORMATION.
    Unavailable,
    /// A precise native ATTRIBUTE_TYPE_INVALID response, not conformity evidence.
    Unsupported,
    /// Exact observed mechanism value.
    Mechanism(u64),
}
/// Provenance observed at admission, without a claim about physical enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseProtection {
    /// Exact caller-selected read plan that produced this snapshot.
    pub observation_plan: HistoryObservationPlan,
    /// Actual current protection observations.
    pub current: ObservedCurrentKeyProtection,
    /// Actual historical observations.
    pub historical: HistoricalAttributes,
    /// Actual CKA_LOCAL; never inferred from the operation invoked.
    pub local: Observation<bool>,
    /// Actual generator or its absence; no sentinel mechanism is fabricated.
    pub generation: Observation<u64>,
}
/// Native observations plus known in-context contradictions for an existing key.
/// No comparison with an unobserved historical parent or physical attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHistory {
    protection: BaseProtection,
}
impl KeyHistory {
    /// Exact native declarations read by the explicit session query.
    pub fn protection(&self) -> BaseProtection {
        self.protection
    }
}
/// Exact derivation path, kept with the result rather than inferred from success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationPath {
    /// Native ECDH1 and this exact KDF.
    Ecdh(EcdhKdf),
    /// SHA256 HKDF extraction and expansion.
    HkdfExtractExpand,
    /// SHA256 extraction only, producing a derive-only PRK object.
    HkdfExtract,
    /// SHA256 expansion only; caller owns the PRK input provenance.
    HkdfExpand,
    /// Native HKDF extraction and expansion with this exact base hash identifier.
    HkdfExtractExpandWithHash(u64),
    /// Native extraction only with this exact base hash identifier.
    HkdfExtractWithHash(u64),
    /// Native expansion only with this exact base hash identifier.
    HkdfExpandWithHash(u64),
}
impl DerivationPath {
    /// Base hash actually selected for HKDF; ECDH uses its own KDF identifier.
    pub fn hkdf_hash(self) -> Option<u64> {
        match self {
            Self::Ecdh(_) => None,
            Self::HkdfExtractExpand | Self::HkdfExtract | Self::HkdfExpand => {
                Some(CKM_SHA256 as u64)
            }
            Self::HkdfExtractExpandWithHash(hash)
            | Self::HkdfExtractWithHash(hash)
            | Self::HkdfExpandWithHash(hash) => Some(hash),
        }
    }
    fn hkdf_parameters(self) -> Result<(CK_MECHANISM_TYPE, CK_BBOOL, CK_BBOOL)> {
        let (hash, extract, expand) = match self {
            Self::HkdfExtractExpand => (CKM_SHA256 as u64, CK_TRUE, CK_TRUE),
            Self::HkdfExtract => (CKM_SHA256 as u64, CK_TRUE, CK_FALSE),
            Self::HkdfExpand => (CKM_SHA256 as u64, CK_FALSE, CK_TRUE),
            Self::HkdfExtractExpandWithHash(hash) => (hash, CK_TRUE, CK_TRUE),
            Self::HkdfExtractWithHash(hash) => (hash, CK_TRUE, CK_FALSE),
            Self::HkdfExpandWithHash(hash) => (hash, CK_FALSE, CK_TRUE),
            Self::Ecdh(_) => {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::HkdfDerivationPathRequired,
                )))
            }
        };
        let hash = CK_MECHANISM_TYPE::try_from(hash).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::HkdfHashIdentifierWidth,
            ))
        })?;
        Ok((hash, extract, expand))
    }
}
/// Immutable observations and comparison for one successful native derivation.
/// Parent observations are native declarations at this call, not an attestation
/// of unobserved earlier derivations. Known local deviations are preserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivationProvenance {
    path: DerivationPath,
    parent: BaseProtection,
    child: BaseProtection,
}
impl DerivationProvenance {
    fn new(path: DerivationPath, parent: BaseProtection, child: BaseProtection) -> Self {
        Self {
            path,
            parent,
            child,
        }
    }
    /// Exact mechanism and KDF/mode dispatched once.
    pub fn path(&self) -> DerivationPath {
        self.path
    }
    /// Parent's actual declarations reread under object/session guards.
    pub fn parent(&self) -> BaseProtection {
        self.parent
    }
    /// Child's actual values, including historical contradictions.
    pub fn child(&self) -> BaseProtection {
        self.child
    }
}
/// Opaque derive-only private key; protection is observed, not unconditional.
pub struct AgreementKey {
    managed: ManagedObjectRef,
    spec: AgreementKeySpec,
    protection: BaseProtection,

    mechanism_report: crate::MechanismObservationReport,
}
impl AgreementKey {
    /// Admission-time mechanism observation and explicitly selected evaluation.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.mechanism_report
    }

    /// Administrative reference; mutation revokes cryptographic aliases.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
    /// Observed declarations at admission, without rereading the module.
    pub fn protection(&self) -> BaseProtection {
        self.protection
    }
}
/// Native generation result; public point came from the same GenerateKeyPair call.
pub struct AgreementKeyPair {
    /// Opaque derive-only private key.
    pub private: AgreementKey,
    /// Administrative public reference.
    pub public: ManagedObjectRef,
    /// Canonical public SPKI; no additional signature is required.
    pub public_der: Vec<u8>,
}
/// Native HKDF base representation; there is no type fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HkdfKeyType {
    /// CKK_GENERIC_SECRET, generic secret key generator.
    Generic,
    /// CKK_HKDF, HKDF key generator.
    Dedicated,
}
impl HkdfKeyType {
    /// Native derivation mechanism number; not a capability or permission claim.
    pub fn derivation_mechanism_number(self) -> u64 {
        CKM_HKDF_DERIVE as u64
    }
    fn raw(self) -> CK_KEY_TYPE {
        match self {
            Self::Generic => CKK_GENERIC_SECRET,
            Self::Dedicated => CKK_HKDF,
        }
    }
    fn generator(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Generic => CKM_GENERIC_SECRET_KEY_GEN,
            Self::Dedicated => CKM_HKDF_KEY_GEN,
        }
    }
}
/// Explicit HKDF base or intermediate native key specification.
pub struct HkdfKeySpec {
    /// Native usage requests, independent of admission.
    pub usages: crate::KeyUsageRequest,
    /// Native CKA_PRIVATE request.
    pub visibility: crate::ObjectVisibility,
    /// Native key length in bytes, selected for creation and length admission.
    pub length: usize,
    /// Explicit observations for the resulting object.
    pub admission: crate::ObjectAdmission,
    /// Explicit observation of the native allowed-mechanism attribute.
    pub mechanisms: crate::MechanismObservationPlan,
    /// Explicit native type.
    pub kind: HkdfKeyType,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Token versus creator-session object.
    pub persistent: bool,
}
/// Native opaque HKDF base; callers supplying PRKs own their protocol semantics.
pub struct HkdfKey {
    managed: ManagedObjectRef,
    spec: HkdfKeySpec,
    protection: BaseProtection,

    mechanism_report: crate::MechanismObservationReport,
}
impl HkdfKey {
    /// Admission-time mechanism observation and explicitly selected evaluation.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.mechanism_report
    }

    /// Administrative reference, without a handle or secret-byte conversion.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
    /// Exact observed declarations at admission.
    pub fn protection(&self) -> BaseProtection {
        self.protection
    }
}
/// Salt supplied as public data, a native key reference, or the normative NULL choice.
/// Empty explicit data remains distinct from NULL.
pub enum HkdfSalt<'a> {
    /// CKF_HKDF_SALT_NULL.
    Null,
    /// CKF_HKDF_SALT_DATA; public bytes charged to the caller-selected memory budget.
    Data(&'a [u8]),
    /// CKF_HKDF_SALT_KEY. The reference must belong to this session and remain valid.
    /// The module uses its native key value; Fe11 does not read or export that value.
    Key(&'a ManagedObjectRef),
}
/// Symmetric result and its immutable observation; no derived bytes are exported.
pub struct DerivedSymmetricKey {
    key: SymmetricKey,
    provenance: DerivationProvenance,
}
impl DerivedSymmetricKey {
    /// Consume through the symmetric-operation API.
    pub fn key(&self) -> &SymmetricKey {
        &self.key
    }
    /// Separate current protection, history and observed propagation.
    pub fn provenance(&self) -> &DerivationProvenance {
        &self.provenance
    }
}
/// Extraction result exposing the HKDF expansion facade and its native owner.
/// The module enforces the permissions of that owner on other explicit operations.
pub struct DerivedHkdfKey {
    key: HkdfKey,
    provenance: DerivationProvenance,
}
impl DerivedHkdfKey {
    /// Borrow the PRK facade for explicit expansion; native permissions remain authoritative.
    pub fn key(&self) -> &HkdfKey {
        &self.key
    }
    /// Exact provenance of the extraction operation.
    pub fn provenance(&self) -> &DerivationProvenance {
        &self.provenance
    }
}
fn identity(id: &[u8], label: &str) -> crate::Result<()> {
    crate::bounds::metadata_lengths(id, label.as_bytes())
}
