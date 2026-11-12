// SPDX-License-Identifier: Apache-2.0
//! Explicit historical verification only, never a signing authorization.
use super::{
    HashAlgorithm, HashExecution, HashProvenance, InputLimits, NativeHash, VerificationKey,
};
use crate::{bounds, module::State, Error, Result, SecretBytes, Session, Verification};
use fe11_sys::*;

/// Historical digest identifiers, deliberately separate from HashAlgorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalHash {
    /// SHA1 for explicitly historical verification only.
    Sha1,
    /// MD5 remains non-approved, including when a signature verifies.
    Md5,
}

impl HistoricalHash {
    pub(super) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Sha1 => CKM_SHA_1,
            Self::Md5 => CKM_MD5,
        }
    }
    /// Exact digest size; no truncation, extension or padding is permitted.
    pub fn output_length(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Md5 => 16,
        }
    }
}
/// Consumer-supplied historical digest; never accepted by a signing entry.
pub struct HistoricalDigest {
    algorithm: HistoricalHash,
    bytes: SecretBytes,
}
impl HistoricalDigest {
    /// Copy exactly the declared digest width into an owned wiping allocation.
    pub fn from_bytes(algorithm: HistoricalHash, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != algorithm.output_length() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::HistoricalDigestWidth,
                ),
            ));
        }
        let mut owned = SecretBytes::new(bytes.len())?;
        owned.as_mut_slice().copy_from_slice(bytes);
        Ok(Self {
            algorithm,
            bytes: owned,
        })
    }
    /// Declared hash, without an attestation of how the consumer calculated it.
    pub fn algorithm(&self) -> HistoricalHash {
        self.algorithm
    }
    /// Borrow the supplied bytes. Any consumer copy remains its responsibility.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}
/// Historical SHA1/MGF1-SHA1 adapter with explicit salt length and fixed trailer0xbc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoricalPssParameters {
    /// Must be SHA1; no implicit hash selection.
    pub hash: HistoricalHash,
    /// Explicit MGF1 hash, required to be SHA1.
    pub mgf_hash: HistoricalHash,
    /// Explicit salt length in bytes; no automatic salt.
    pub salt_length: usize,
}
impl HistoricalPssParameters {
    pub(super) fn checked(self) -> Result<CK_RSA_PKCS_PSS_PARAMS> {
        if self.hash != HistoricalHash::Sha1 || self.mgf_hash != HistoricalHash::Sha1 {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::HistoricalPssParameters,
                ),
            ));
        }
        Ok(CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA_1,
            mgf: CKG_MGF1_SHA1,
            sLen: bounds::ck_length(self.salt_length)?,
        })
    }
}

/// Hashes permitted for historical DSA verification; not modern signing inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsaVerificationHash {
    /// Historical SHA1, 160 bits.
    Sha1,
    /// SHA224 used with a historical DSA key.
    Sha224,
    /// SHA256 used with a historical DSA key.
    Sha256,
    /// SHA384 used with a historical DSA key.
    Sha384,
    /// SHA512 used with a historical DSA key.
    Sha512,
}
impl DsaVerificationHash {
    /// Width of the identified digest, passed intact to CKM_DSA. The module
    /// performs DSA's reduction to the subgroup size; Fe11 does not truncate it.
    pub fn output_length(self) -> usize {
        self.native_hash().output_length()
    }

    fn native_hash(self) -> NativeHash {
        match self {
            Self::Sha1 => NativeHash::Historical(HistoricalHash::Sha1),
            Self::Sha224 => NativeHash::Modern(HashAlgorithm::Sha224),
            Self::Sha256 => NativeHash::Modern(HashAlgorithm::Sha256),
            Self::Sha384 => NativeHash::Modern(HashAlgorithm::Sha384),
            Self::Sha512 => NativeHash::Modern(HashAlgorithm::Sha512),
        }
    }

    fn software_hash(self) -> Result<HashAlgorithm> {
        match self {
            Self::Sha1 => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::RustSha1DigestUnavailable,
                ),
            )),
            Self::Sha224 => Ok(HashAlgorithm::Sha224),
            Self::Sha256 => Ok(HashAlgorithm::Sha256),
            Self::Sha384 => Ok(HashAlgorithm::Sha384),
            Self::Sha512 => Ok(HashAlgorithm::Sha512),
        }
    }

    fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Sha1 => CKM_DSA_SHA1,
            Self::Sha224 => CKM_DSA_SHA224,
            Self::Sha256 => CKM_DSA_SHA256,
            Self::Sha384 => CKM_DSA_SHA384,
            Self::Sha512 => CKM_DSA_SHA512,
        }
    }
}
/// Caller-supplied DSA digest with an explicit hash and exact output width.
///
/// Construction checks representation, not provenance or DSA parameters. Native
/// verification consumes these bytes once, without another hash or truncation.
/// This type cannot enter a signing API.
pub struct DsaVerificationDigest {
    algorithm: DsaVerificationHash,
    bytes: SecretBytes,
}

impl DsaVerificationDigest {
    /// Copy the declared digest into wiping storage; never infer its hash.
    pub fn from_bytes(algorithm: DsaVerificationHash, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != algorithm.output_length() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::DsaDigestWidth,
                ),
            ));
        }
        let mut owned = SecretBytes::new(bytes.len())?;
        owned.as_mut_slice().copy_from_slice(bytes);
        Ok(Self {
            algorithm,
            bytes: owned,
        })
    }

    /// Caller-declared hash; this does not attest how the bytes were produced.
    pub fn algorithm(&self) -> DsaVerificationHash {
        self.algorithm
    }

    /// Borrow the intact digest; consumer copies have their own lifetime.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// Closed historical verification profiles, with no conversion to signing profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalProfile {
    /// RSA PKCS1v1.5 with SHA1 or non-approved MD5.
    RsaPkcs1(HistoricalHash),
    /// The explicit historical PSS recipe, without a signing counterpart.
    RsaPss(HistoricalPssParameters),
    /// Historical ECDSA with SHA1; combined or native digest then primitive.
    EcdsaSha1,
    /// Classic DSA is permitted only for historical verification, for any hash.
    Dsa(DsaVerificationHash),
}
impl HistoricalProfile {
    pub(super) fn validate(self) -> Result<()> {
        if let Self::RsaPss(p) = self {
            p.checked()?;
        }
        Ok(())
    }
    fn hash(self) -> Option<HistoricalHash> {
        match self {
            Self::RsaPkcs1(h) => Some(h),
            Self::RsaPss(p) => Some(p.hash),
            Self::EcdsaSha1 => Some(HistoricalHash::Sha1),
            Self::Dsa(_) => None,
        }
    }
    fn native_hash(self) -> NativeHash {
        match self {
            Self::RsaPkcs1(hash) => NativeHash::Historical(hash),
            Self::RsaPss(parameters) => NativeHash::Historical(parameters.hash),
            Self::EcdsaSha1 => NativeHash::Historical(HistoricalHash::Sha1),
            Self::Dsa(hash) => hash.native_hash(),
        }
    }

    fn software_hash(self) -> Result<HashAlgorithm> {
        match self {
            Self::Dsa(hash) => hash.software_hash(),
            // RustSoftware selects the built-in SHA2/SHA3 engine. Neither a
            // configured native software component nor PKCS#11 is a fallback.
            _ => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::HistoricalDigestUnavailableInRustEngine,
                ),
            )),
        }
    }

    fn primitive(self) -> Result<CK_MECHANISM_TYPE> {
        self.validate()?;
        match self {
            Self::RsaPkcs1(_) => Ok(CKM_RSA_PKCS),
            Self::RsaPss(_) => Ok(CKM_RSA_PKCS_PSS),
            Self::EcdsaSha1 => Ok(CKM_ECDSA),
            Self::Dsa(_) => Ok(CKM_DSA),
        }
    }
    fn mechanism(self, execution: HashExecution) -> Result<CK_MECHANISM_TYPE> {
        self.validate()?;
        match (self, execution) {
            (Self::Dsa(h), HashExecution::Pkcs11Combined) => Ok(h.mechanism()),
            (Self::RsaPkcs1(HistoricalHash::Sha1), HashExecution::Pkcs11Combined) => {
                Ok(CKM_SHA1_RSA_PKCS)
            }
            (Self::RsaPkcs1(HistoricalHash::Md5), HashExecution::Pkcs11Combined) => {
                Ok(CKM_MD5_RSA_PKCS)
            }
            (Self::RsaPss(_), HashExecution::Pkcs11Combined) => Ok(CKM_SHA1_RSA_PKCS_PSS),
            (Self::EcdsaSha1, HashExecution::Pkcs11Combined) => Ok(CKM_ECDSA_SHA1),
            (_, HashExecution::Pkcs11DigestThenPrimitive) => self.primitive(),
            (_, HashExecution::RustSoftware) => {
                self.software_hash()?;
                self.primitive()
            }
        }
    }
    fn digest_input_length(self) -> Result<usize> {
        let length = self.native_hash().output_length();
        if let Self::RsaPkcs1(hash) = self {
            super::rsa::encoded_digest_info_length(
                match hash {
                    HistoricalHash::Sha1 => "1.3.14.3.2.26",
                    HistoricalHash::Md5 => "1.2.840.113549.2.5",
                },
                length,
            )
        } else {
            Ok(length)
        }
    }
    fn digest_input_into(self, bytes: &[u8], target: &mut [u8]) -> Result<()> {
        if let Self::RsaPkcs1(hash) = self {
            super::rsa::encode_digest_info_into(
                match hash {
                    HistoricalHash::Sha1 => "1.3.14.3.2.26",
                    HistoricalHash::Md5 => "1.2.840.113549.2.5",
                },
                bytes,
                target,
            )
        } else {
            if target.len() != bytes.len() {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::HistoricalPreparedDigestLength,
                    ),
                ));
            }
            target.copy_from_slice(bytes);
            Ok(())
        }
    }
}
/// Usage restriction, independent of cryptographic validity or signing date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoricalClassification {
    /// MD5 is non-approved even if its cryptographic equation verifies.
    NonApprovedMd5,
    /// Restricted to historical verification; neither date nor trust is proved.
    HistoricalOnly,
}
/// Historical verification evidence. This result never establishes certificate
/// trust, prior signing date, key ownership or an approved operational use.
pub struct HistoricalVerificationResult {
    /// Cryptographic validity; provider failures remain errors.
    pub validity: Verification,
    /// Exact historical profile requested and executed.
    pub profile: HistoricalProfile,
    /// Canonical public identity validated at import/selection.
    pub key_fingerprint: [u8; 32],
    /// Explicit restriction retained on Valid and Invalid alike.
    pub classification: HistoricalClassification,
    /// Executed hashing or a caller-attested digest, without an inferred origin.
    pub hash_provenance: HashProvenance,
    /// Independent RSA exponent classification, absent for DSA/EC.
    pub rsa_exponent_class: Option<super::RsaExponentClass>,
}
impl Session {
    /// Historical public verification over the exact message. The caller chooses
    /// the hash route. RustSoftware supports DSA SHA2 here; SHA1/MD5 are absent
    /// from that engine. Missing capabilities never trigger another route.
    pub fn verify_historical(
        &self,
        key: &VerificationKey,
        profile: HistoricalProfile,
        execution: HashExecution,
        message: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<HistoricalVerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_historical_parts(
            key,
            profile,
            execution,
            &[message],
            false,
            signature,
            limits,
            diagnostics,
        )
    }
    /// Verify finite bounded pieces. A combined route uses VerifyUpdate/Final;
    /// native digest-then-primitive uses DigestUpdate/Final then one Verify.
    /// RustSoftware hashes the pieces before acquiring session guards.
    pub fn verify_historical_multipart(
        &self,
        key: &VerificationKey,
        profile: HistoricalProfile,
        execution: HashExecution,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<HistoricalVerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_historical_parts(
            key,
            profile,
            execution,
            parts,
            true,
            signature,
            limits,
            diagnostics,
        )
    }
    fn verify_historical_parts(
        &self,
        key: &VerificationKey,
        profile: HistoricalProfile,
        execution: HashExecution,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        limits: InputLimits,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<HistoricalVerificationResult> {
        limits.validate(self.inner.crypto_options.limits, parts)?;
        let kind = profile.mechanism(execution)?;
        let (mut prepared_digest, prepared_signature, mut prehash_storage, s) = self
            .prepare_verification_read_access(
                &key.managed,
                (execution == HashExecution::Pkcs11DigestThenPrimitive)
                    .then(|| profile.native_hash()),
                parts,
                multipart,
                if execution == HashExecution::Pkcs11Combined {
                    parts.iter().map(|part| part.len()).max().unwrap_or(0)
                } else {
                    profile.digest_input_length()?
                },
                signature.len(),
                if execution == HashExecution::RustSoftware {
                    Some(profile.software_hash()?)
                } else {
                    None
                },
                (execution != HashExecution::Pkcs11Combined)
                    .then(|| profile.digest_input_length())
                    .transpose()?,
                None,
            )?;
        let object = self.historical_gate(&s, key, profile)?;

        let validity = if execution == HashExecution::Pkcs11Combined {
            self.historical_verify_native(
                &s,
                object,
                profile,
                kind,
                parts,
                multipart,
                signature,
                prepared_signature,
                diagnostics,
            )?
        } else {
            if s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none() {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(crate::ClassicalSignaturesRejection::HistoricalVerificationFunctionsUnavailable),
                ));
            }
            // A raw primitive consumes one complete digest. Do not truncate DSA
            // input to q, hash it twice, or substitute a missing native digest.
            let mut input = prehash_storage
                .encoded
                .take()
                .expect("prepared historical encoding");
            if let Some(digest) = &prehash_storage.software {
                profile.digest_input_into(digest.as_bytes(), input.as_mut_slice())?;
            } else {
                let digest = self.native_digest_guarded(
                    &s,
                    profile.native_hash(),
                    parts,
                    multipart,
                    prepared_digest.take().expect("native prehash prepared"),
                    diagnostics,
                )?;
                profile.digest_input_into(digest.as_slice(), input.as_mut_slice())?;
            }
            self.historical_verify_native(
                &s,
                object,
                profile,
                kind,
                &[input.as_slice()],
                false,
                signature,
                prepared_signature,
                diagnostics,
            )?
        };
        self.public_result(
            &s,
            Ok(Self::historical_result(
                key,
                profile,
                validity,
                HashProvenance::Executed(execution),
            )),
        )
    }
    /// Verify a consumer-supplied historical digest. The declared profile and
    /// usage classification never turn ConsumerAttested into a trust decision.
    pub fn verify_historical_digest(
        &self,
        key: &VerificationKey,
        profile: HistoricalProfile,
        digest: &HistoricalDigest,
        signature: &[u8],
    ) -> Result<HistoricalVerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        profile.validate()?;
        if profile.hash() != Some(digest.algorithm) {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::HistoricalDigestProfile,
                ),
            ));
        }
        self.verify_historical_prepared(key, profile, digest.as_bytes(), signature, diagnostics)
    }

    /// Verify the caller's identified DSA digest with CKM_DSA. Its full output
    /// width is preserved; no hash, padding or mathematical DSA check is added.
    /// The result records ConsumerAttested provenance, never a trust decision.
    pub fn verify_dsa_digest(
        &self,
        key: &VerificationKey,
        digest: &DsaVerificationDigest,
        signature: &[u8],
    ) -> Result<HistoricalVerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_historical_prepared(
            key,
            HistoricalProfile::Dsa(digest.algorithm()),
            digest.as_bytes(),
            signature,
            diagnostics,
        )
    }

    fn verify_historical_prepared(
        &self,
        key: &VerificationKey,
        profile: HistoricalProfile,
        input: &[u8],
        signature: &[u8],
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<HistoricalVerificationResult> {
        let kind = profile.primitive()?;
        let encoded_length = matches!(profile, HistoricalProfile::RsaPkcs1(_))
            .then(|| profile.digest_input_length())
            .transpose()?;
        let (_, prepared_signature, mut prehash_storage, s) = self
            .prepare_verification_read_access(
                &key.managed,
                None,
                &[input],
                false,
                encoded_length.unwrap_or(input.len()),
                signature.len(),
                None,
                encoded_length,
                None,
            )?;
        let input = if let Some(encoded) = prehash_storage.encoded.as_mut() {
            profile.digest_input_into(input, encoded.as_mut_slice())?;
            encoded.as_slice()
        } else {
            input
        };
        let object = self.historical_gate(&s, key, profile)?;
        let validity = self.historical_verify_native(
            &s,
            object,
            profile,
            kind,
            &[input],
            false,
            signature,
            prepared_signature,
            diagnostics,
        )?;
        self.public_result(
            &s,
            Ok(Self::historical_result(
                key,
                profile,
                validity,
                HashProvenance::ConsumerAttested,
            )),
        )
    }
    fn historical_gate(
        &self,
        s: &State,
        key: &VerificationKey,
        profile: HistoricalProfile,
    ) -> Result<CK_OBJECT_HANDLE> {
        let object = self.managed_handle(s, &key.managed)?;

        match profile {
            HistoricalProfile::Dsa(_) => {
                key.dsa.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::NotADsaReference,
                    ),
                ))?;
            }
            HistoricalProfile::EcdsaSha1 => {
                key.curve.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::NotAnEcdsaReference,
                    ),
                ))?;
            }
            _ => {
                key.rsa.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::NotAnRsaReference,
                    ),
                ))?;
            }
        };

        Ok(object)
    }

    fn historical_verify_native(
        &self,
        s: &crate::session::SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
        profile: HistoricalProfile,
        kind: CK_MECHANISM_TYPE,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        prepared_signature: super::native_signature::storage::Storage,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<Verification> {
        let parameters = match profile {
            HistoricalProfile::RsaPss(p) => {
                super::native_signature::SignatureParameters::pss(p.checked()?)
            }
            _ => super::native_signature::SignatureParameters::None,
        };
        self.verify_native_mechanism(
            s,
            object,
            kind,
            parameters,
            parts,
            multipart,
            signature,
            prepared_signature,
            diagnostics,
        )
    }
    fn historical_result(
        key: &VerificationKey,
        profile: HistoricalProfile,
        validity: Verification,
        hash_provenance: HashProvenance,
    ) -> HistoricalVerificationResult {
        HistoricalVerificationResult {
            validity,
            profile,
            key_fingerprint: key.fingerprint,
            classification: if profile == HistoricalProfile::RsaPkcs1(HistoricalHash::Md5) {
                HistoricalClassification::NonApprovedMd5
            } else {
                HistoricalClassification::HistoricalOnly
            },
            hash_provenance,
            rsa_exponent_class: key.rsa_exponent_class(),
        }
    }
}
