// SPDX-License-Identifier: Apache-2.0
//! RSA verification, library-owned DigestInfo and independent key classification.
use super::{
    HashAlgorithm, HashExecution, HashProvenance, InputLimits, PreparedDigest, VerificationKey,
    VerificationProfile, VerificationResult,
};

use crate::{module::State, Error, Result, Session, Verification};
use der::{
    asn1::{AnyRef, ObjectIdentifier, OctetStringRef},
    Encode, Sequence,
};
use fe11_sys::*;
use x509_cert::spki::AlgorithmIdentifierRef;
#[derive(Sequence)]
struct DigestInfo<'a> {
    algorithm: AlgorithmIdentifierRef<'a>,
    digest: OctetStringRef<'a>,
}
/// Explicit PSS parameters. Message hash, MGF1 hash and salt length are independent.
/// The PKCS11 mechanism fixes the RFC8017 trailer to 0xbc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsaPssParameters {
    /// Exact message hash.
    pub hash: HashAlgorithm,
    /// Explicit MGF1 hash, independent of the message hash.
    pub mgf_hash: HashAlgorithm,
    /// Exact salt length in bytes, never automatic.
    pub salt_length: usize,
}

impl RsaPssParameters {
    // Decode only the typed hash catalogue; unknown encodings are not silently
    // mapped to a default. Used when rebuilding an exact message checkpoint.
    pub(crate) fn from_native(parameters: &CK_RSA_PKCS_PSS_PARAMS) -> Result<Self> {
        let hashes = HashAlgorithm::ALL;
        let hash = hashes
            .into_iter()
            .find(|h| h.mechanism() == parameters.hashAlg)
            .ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::PssEncodedHash,
                ),
            ))?;
        let mgf_hash = hashes
            .into_iter()
            .find(|h| {
                Self {
                    hash,
                    mgf_hash: *h,
                    salt_length: 0,
                }
                .checked()
                .is_ok_and(|p| p.mgf == parameters.mgf)
            })
            .ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::PssEncodedMgf,
                ),
            ))?;
        let salt_length = usize::try_from(parameters.sLen).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::PssSaltWidth,
            ))
        })?;
        Ok(Self {
            hash,
            mgf_hash,
            salt_length,
        })
    }
    pub(crate) fn checked(self) -> Result<CK_RSA_PKCS_PSS_PARAMS> {
        let mgf = match self.mgf_hash {
            HashAlgorithm::Sha224 => CKG_MGF1_SHA224,
            HashAlgorithm::Sha256 => CKG_MGF1_SHA256,
            HashAlgorithm::Sha384 => CKG_MGF1_SHA384,
            HashAlgorithm::Sha512 => CKG_MGF1_SHA512,
            HashAlgorithm::Sha3_224 => CKG_MGF1_SHA3_224,
            HashAlgorithm::Sha3_256 => CKG_MGF1_SHA3_256,
            HashAlgorithm::Sha3_384 => CKG_MGF1_SHA3_384,
            HashAlgorithm::Sha3_512 => CKG_MGF1_SHA3_512,
        };
        Ok(CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: self.hash.mechanism(),
            mgf,
            sLen: crate::bounds::ck_length(self.salt_length)?,
        })
    }
    pub(crate) fn mechanism(self, execution: HashExecution) -> Result<CK_MECHANISM_TYPE> {
        self.checked()?;
        Ok(if execution == HashExecution::Pkcs11Combined {
            match self.hash {
                HashAlgorithm::Sha224 => CKM_SHA224_RSA_PKCS_PSS,
                HashAlgorithm::Sha256 => CKM_SHA256_RSA_PKCS_PSS,
                HashAlgorithm::Sha384 => CKM_SHA384_RSA_PKCS_PSS,
                HashAlgorithm::Sha512 => CKM_SHA512_RSA_PKCS_PSS,
                HashAlgorithm::Sha3_224 => CKM_SHA3_224_RSA_PKCS_PSS,
                HashAlgorithm::Sha3_256 => CKM_SHA3_256_RSA_PKCS_PSS,
                HashAlgorithm::Sha3_384 => CKM_SHA3_384_RSA_PKCS_PSS,
                HashAlgorithm::Sha3_512 => CKM_SHA3_512_RSA_PKCS_PSS,
            }
        } else {
            CKM_RSA_PKCS_PSS
        })
    }
}
pub(super) fn combined(hash: HashAlgorithm) -> Result<CK_MECHANISM_TYPE> {
    Ok(match hash {
        HashAlgorithm::Sha224 => CKM_SHA224_RSA_PKCS,
        HashAlgorithm::Sha256 => CKM_SHA256_RSA_PKCS,
        HashAlgorithm::Sha384 => CKM_SHA384_RSA_PKCS,
        HashAlgorithm::Sha512 => CKM_SHA512_RSA_PKCS,
        HashAlgorithm::Sha3_224 => CKM_SHA3_224_RSA_PKCS,
        HashAlgorithm::Sha3_256 => CKM_SHA3_256_RSA_PKCS,
        HashAlgorithm::Sha3_384 => CKM_SHA3_384_RSA_PKCS,
        HashAlgorithm::Sha3_512 => CKM_SHA3_512_RSA_PKCS,
    })
}
pub(super) fn digest_info_into(digest: &PreparedDigest, target: &mut [u8]) -> Result<()> {
    encode_digest_info_into(digest_oid(digest.algorithm), digest.as_bytes(), target)
}
pub(super) fn encode_digest_info_into(oid: &str, bytes: &[u8], target: &mut [u8]) -> Result<()> {
    let info = DigestInfo {
        algorithm: AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap(oid),
            parameters: Some(AnyRef::NULL),
        },
        digest: OctetStringRef::new(bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoInput,
            ))
        })?,
    };
    let length: usize = info
        .encoded_len()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoLength,
            ))
        })?
        .try_into()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoLength,
            ))
        })?;
    if target.len() != length {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoPreparedLength,
            ),
        ));
    }
    info.encode_to_slice(target).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::DigestinfoEncoding,
        ))
    })?;
    Ok(())
}
fn digest_oid(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha224 => "2.16.840.1.101.3.4.2.4",
        HashAlgorithm::Sha256 => "2.16.840.1.101.3.4.2.1",
        HashAlgorithm::Sha384 => "2.16.840.1.101.3.4.2.2",
        HashAlgorithm::Sha512 => "2.16.840.1.101.3.4.2.3",
        HashAlgorithm::Sha3_224 => "2.16.840.1.101.3.4.2.7",
        HashAlgorithm::Sha3_256 => "2.16.840.1.101.3.4.2.8",
        HashAlgorithm::Sha3_384 => "2.16.840.1.101.3.4.2.9",
        HashAlgorithm::Sha3_512 => "2.16.840.1.101.3.4.2.10",
    }
}
/// Use the same DER encoder's length calculation for pre-admission; the fixed
/// scratch is a dummy digest, not message material and never enters native code.
pub(super) fn digest_info_length(algorithm: HashAlgorithm) -> Result<usize> {
    encoded_digest_info_length(digest_oid(algorithm), algorithm.output_length())
}
pub(super) fn encoded_digest_info_length(oid: &str, length: usize) -> Result<usize> {
    let bytes = [0; 64];
    let info = DigestInfo {
        algorithm: AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap(oid),
            parameters: Some(AnyRef::NULL),
        },
        digest: OctetStringRef::new(bytes.get(..length).ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoInputLength,
            ),
        ))?)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoInput,
            ))
        })?,
    };
    info.encoded_len()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoLength,
            ))
        })?
        .try_into()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DigestinfoLengthConversion,
            ))
        })
}

impl Session {
    /// Verify PSS over the original message, with exact parameters and hash route.
    pub fn verify_rsa_pss(
        &self,
        key: &VerificationKey,
        parameters: RsaPssParameters,
        execution: HashExecution,
        message: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_rsa_pss_parts(
            key,
            parameters,
            execution,
            &[message],
            false,
            signature,
            limits,
            diagnostics,
        )
    }
    /// Verify with actual native Update/Final when the requested route uses them.
    pub fn verify_rsa_pss_multipart(
        &self,
        key: &VerificationKey,
        parameters: RsaPssParameters,
        execution: HashExecution,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_rsa_pss_parts(
            key,
            parameters,
            execution,
            parts,
            true,
            signature,
            limits,
            diagnostics,
        )
    }
    /// Verify an explicitly caller-prepared digest. Its provenance remains
    /// ConsumerAttested, independent of validity and exponent classification.
    pub fn verify_rsa_pss_digest(
        &self,
        key: &VerificationKey,
        parameters: RsaPssParameters,
        digest: &PreparedDigest,
        signature: &[u8],
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        parameters.checked()?;
        if digest.algorithm != parameters.hash {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::PssDigestAlgorithm,
                ),
            ));
        }
        let (_, prepared_signature, _, s) = self.prepare_verification_read_access(
            &key.managed,
            None,
            &[digest.as_bytes()],
            false,
            digest.as_bytes().len(),
            signature.len(),
            None,
            None,
            Some(digest),
        )?;
        let object = self.rsa_reference_handle(&s, key)?;
        let validity = self.pss_verify_native(
            &s,
            object,
            parameters,
            CKM_RSA_PKCS_PSS,
            &[digest.as_bytes()],
            false,
            signature,
            prepared_signature,
            diagnostics,
        )?;
        self.public_result(
            &s,
            Ok(Self::pss_result(
                key,
                parameters,
                validity,
                HashProvenance::ConsumerAttested,
            )),
        )
    }
    fn verify_rsa_pss_parts(
        &self,
        key: &VerificationKey,
        parameters: RsaPssParameters,
        execution: HashExecution,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        limits: InputLimits,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<VerificationResult> {
        limits.validate(self.inner.crypto_options.limits, parts)?;
        let kind = parameters.mechanism(execution)?;
        let (mut prepared_digest, prepared_signature, prehash_storage, s) = self
            .prepare_verification_read_access(
                &key.managed,
                (execution == HashExecution::Pkcs11DigestThenPrimitive)
                    .then_some(super::NativeHash::Modern(parameters.hash)),
                parts,
                multipart,
                if execution == HashExecution::Pkcs11Combined {
                    parts.iter().map(|part| part.len()).max().unwrap_or(0)
                } else {
                    parameters.hash.output_length()
                },
                signature.len(),
                (execution == HashExecution::RustSoftware).then_some(parameters.hash),
                None,
                None,
            )?;
        let object = self.rsa_reference_handle(&s, key)?;
        let validity = match execution {
            HashExecution::RustSoftware => self.pss_verify_native(
                &s,
                object,
                parameters,
                kind,
                &[prehash_storage
                    .software
                    .as_ref()
                    .expect("prepared software digest")
                    .as_bytes()],
                false,
                signature,
                prepared_signature,
                diagnostics,
            )?,
            HashExecution::Pkcs11Combined => self.pss_verify_native(
                &s,
                object,
                parameters,
                kind,
                parts,
                multipart,
                signature,
                prepared_signature,
                diagnostics,
            )?,
            HashExecution::Pkcs11DigestThenPrimitive => {
                if s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::PssVerifyFunctionsUnavailable,
                        ),
                    ));
                }
                let digest = self.digest_guarded(
                    &s,
                    parameters.hash,
                    parts,
                    multipart,
                    prepared_digest.take().expect("native prehash prepared"),
                    diagnostics,
                )?;
                self.pss_verify_native(
                    &s,
                    object,
                    parameters,
                    kind,
                    &[digest.as_bytes()],
                    false,
                    signature,
                    prepared_signature,
                    diagnostics,
                )?
            }
        };
        self.public_result(
            &s,
            Ok(Self::pss_result(
                key,
                parameters,
                validity,
                HashProvenance::Executed(execution),
            )),
        )
    }
    fn pss_verify_native(
        &self,
        s: &crate::session::SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
        parameters: RsaPssParameters,
        kind: CK_MECHANISM_TYPE,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        prepared_signature: super::native_signature::storage::Storage,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<Verification> {
        self.verify_native_mechanism(
            s,
            object,
            kind,
            super::native_signature::SignatureParameters::pss(parameters.checked()?),
            parts,
            multipart,
            signature,
            prepared_signature,
            diagnostics,
        )
    }
    fn pss_result(
        key: &VerificationKey,
        parameters: RsaPssParameters,
        validity: Verification,
        hash_provenance: HashProvenance,
    ) -> VerificationResult {
        VerificationResult {
            validity,
            profile: VerificationProfile::RsaPss(parameters),
            key_fingerprint: key.fingerprint,
            hash_provenance,
            rsa_exponent_class: key.rsa_exponent_class(),
        }
    }
    /// Verify RSA PKCS1v1.5 over an exact message with explicit hashing route.
    pub fn verify_rsa_pkcs1(
        &self,
        key: &VerificationKey,
        hash: HashAlgorithm,
        execution: HashExecution,
        message: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_rsa_parts(
            key,
            hash,
            execution,
            &[message],
            false,
            signature,
            limits,
            diagnostics,
        )
    }
    /// Real native Update/Final when requested; no concatenation or fallback.
    pub fn verify_rsa_pkcs1_multipart(
        &self,
        key: &VerificationKey,
        hash: HashAlgorithm,
        execution: HashExecution,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_rsa_parts(
            key,
            hash,
            execution,
            parts,
            true,
            signature,
            limits,
            diagnostics,
        )
    }
    /// Verify a caller-provided digest. The library builds exact DigestInfo;
    /// ConsumerAttested and exponent classification survive Invalid as well.
    pub fn verify_rsa_pkcs1_digest(
        &self,
        key: &VerificationKey,
        digest: &PreparedDigest,
        signature: &[u8],
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        let (_, prepared_signature, mut prehash_storage, s) = self
            .prepare_verification_read_access(
                &key.managed,
                None,
                &[],
                false,
                digest_info_length(digest.algorithm)?,
                signature.len(),
                None,
                Some(digest_info_length(digest.algorithm)?),
                Some(digest),
            )?;
        let mut info = prehash_storage
            .encoded
            .take()
            .expect("prepared RSA encoding");
        digest_info_into(digest, info.as_mut_slice())?;
        let object = self.rsa_reference_handle(&s, key)?;
        let validity = self.parameterless_verify_native(
            &s,
            object,
            CKM_RSA_PKCS,
            &[info.as_slice()],
            false,
            signature,
            prepared_signature,
            diagnostics,
        )?;
        self.public_result(
            &s,
            Ok(Self::rsa_result(
                key,
                digest.algorithm,
                validity,
                HashProvenance::ConsumerAttested,
            )),
        )
    }

    fn rsa_reference_handle(&self, s: &State, key: &VerificationKey) -> Result<CK_OBJECT_HANDLE> {
        let object = self.managed_handle(s, &key.managed)?;
        key.rsa.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::NotAnRsaReference,
            ),
        ))?;

        Ok(object)
    }
    fn rsa_result(
        key: &VerificationKey,
        hash: HashAlgorithm,
        validity: Verification,
        hash_provenance: HashProvenance,
    ) -> VerificationResult {
        VerificationResult {
            validity,
            profile: VerificationProfile::RsaPkcs1(hash),
            key_fingerprint: key.fingerprint,
            hash_provenance,
            rsa_exponent_class: key.rsa_exponent_class(),
        }
    }
    fn verify_rsa_parts(
        &self,
        key: &VerificationKey,
        hash: HashAlgorithm,
        execution: HashExecution,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        limits: InputLimits,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<VerificationResult> {
        limits.validate(self.inner.crypto_options.limits, parts)?;
        let combined = combined(hash)?;
        let (mut prepared_digest, prepared_signature, mut prehash_storage, s) = self
            .prepare_verification_read_access(
                &key.managed,
                (execution == HashExecution::Pkcs11DigestThenPrimitive)
                    .then_some(super::NativeHash::Modern(hash)),
                parts,
                multipart,
                if execution == HashExecution::Pkcs11Combined {
                    parts.iter().map(|part| part.len()).max().unwrap_or(0)
                } else {
                    digest_info_length(hash)?
                },
                signature.len(),
                (execution == HashExecution::RustSoftware).then_some(hash),
                (execution != HashExecution::Pkcs11Combined)
                    .then(|| digest_info_length(hash))
                    .transpose()?,
                None,
            )?;
        let mechanism = if execution == HashExecution::Pkcs11Combined {
            combined
        } else {
            CKM_RSA_PKCS
        };
        if let Some(digest) = prehash_storage.software.as_ref() {
            digest_info_into(
                digest,
                prehash_storage
                    .encoded
                    .as_mut()
                    .expect("prepared RSA encoding")
                    .as_mut_slice(),
            )?;
        }
        let object = self.rsa_reference_handle(&s, key)?;
        let validity = match execution {
            HashExecution::RustSoftware => self.parameterless_verify_native(
                &s,
                object,
                mechanism,
                &[prehash_storage
                    .encoded
                    .as_ref()
                    .expect("prepared RSA encoding")
                    .as_slice()],
                false,
                signature,
                prepared_signature,
                diagnostics,
            )?,
            HashExecution::Pkcs11Combined => self.parameterless_verify_native(
                &s,
                object,
                mechanism,
                parts,
                multipart,
                signature,
                prepared_signature,
                diagnostics,
            )?,
            HashExecution::Pkcs11DigestThenPrimitive => {
                if s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::RsaVerifyFunctionsUnavailable,
                        ),
                    ));
                }
                let digest = self.digest_guarded(
                    &s,
                    hash,
                    parts,
                    multipart,
                    prepared_digest.take().expect("native prehash prepared"),
                    diagnostics,
                )?;
                let mut info = prehash_storage
                    .encoded
                    .take()
                    .expect("prepared RSA encoding");
                digest_info_into(&digest, info.as_mut_slice())?;
                self.parameterless_verify_native(
                    &s,
                    object,
                    mechanism,
                    &[info.as_slice()],
                    false,
                    signature,
                    prepared_signature,
                    diagnostics,
                )?
            }
        };
        self.public_result(
            &s,
            Ok(Self::rsa_result(
                key,
                hash,
                validity,
                HashProvenance::Executed(execution),
            )),
        )
    }
}
