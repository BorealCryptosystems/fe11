// SPDX-License-Identifier: Apache-2.0
//! ECDSA message verification with explicit hashing origin and bounded multipart.
use super::{
    HashAlgorithm, HashExecution, InputLimits, PreparedDigest, VerificationKey, VerificationProfile,
};
use crate::{bounds, module::State, session::Sequence, Error, Result, Session, Verification};
use fe11_sys::*;

/// Where the digest used for verification actually came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashProvenance {
    /// Library-controlled execution over the provided message.
    Executed(HashExecution),
    /// Caller supplied a typed digest; its claimed hash provenance is not proven.
    ConsumerAttested,
}
/// Cryptographic result and provenance, never an implicit trust decision.
#[derive(Debug)]
pub struct VerificationResult {
    /// Valid or Invalid; operational provider errors remain separate errors.
    pub validity: Verification,
    /// Explicit profile used, also present for Invalid results.
    pub profile: VerificationProfile,
    /// Expected canonical SPKI SHA-256 bound to the reference.
    pub key_fingerprint: [u8; 32],
    /// Executed hashing route or unproven caller attestation.
    pub hash_provenance: HashProvenance,
    /// RSA exponent classification, independent of validity and hash provenance.
    pub rsa_exponent_class: Option<super::RsaExponentClass>,
}
pub(super) fn combined(hash: HashAlgorithm) -> CK_MECHANISM_TYPE {
    match hash {
        HashAlgorithm::Sha224 => CKM_ECDSA_SHA224,
        HashAlgorithm::Sha256 => CKM_ECDSA_SHA256,
        HashAlgorithm::Sha384 => CKM_ECDSA_SHA384,
        HashAlgorithm::Sha512 => CKM_ECDSA_SHA512,
        HashAlgorithm::Sha3_224 => CKM_ECDSA_SHA3_224,
        HashAlgorithm::Sha3_256 => CKM_ECDSA_SHA3_256,
        HashAlgorithm::Sha3_384 => CKM_ECDSA_SHA3_384,
        HashAlgorithm::Sha3_512 => CKM_ECDSA_SHA3_512,
    }
}
impl Session {
    /// Verify PKCS#11 r||s over a message, with a mandatory hashing route.
    /// Both halves may be equally short (PKCS#11 §6.3.1); their exact bytes
    /// reach the module without padding or a retry using another encoding.
    pub fn verify_ecdsa(
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
        self.verify_ecdsa_parts(
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
    /// Verify bounded message pieces. Combined mode uses real VerifyUpdate/Final;
    /// native-digest mode uses real DigestUpdate/Final followed by raw Verify.
    pub fn verify_ecdsa_multipart(
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
        self.verify_ecdsa_parts(
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
    /// Verify a caller-supplied digest; ConsumerAttested is retained on Valid and
    /// Invalid. This entry cannot sign and does not prove the declared hash.
    pub fn verify_ecdsa_digest(
        &self,
        key: &VerificationKey,
        digest: &PreparedDigest,
        signature: &[u8],
    ) -> Result<VerificationResult> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
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
        let object = self.ecdsa_gate(&s, key)?;
        // Signature validity, including scalar values and lengths, belongs to
        // the module. Forward the caller's exact bytes without padding.
        let validity = self.parameterless_verify_native(
            &s,
            object,
            CKM_ECDSA,
            &[digest.as_bytes()],
            false,
            signature,
            prepared_signature,
            diagnostics,
        )?;
        self.public_result(
            &s,
            Ok(VerificationResult {
                validity,
                profile: VerificationProfile::Ecdsa(digest.algorithm),
                key_fingerprint: key.fingerprint,
                hash_provenance: HashProvenance::ConsumerAttested,
                rsa_exponent_class: None,
            }),
        )
    }
    fn verify_ecdsa_parts(
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
        // Software CPU work precedes locking; its protected result is also wiped
        // if subsequent authorization or reference checks fail.
        let (mut prepared_digest, prepared_signature, prehash_storage, s) = self
            .prepare_verification_read_access(
                &key.managed,
                (execution == HashExecution::Pkcs11DigestThenPrimitive)
                    .then_some(super::NativeHash::Modern(hash)),
                parts,
                multipart,
                if execution == HashExecution::Pkcs11Combined {
                    parts.iter().map(|part| part.len()).max().unwrap_or(0)
                } else {
                    hash.output_length()
                },
                signature.len(),
                (execution == HashExecution::RustSoftware).then_some(hash),
                None,
                None,
            )?;
        let mechanism = if execution == HashExecution::Pkcs11Combined {
            combined(hash)
        } else {
            CKM_ECDSA
        };
        let object = self.ecdsa_gate(&s, key)?;
        let validity = match execution {
            HashExecution::RustSoftware => self.parameterless_verify_native(
                &s,
                object,
                mechanism,
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
                // Validate the final primitive's functions before starting Digest.
                if s.native.table.C_VerifyInit.is_none() || s.native.table.C_Verify.is_none() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::EcdsaVerifyFunctionsUnavailable,
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
                self.parameterless_verify_native(
                    &s,
                    object,
                    mechanism,
                    &[digest.as_bytes()],
                    false,
                    signature,
                    prepared_signature,
                    diagnostics,
                )?
            }
        };
        let hash_provenance = HashProvenance::Executed(execution);
        self.public_result(
            &s,
            Ok(VerificationResult {
                validity,
                profile: VerificationProfile::Ecdsa(hash),
                key_fingerprint: key.fingerprint,
                hash_provenance,
                rsa_exponent_class: None,
            }),
        )
    }
    fn ecdsa_gate(&self, s: &State, key: &VerificationKey) -> Result<CK_OBJECT_HANDLE> {
        let object = self.managed_handle(s, &key.managed)?;
        key.curve.ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::NotAnEcdsaReference,
            ),
        ))?;

        Ok(object)
    }
    pub(super) fn parameterless_verify_native(
        &self,
        s: &crate::session::SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
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
            super::native_signature::SignatureParameters::None,
            parts,
            multipart,
            signature,
            prepared_signature,
            diagnostics,
        )
    }
    pub(super) fn verify_native_mechanism(
        &self,
        s: &crate::session::SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
        kind: CK_MECHANISM_TYPE,
        parameters: super::native_signature::SignatureParameters<'_>,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        prepared_signature: super::native_signature::storage::Storage,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<Verification> {
        if !multipart && parts.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                crate::NativeSignatureRejection::SinglePartVerificationRequiresOneInput,
            )));
        }
        let handle = self.entry(s)?.handle;
        let init = s.native.table.C_VerifyInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CVerifyInitUnavailable,
            ),
        ))?;
        // Retain one complete route before Init. A native return cannot change
        // the selected tuple or turn a later Update/Final into an absent entry.
        let route = if multipart {
            crate::crypto::native_route::Route::Multipart {
                update: s.native.table.C_VerifyUpdate.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CVerifyUpdateUnavailable,
                    ),
                ))?,
                finish: s.native.table.C_VerifyFinal.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CVerifyFinalUnavailable,
                    ),
                ))?,
            }
        } else {
            crate::crypto::native_route::Route::Single(s.native.table.C_Verify.ok_or(
                Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CVerifyUnavailable,
                )),
            )?)
        };
        let empty: &[&[u8]] = &[&[]];
        let pieces = if parts.is_empty() { empty } else { parts };
        let mut capacity = 0;
        for part in pieces {
            bounds::ck_length(part.len())?;
            capacity = capacity.max(part.len());
        }
        let signature_length = bounds::ck_length(signature.len())?;
        let input_length = bounds::ck_length(capacity)?;
        let (mut prepared, diagnostic) =
            prepared_signature.bind(kind, parameters, capacity, signature.len())?;
        let diagnostic = diagnostics.primitive.insert(diagnostic).cell();
        prepared.signature.as_mut_slice().copy_from_slice(signature);
        let mut frame = crate::native::frame::NativeFrame::session(s.clone(), prepared)?;
        frame.data.mechanism.bind_parameters()?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let call = &mut *body.data;
        s.native.record("C_VerifyInit")?;
        let sequence = Sequence::for_frame_prepared(s, self, returned, diagnostic);
        // SAFETY: the stable frame owns the mechanism, nested parameters and all
        // guards including the key activity. No caller descriptor is borrowed.
        let rv = returned.observe(
            unsafe { init(handle, &mut call.mechanism.native, object) },
            &s.native,
        );
        sequence
            .inspect_return(
                rv,
                "C_VerifyInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if !call.mechanism.unchanged(kind, parameters) {
                        Err(Error::Rejected(
                            crate::RejectionReason::ClassicalSignatures(
                                crate::ClassicalSignaturesRejection::VerificationParametersChanged,
                            ),
                        ))
                    } else {
                        Ok(())
                    }
                },
            )?
            .check(false)?;
        if let crate::crypto::native_route::Route::Multipart { update, .. } = route {
            for expected in pieces {
                zeroize::Zeroize::zeroize(call.input.as_mut_slice());
                call.input.as_mut_slice()[..expected.len()].copy_from_slice(expected);
                let length = bounds::ck_length(expected.len())?;
                sequence.record_next("C_VerifyUpdate")?;
                // SAFETY: one preallocated writable scratch lives in the complete
                // frame; reuse requires a successful synchronous Update return.
                let rv = returned.observe(
                    unsafe { update(handle, call.input.as_mut_slice().as_mut_ptr(), length) },
                    &s.native,
                );
                sequence
                    .inspect_return(
                        rv,
                        "C_VerifyUpdate",
                        crate::native_return::protocol::SequencePhase::Continue(
                            crate::native_return::sequence::OutputRequest::Unspecified,
                        ),
                        || {
                            if !call.mechanism.unchanged(kind, parameters)
                                || !call.input_unchanged(expected)
                            {
                                Err(Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::VerificationInputChanged,
                        )))
                            } else {
                                Ok(())
                            }
                        },
                    )?
                    .check(false)?;

            }
        } else {
            call.input.as_mut_slice()[..pieces[0].len()].copy_from_slice(pieces[0]);
        }
        let function = if multipart {
            "C_VerifyFinal"
        } else {
            "C_Verify"
        };
        sequence.record_next(function)?;
        // SAFETY: signature, scratch and mechanism remain in the same frame
        // until function-specific completion. No NULL sizing call or retry.
        let rv = returned.observe(
            unsafe {
                match route {
                    crate::crypto::native_route::Route::Multipart { finish, .. } => finish(
                        handle,
                        call.signature.as_mut_slice().as_mut_ptr(),
                        signature_length,
                    ),
                    crate::crypto::native_route::Route::Single(verify) => verify(
                        handle,
                        call.input.as_mut_slice().as_mut_ptr(),
                        input_length,
                        call.signature.as_mut_slice().as_mut_ptr(),
                        signature_length,
                    ),
                }
            },
            &s.native,
        );
        let last = pieces.last().expect("at least one verification piece");
        let result = sequence
            .inspect_return(
                rv,
                function,
                crate::native_return::protocol::SequencePhase::Continue(
                    crate::native_return::sequence::OutputRequest::Unspecified,
                ),
                || {
                    if !call.mechanism.unchanged(kind, parameters)
                        || !call.input_unchanged(last)
                        || call.signature.as_slice() != signature
                    {
                        Err(Error::Rejected(
                            crate::RejectionReason::ClassicalSignatures(
                                crate::ClassicalSignaturesRejection::VerificationInputChanged,
                            ),
                        ))
                    } else {
                        Ok(())
                    }
                },
            )?
            .check(false);
        if !sequence.termination_known() {
            result?;
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::VerificationCompletionUnproven,
                ),
            ));
        }

        match rv {
            CKR_OK => Ok(Verification::Valid),
            CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE => Ok(Verification::Invalid),
            _ => result.map(|_| unreachable!()),
        }
    }
}
