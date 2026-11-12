// SPDX-License-Identifier: Apache-2.0
//! Bind RSA-PSS native parameters and preserve their witnesses during signing.
//! Contextual and ordinary signing use the same explicit parameter representation.

use super::*;

impl Digest32 {
    /// Accept exactly 32 digest bytes. Never truncate or pad.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(bytes.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::Sha256DigestLength,
            ))
        })?))
    }
}

impl Drop for Digest32 {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl PssCall {
    pub(super) fn bind(&mut self) -> Result<()> {
        self.mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_PSS as _,
            pParameter: std::ptr::addr_of_mut!(self.parameters).cast(),
            ulParameterLen: bounds::ck_length(std::mem::size_of_val(&self.parameters))?,
        };
        Ok(())
    }

    pub(super) fn parameters_unchanged(&self, expected: PssParams) -> bool {
        self.mechanism.mechanism == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
            && self.mechanism.pParameter == std::ptr::addr_of!(self.parameters).cast_mut().cast()
            && self.mechanism.ulParameterLen
                == std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG
            && self.parameters.hashAlg as u64 == expected.hash
            && self.parameters.mgf as u64 == expected.mgf
            && self.parameters.sLen as usize == expected.salt_length
    }
}

impl PssParams {
    pub(super) fn checked(self) -> Result<CK_RSA_PKCS_PSS_PARAMS> {
        if self.hash != CKM_SHA256 as u64 {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::Digest32RequiresSha256,
            )));
        }
        Ok(CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: CKM_SHA256 as _,
            mgf: self.mgf.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::MgfIdentifierConversion,
                ))
            })?,
            sLen: bounds::ck_length(self.salt_length)?,
        })
    }
}

impl Session {
    /// Sign one digest using the explicit RSA-PSS profile. No sizing signature,
    /// mechanism fallback or private-operation retry is performed. An active
    /// sequence whose termination is unproven retains its native frame/session;
    /// consumed digest storage is erased only when ordinary release is safe.
    pub fn sign_pss(
        &self,
        key: &ObjectRef,
        digest: Digest32,
        params: PssParams,
    ) -> Result<Vec<u8>> {
        let mut diagnostics = pss_preparation::SigningDiagnostics::default();
        self.sign_pss_selected(key, digest, params, None, &mut diagnostics)
    }

    /// Sign one digest with an explicit contextual login between SignInit and
    /// Sign, without a second Init or any PIN/mechanism retry. The token writer
    /// is acquired before Init because PIN_LOCKED can affect every session.
    /// If login refuses after Init, the initialized frame remains retained and
    /// this synchronous session requires explicit successful closure; use an
    /// advanced retained operation when interactive PIN retry is required.
    pub fn sign_pss_with_context(
        &self,
        key: &ObjectRef,
        digest: Digest32,
        params: PssParams,
        authentication: ContextAuthentication,
    ) -> Result<Vec<u8>> {
        let mut diagnostics = pss_preparation::SigningDiagnostics::default();
        self.sign_pss_selected(key, digest, params, Some(authentication), &mut diagnostics)
    }

    pub(super) fn sign_pss_selected(
        &self,
        key: &ObjectRef,
        digest: Digest32,
        params: PssParams,
        mut authentication: Option<ContextAuthentication>,
        diagnostics: &mut pss_preparation::SigningDiagnostics,
    ) -> Result<Vec<u8>> {
        let mut prepared_authentication;
        let parameters = params.checked()?;
        let expected_digest = zeroize::Zeroizing::new(digest.0);
        let capacity = key.identity.modulus_bits.div_ceil(8);
        // Validate the route and reference before resource admission. This closure
        // grants access only: it must never initialize a native operation.
        let progress = crate::session::AdmissionProgress::default();
        let epoch = self.snapshot.authentication_stamp();
        let mut authentication_plan =
            crate::session::ContextLoginPlan::at_epoch(self, authentication.as_ref(), epoch)?;
        let acquire = |attempt| {
            use crate::session::activity::PossessionAttempt;
            let access = match attempt {
                PossessionAttempt::Nonwaiting => {
                    self.try_operation_access_progress(authentication.is_some(), &progress)
                }
                PossessionAttempt::Admitted if authentication.is_some() => {
                    self.context_operation_access_progress(&progress)
                }
                PossessionAttempt::Admitted => self.access_progress(&progress),
            }?;
            self.object(&access, key, Some(ObjectClass::PrivateKey))?;
            access.native.table.C_SignInit.ok_or(Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CSignInitUnavailable,
                ),
            ))?;
            access.native.table.C_Sign.ok_or(Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CSignUnavailable,
                ),
            ))?;
            Ok(access)
        };
        drop(acquire(
            crate::session::activity::PossessionAttempt::Admitted,
        )?);
        let readers = crate::session::activity::Readers::prepare_at_epoch(
            self,
            [Some(&key.identity.activity)],
            epoch,
        )?;
        let (storage, mut authentication_storage, s, permits) = authentication_plan
            .prepare_readers_with(
                self,
                &readers,
                |overhead| {
                    pss_preparation::Storage::prepare(self, capacity, overhead, &progress, epoch)
                },
                acquire,
            )?;
        let diagnostic = diagnostics.sequence.insert(storage.diagnostic).cell();
        // Complete fallible preparation before native Init. The login frame
        // retains a clone of the same exclusive access, never a lock upgrade.
        let mut permits = permits;
        let s = s;
        prepared_authentication = crate::session::PreparedContextLogin::from_prepared(
            self,
            &s,
            &mut authentication,
            &mut authentication_storage,
        )?;
        // Resolve the complete route before Init; never leave an operation active
        // solely because its final function is absent from the native interface.
        let init = s.native.table.C_SignInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CSignInitUnavailable,
            ),
        ))?;
        let sign = s.native.table.C_Sign.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CSignUnavailable,
            ),
        ))?;
        let permit = permits[0].take().expect("prepared RSA key reader");
        let object = self.object(&s, key, Some(ObjectClass::PrivateKey))?;
        let handle = self.entry(&s)?.handle;
        let mut frame = crate::native::frame::NativeFrame::session(
            s,
            PssCall {
                parameters,
                mechanism: crate::native::output::mechanism(),
                digest,
                signature: storage.signature,
                _credit: storage.credit,
                length: bounds::ck_length(capacity)?,
                _object: permit,
                _activity: key.identity.activity.clone(),
            },
        )?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let call = &mut *body.data;
        let result = (|| {
            call.bind()?;
            s.native.record("C_SignInit")?;
            let mut sequence = Sequence::for_frame_prepared(s, self, returned, diagnostic);
            // SAFETY: mechanism and parameters are bound inside a stable frame
            // owning the session guards, their referents and the object permit.
            let rv = returned.observe(
                unsafe { init(handle, &mut call.mechanism, object) },
                &s.native,
            );
            let inspected_return = sequence.inspect_return(
                rv,
                "C_SignInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if !call.parameters_unchanged(params) {
                        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                            crate::SessionLifecycleRejection::PssInputDescriptorChanged,
                        )));
                    }

                    Ok(())
                },
            )?;

            inspected_return.check(false)?;

            if let Some(authentication) = prepared_authentication.as_mut() {
                if let Err(error) = authentication.perform(self) {
                    // Login failure is not proof that the signing operation
                    // terminated. A returned active frame can release guards
                    // into the close ledger; PENDING/ABI anomalies still retain
                    // the complete uncertain owners through NativeFrame.
                    returned.recoverable();
                    return Err(error);
                }
                if !call.parameters_unchanged(params) || call.digest.0 != *expected_digest {
                    returned.quarantine(&s.native);
                    return Err(
                        sequence.invalid_output(crate::RejectionReason::SessionLifecycle(crate::SessionLifecycleRejection::PssInputChangedDuringContextAuthentication))
                    );
                }
            }

            sequence.record_next("C_Sign")?;
            let rv = {
                // SAFETY: digest, fixed output allocation and length slot are
                // owned by the frame, retained before any fallible inspection.
                returned.observe(
                    unsafe {
                        sign(
                            handle,
                            call.digest.0.as_mut_ptr(),
                            32,
                            call.signature.as_mut_ptr(),
                            &mut call.length,
                        )
                    },
                    &s.native,
                )
            };
            let inspected_return = sequence.inspect_output_return(
                rv,
                "C_Sign",
                capacity,
                || call.length,
                || {
                    if !call.parameters_unchanged(params) || call.digest.0 != *expected_digest {
                        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                            crate::SessionLifecycleRejection::PssInputChanged,
                        )));
                    }
                    if rv == fe11_sys::CKR_OK {
                        bounds::final_length(call.length, capacity).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::SessionLifecycle(
                                crate::SessionLifecycleRejection::RsaSignatureCapacity,
                            ))
                        })?;
                    }
                    Ok(())
                },
            )?;

            inspected_return.check(true)?;
            let length = bounds::final_length(call.length, capacity).map_err(|_| {
                returned.quarantine(&s.native);
                sequence.invalid_output(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::RsaSignatureCapacity,
                ))
            })?;
            if length != capacity {
                return Err(
                    sequence.invalid_value(crate::RejectionReason::SessionLifecycle(
                        crate::SessionLifecycleRejection::RsaSignatureLength,
                    )),
                );
            }
            sequence.complete();
            Ok(std::mem::take(&mut call.signature))
        })();
        diagnostics.authentication = prepared_authentication.map(|value| value.into_diagnostics());
        key.identity.access.result(self, s, result)
    }

    /// Verify with the native provider. Length/value rejection is Invalid;
    /// other provider errors retain their status and function-specific scope.
    /// Unproven termination retains the native frame and prevents session reuse.
    pub fn verify_pss(
        &self,
        key: &ObjectRef,
        digest: Digest32,
        params: PssParams,
        signature: &[u8],
    ) -> Result<Verification> {
        // A preparation failure must release session access before diagnostic
        // credit wakes other admissions, just as on the completed frame path.
        let mut diagnostic_root = None;
        let parameters = params.checked()?;
        let expected_digest = zeroize::Zeroizing::new(digest.0);
        // Validate the route and reference before resource admission. This closure
        // grants access only: it must never initialize a native operation.
        let progress = AdmissionProgress::default();
        let epoch = self.snapshot.authentication_stamp();
        let acquire = |attempt| {
            use activity::PossessionAttempt;
            let access = match attempt {
                PossessionAttempt::Nonwaiting => {
                    self.try_operation_access_progress(false, &progress)
                }
                PossessionAttempt::Admitted => self.access_progress(&progress),
            }?;
            self.object(&access, key, Some(ObjectClass::PublicKey))?;
            access.native.table.C_VerifyInit.ok_or(Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CVerifyInitUnavailable,
                ),
            ))?;
            access.native.table.C_Verify.ok_or(Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CVerifyUnavailable,
                ),
            ))?;
            Ok(access)
        };
        drop(acquire(activity::PossessionAttempt::Admitted)?);
        let readers = crate::session::activity::Readers::prepare_at_epoch(
            self,
            [Some(&key.identity.activity)],
            epoch,
        )?;
        if signature.len() != key.identity.modulus_bits.div_ceil(8) {
            let (s, _permits) = readers
                .acquire_in_context(self, || acquire(activity::PossessionAttempt::Admitted))?;
            return key
                .identity
                .access
                .result(self, &s, Ok(Verification::Invalid));
        }
        let mut authentication_plan = ContextLoginPlan::at_epoch(self, None, epoch)?;
        let (mut storage, _, s, mut permits) = authentication_plan.prepare_readers_with(
            self,
            &readers,
            |overhead| {
                pss_preparation::Storage::prepare(self, signature.len(), overhead, &progress, epoch)
            },
            acquire,
        )?;
        let init = s.native.table.C_VerifyInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CVerifyInitUnavailable,
            ),
        ))?;
        let verify = s.native.table.C_Verify.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CVerifyUnavailable,
            ),
        ))?;
        let permit = permits[0].take().expect("prepared RSA key reader");
        let object = self.object(&s, key, Some(ObjectClass::PublicKey))?;
        let handle = self.entry(&s)?.handle;
        let signature_length = bounds::ck_length(signature.len())?;
        let diagnostic = diagnostic_root.insert(storage.diagnostic).cell();
        storage.signature.copy_from_slice(signature);
        let mut frame = crate::native::frame::NativeFrame::session(
            s,
            PssCall {
                parameters,
                mechanism: crate::native::output::mechanism(),
                digest,
                signature: storage.signature,
                _credit: storage.credit,
                length: signature_length,
                _object: permit,
                _activity: key.identity.activity.clone(),
            },
        )?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let call = &mut *body.data;
        let result = (|| {
            call.bind()?;
            s.native.record("C_VerifyInit")?;
            let sequence = Sequence::for_frame_prepared(s, self, returned, diagnostic);
            // SAFETY: same complete native ownership as signing, including the
            // copied public signature. No borrowed caller memory reaches C.
            let rv = returned.observe(
                unsafe { init(handle, &mut call.mechanism, object) },
                &s.native,
            );
            let inspected_return = sequence.inspect_return(
                rv,
                "C_VerifyInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if !call.parameters_unchanged(params) {
                        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                            crate::SessionLifecycleRejection::PssInputDescriptorChanged,
                        )));
                    }

                    Ok(())
                },
            )?;

            inspected_return.check(false)?;
            sequence.record_next("C_Verify")?;
            // SAFETY: exact owned input allocations remain stable through the
            // native return; PENDING is observed before inspecting any input.
            let rv = returned.observe(
                unsafe {
                    verify(
                        handle,
                        call.digest.0.as_mut_ptr(),
                        32,
                        call.signature.as_mut_ptr(),
                        signature_length,
                    )
                },
                &s.native,
            );
            let inspected_return = sequence.inspect_return(
                rv,
                "C_Verify",
                crate::native_return::protocol::SequencePhase::Continue(
                    crate::native_return::sequence::OutputRequest::Unspecified,
                ),
                || {
                    if !call.parameters_unchanged(params)
                        || call.digest.0 != *expected_digest
                        || call.signature.as_slice() != signature
                    {
                        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                            crate::SessionLifecycleRejection::PssVerificationInputChanged,
                        )));
                    }

                    Ok(())
                },
            )?;

            let status = inspected_return.check(false);
            match rv {
                CKR_OK => {
                    status?;
                    Ok(Verification::Valid)
                }
                CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE => Ok(Verification::Invalid),
                _ => status.map(|_| Verification::Invalid),
            }
        })();
        key.identity.access.result(self, s, result)
    }
}
