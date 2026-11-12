// SPDX-License-Identifier: Apache-2.0
//! Maintain paired-operation keys, terminal facts and checkpoint metadata.
//! Each half retains its own native completion and continuation state.

use super::*;

impl DualOperation {
    pub(in crate::advanced) fn check_keys(&self, entry: &SessionEntry) -> Result<()> {
        self.cipher_key.check(entry)?;
        if let Some(m) = self.authentication.key() {
            m.check(entry)?;
        }
        Ok(())
    }

    pub(in crate::advanced) fn encrypting(&self) -> bool {
        !self.mode.decrypt()
    }

    // Only the transfer control calls this after C_AsyncGetID OK: the module
    // has released its access to the original native allocations, not completed.
    pub(in crate::advanced) fn detached_native_release(&mut self) {
        self.pending = false;
    }

    pub(in crate::advanced) fn checkpoint_header(
        &self,
    ) -> Result<(record::Descriptor, record::KeyBindings<'_>)> {
        let descriptor = record::Descriptor {
            input: crate::advanced::input::InputState::closed(),
            family: match self.mode {
                Mode::DigestEncrypt => Family::DigestEncrypt,
                Mode::DecryptDigest => Family::DecryptDigest,
                Mode::SignEncrypt => Family::SignEncrypt,
                Mode::DecryptVerify => Family::DecryptVerify,
            },
            profile: self
                .authentication
                .selection()
                .profile(self.cipher_key.checkpoint_profile()?)?,
            phase: record::Function::from_name(if self.complete() {
                if !self.mode.mac() {
                    "C_DigestFinal"
                } else if self.mode.decrypt() {
                    "C_VerifyFinal"
                } else {
                    "C_SignFinal"
                }
            } else {
                self.function()?
            })?,
            mechanism: self.cipher.mechanism.mechanism as u64,
            size: 0,
            active_flags: self.active_flags as u64,
            validation_requested: false,
            digest_bits: None,
            cipher_options: None,
            carried_messages: 0,
        };
        Ok((
            descriptor,
            record::KeyBindings {
                cipher: Some(self.cipher_key.checkpoint_key(record::KeyRole::Cipher)?),
                authentication: self
                    .authentication
                    .key()
                    .map(|k| k.checkpoint_key(record::KeyRole::Authentication))
                    .transpose()?,
            },
        ))
    }

    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        budget: &Arc<Budget>,
        writer: &mut super::super::record::Writer<'_>,
        limits: super::super::record::Limits,
    ) -> Result<()> {
        self.write_terminal_messages(budget, writer, limits, false)
    }

    pub(in crate::advanced) fn terminal_valid(&self) -> bool {
        self.valid
    }

    pub(in crate::advanced) fn set_terminal(
        &mut self,
        valid: bool,
        authentication: &[u8],
    ) -> Result<()> {
        if authentication.len() != self.authentication.selection().length() {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::TerminalDualAuthenticationWidth,
            )));
        }
        self.auth.as_mut().copy_from_slice(authentication);
        self.step = DualStep::Done;
        self.pending = false;
        self.valid = valid;
        self.active_flags = 0;
        Ok(())
    }

    pub(in crate::advanced) fn write_terminal_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
        terminal: bool,
    ) -> Result<()> {
        use super::super::record::{Message, MessageState, Messages, NonceOrigin, Parameters};
        if self.pending || !self.valid && !terminal || self.step == DualStep::Failed {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualCheckpointUnavailable,
            )));
        }
        let parts = self
            .layout
            .fragments(&self.inputs, MessageRoute::Multipart)?;
        let (state, next_fragment) = match self.step {
            DualStep::AuthInit => (MessageState::Planned, 0),
            DualStep::CipherInit => (MessageState::Engaged, 0),
            DualStep::Update(n) => (MessageState::Engaged, n),
            DualStep::Done => (MessageState::Finished, parts.len()),
            _ => (MessageState::Engaged, parts.len()),
        };
        let output = self.output.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOutputAbsent,
            ),
        ))?;
        let result = if terminal && !self.valid {
            &[]
        } else {
            output.as_slice().get(..self.used).ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualCheckpointOutputRange,
                ),
            ))?
        };
        let gcm = self.cipher.gcm();
        let (_, expected) = output_bounds(
            self.input_length,
            self.mode.decrypt(),
            self.cipher.kind() as u64,
            self.cipher.tag_bytes(),
        )?;
        let auth = if self.mode == Mode::DecryptVerify || self.step == DualStep::Done {
            Some(self.auth.as_slice())
        } else {
            None
        };
        let message = Message {
            route: MessageRoute::Multipart,
            params: Parameters {
                digest_output: None,
                cipher_extension: None,
                digest_extension: None,
                signature: None,
                digest_oid: None,
                message_init: None,
                counter_bits: self.cipher.counter_bits(),
                iv_generator: self.cipher.selection().map(|_| 0),
                iv_fixed_bits: self.cipher.selection().map(|_| 0),
                iv_initial: self.cipher.selection().map(|n| n.iv()),
                nonce: Some(self.cipher.expected_iv.as_slice()),
                aad: if gcm {
                    Some(self.cipher.aad.as_slice())
                } else {
                    None
                },
                tag_bits: self.cipher.selection().map_or(0, |n| n.tag_bits() as u32),
                hash: Some(self.authentication.selection().hash().mechanism_number()),
                mgf: None,
                salt: None,
            },
            origin: NonceOrigin::Provided,
            state,
            fragments: parts,
            next_fragment,
            produced: result.len(),
            expected,
            result,
            tag_or_signature: auth,
            residual_start: if terminal && !self.valid {
                0
            } else {
                self.residual_start
            },
            residual_length: if terminal && !self.valid {
                0
            } else {
                self.residual_length
            },
        };
        Messages::write(writer, &[message], limits)
    }

    pub(in crate::advanced) fn restore_keys(
        &self,
        session: &Session,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut restoration_keys::BoundKeys,
    ) -> Result<()> {
        let key =
            keys.encryption
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::RestorationEncryptionKeyRequired,
                )))?;
        let lease = self.cipher_key.rebind_retained(
            session,
            key.reference,
            self.cipher.mechanism.mechanism,
            permits,
            &mut bound.encryption,
        )?;
        bound.native_encryption = match key.encoding {
            crate::advanced::StateKeyEncoding::Supplied => lease.handle,
            crate::advanced::StateKeyEncoding::Embedded => fe11_sys::CK_INVALID_HANDLE,
        };
        bound.encryption = Some(lease);
        match (self.authentication.key(), keys.authentication) {
            (Some(old), Some(k)) => {
                let lease = old.rebind_retained(
                    session,
                    k.reference,
                    self.authentication.selection().mechanism(),
                    permits,
                    &mut bound.authentication,
                )?;
                bound.native_authentication = match k.encoding {
                    crate::advanced::StateKeyEncoding::Supplied => lease.handle,
                    crate::advanced::StateKeyEncoding::Embedded => fe11_sys::CK_INVALID_HANDLE,
                };
                bound.authentication = Some(lease);
            }
            (None, None) => {}
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::RestorationDualKeyRoles,
                )))
            }
        }
        Ok(())
    }

    /// Return both displaced roles without releasing either under possession.
    pub(in crate::advanced) fn bind_restored(
        &mut self,
        mut keys: restoration_keys::BoundKeys,
    ) -> restoration_keys::BoundKeys {
        let replacement = keys
            .encryption
            .take()
            .expect("validated restoration encryption key");
        keys.encryption = Some(std::mem::replace(&mut self.cipher_key, replacement));
        keys.authentication = self.authentication.replace_key(keys.authentication.take());
        keys
    }

    pub(in crate::advanced) fn complete(&self) -> bool {
        self.step == DualStep::Done
    }

    pub(in crate::advanced) fn result(
        &mut self,
        _entry: &SessionEntry,
    ) -> Result<OperationProgress> {
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualNotComplete,
            )));
        }
        if !self.valid {
            return Ok(OperationProgress::Dual(DualResult::Invalid));
        }
        let bytes = self.output.take().ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAlreadyPublished,
            ),
        ))?;
        let plaintext = |bytes| {
            if self.cipher.tag_bytes() != 0 {
                DigestPlaintext::Authenticated(DualAuthenticatedPlaintext(bytes))
            } else {
                DigestPlaintext::Unauthenticated(UnauthenticatedPlaintext(bytes))
            }
        };
        // Publish the already allocated output; no allocation or budget wait is
        // allowed after the native operation has completed successfully.
        let result = match (self.mode, self.authentication.selection()) {
            (Mode::DigestEncrypt, Authentication::Digest(algorithm)) => {
                DualResult::DigestEncryptedWithAlgorithm {
                    ciphertext: DualCiphertext(bytes),
                    digest: crate::PreparedDigest::take_budgeted(algorithm, &mut self.auth)?,
                }
            }
            (Mode::DecryptDigest, Authentication::Digest(algorithm)) => {
                DualResult::DigestDecryptedWithAlgorithm {
                    plaintext: plaintext(bytes),
                    digest: crate::PreparedDigest::take_budgeted(algorithm, &mut self.auth)?,
                }
            }
            (Mode::SignEncrypt, Authentication::Hmac(algorithm)) => {
                DualResult::MacEncryptedWithAlgorithm {
                    ciphertext: DualCiphertext(bytes),
                    mac: DualMac {
                        algorithm: algorithm.hash(),
                        bytes: self.auth.take(),
                    },
                }
            }
            (Mode::DecryptVerify, Authentication::LegacyHmacSha256 | Authentication::Hmac(_)) => {
                DualResult::MacDecrypted(DualAuthenticatedPlaintext(bytes))
            }
            (mode, Authentication::LegacyDigestSha256 | Authentication::LegacyHmacSha256) => {
                let authentication = self.auth.as_slice().try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::LegacyDualAuthenticationWidth,
                    ))
                })?;
                match mode {
                    Mode::DigestEncrypt => DualResult::DigestEncrypted {
                        ciphertext: DualCiphertext(bytes),
                        digest: authentication,
                    },
                    Mode::DecryptDigest => DualResult::DigestDecrypted {
                        plaintext: plaintext(bytes),
                        digest: authentication,
                    },
                    Mode::SignEncrypt => DualResult::MacEncrypted {
                        ciphertext: DualCiphertext(bytes),
                        mac: authentication,
                    },
                    Mode::DecryptVerify => unreachable!("validated dual authentication role"),
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualAuthenticationResultRole,
                )))
            }
        };
        Ok(OperationProgress::Dual(result))
    }

    pub(in crate::advanced) fn function(&self) -> Result<&'static str> {
        Ok(match self.step {
            DualStep::AuthInit => {
                if !self.mode.mac() {
                    "C_DigestInit"
                } else if self.mode.decrypt() {
                    "C_VerifyInit"
                } else {
                    "C_SignInit"
                }
            }
            DualStep::CipherInit => {
                if self.mode.decrypt() {
                    "C_DecryptInit"
                } else {
                    "C_EncryptInit"
                }
            }
            DualStep::Update(_) => self.mode.update(),
            DualStep::CipherFinal => {
                if self.mode.decrypt() {
                    "C_DecryptFinal"
                } else {
                    "C_EncryptFinal"
                }
            }
            DualStep::Residual => {
                if self.mode.mac() {
                    "C_VerifyUpdate"
                } else {
                    "C_DigestUpdate"
                }
            }
            DualStep::AuthFinal => {
                if !self.mode.mac() {
                    "C_DigestFinal"
                } else if self.mode.decrypt() {
                    "C_VerifyFinal"
                } else {
                    "C_SignFinal"
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualNotActive,
                )))
            }
        })
    }

    pub(super) fn cipher_output(&self) -> bool {
        matches!(self.step, DualStep::Update(_) | DualStep::CipherFinal)
    }

    pub(super) fn auth_output(&self) -> bool {
        self.step == DualStep::AuthFinal && self.mode != Mode::DecryptVerify
    }

    pub(super) fn finish_step(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        returned: crate::native_return::protocol::PendingInspection,
    ) -> Result<()> {
        let rv = returned.code();
        let name = returned.function();
        let affected = self.step_categories();
        let init = matches!(self.step, DualStep::AuthInit | DualStep::CipherInit);
        use crate::native_return::protocol::SequencePhase;
        use crate::native_return::sequence::{Completion, OutputRequest};
        let size = super::return_size::observe(
            &returned,
            self.step,
            self.mode,
            (
                self.output
                    .as_ref()
                    .map_or(0, |out| out.capacity() - self.used),
                || *self.length,
            ),
            (self.auth.capacity(), || *self.auth_length),
        );
        let inspected = returned.inspect(|| {
            self.cipher.validate()?;
            let auth_kind = self.authentication.selection().mechanism();
            if self.auth_mechanism.mechanism != auth_kind
                || !self.auth_mechanism.pParameter.is_null()
                || self.auth_mechanism.ulParameterLen != 0
            {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualAuthenticationParameterIdentity,
                )));
            }
            // Ordinary native failures do not define output lengths. Only a
            // successful producing call may establish these physical bounds.
            if rv == CKR_OK {
                if self.cipher_output() {
                    let out = self.output.as_ref().expect("prepared dual output");
                    bounds::final_length(*self.length, out.capacity() - self.used)?;
                }
                if self.auth_output() {
                    bounds::final_length(*self.auth_length, self.auth.capacity())?;
                }
            }
            Ok(())
        });
        let version = s.native.table.version;
        let phase = if init {
            SequencePhase::Initialize
        } else {
            SequencePhase::Continue(OutputRequest::Buffer)
        };
        let initialization_refused =
            inspected.initialization_refused((version.major, version.minor), phase);
        let completion = inspected.completion((version.major, version.minor), phase);
        let result = inspected.resolve(|result, cause| {
            self.active_flags |= affected;
            s.native.mark_uncertain();
            self.step = DualStep::Failed;
            if result.code() == CKR_OK {
                cause
            } else {
                self.completion_diagnostic
                    .take()
                    .expect("one terminal dual boundary failure")
                    .bind(result.function())
                    .boundary_with_output(result.code(), size, cause)
            }
        })?;
        if completion == Completion::Terminated || initialization_refused {
            // A function-local termination releases only its own component.
            // Combined Update proves neither component terminated.
            self.active_flags &= !affected;
        }
        let invalid = self.mode == Mode::DecryptVerify
            && self.step == DualStep::AuthFinal
            && matches!(rv, CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE);
        if rv != CKR_OK && !invalid {
            self.step = DualStep::Failed;
            let scope = crate::native_return::native_context_scope(rv);
            if !result.memory_returned() || scope != crate::native_return::FailureScope::None {
                entry.poisoned.store(true, Ordering::Release);
            }
            // Ordinary partial failure retains the other native component for
            // explicit cancellation/close, without poisoning a healthy session.
            return match size {
                Some(size) => Err(size.buffer_too_small()),
                None => result.check(!(init && completion == Completion::Terminated)),
            };
        }
        if invalid {
            self.valid = false;
        }
        let validated = (|| {
            if self.cipher_output() {
                let out = self.output.as_mut().unwrap();
                let length = bounds::final_length(*self.length, out.capacity() - self.used)?;
                if self.step == DualStep::CipherFinal {
                    self.residual_start = self.used;
                    self.residual_length = length;
                }
                self.used += length;
                if self.step == DualStep::CipherFinal {
                    out.set_length(self.used)?;
                }
            }
            if self.auth_output() {
                bounds::final_length(*self.auth_length, self.auth.capacity())?;
            }
            Ok(())
        })();
        if let Err(e) = validated {
            self.active_flags |= affected;
            s.native.mark_uncertain();
            self.step = DualStep::Failed;
            return Err(e);
        }
        let semantic_failure = if self.step == DualStep::CipherFinal {
            let (min, max) = output_bounds(
                self.input_length,
                self.mode.decrypt(),
                self.cipher.kind() as u64,
                self.cipher.tag_bytes(),
            )?;
            (self.used < min || self.used > max).then_some(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualExactOutputLength,
                ),
            )
        } else if self.auth_output()
            && *self.auth_length as u128 != self.authentication.selection().length() as u128
        {
            Some(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualDigestOrMacLength,
            ))
        } else {
            None
        };
        if let Some(reason) = semantic_failure {
            self.step = DualStep::Failed;
            // The native call completed; reporting its invalid semantic length
            // must not allocate under possession or acquire cleanup resources.
            return self
                .completion_diagnostic
                .take()
                .expect("one terminal dual completion failure")
                .bind(name)
                .finish(Err(Error::Rejected(reason)));
        }
        self.step = match self.step {
            DualStep::AuthInit => DualStep::CipherInit,
            DualStep::CipherInit => DualStep::Update(0),
            DualStep::Update(i) => {
                if i + 1 < self.inputs.len() {
                    DualStep::Update(i + 1)
                } else {
                    DualStep::CipherFinal
                }
            }
            DualStep::CipherFinal => {
                if self.mode.decrypt() && self.residual_length != 0 {
                    DualStep::Residual
                } else {
                    DualStep::AuthFinal
                }
            }
            DualStep::Residual => DualStep::AuthFinal,
            DualStep::AuthFinal => DualStep::Done,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DuplicateDualCompletion,
                )))
            }
        };
        Ok(())
    }

    pub(super) fn step_categories(&self) -> CK_FLAGS {
        let auth = if !self.mode.mac() {
            CKF_DIGEST
        } else if self.mode.decrypt() {
            CKF_VERIFY
        } else {
            CKF_SIGN
        };
        let cipher = if self.mode.decrypt() {
            CKF_DECRYPT
        } else {
            CKF_ENCRYPT
        };
        match self.step {
            DualStep::AuthInit | DualStep::Residual | DualStep::AuthFinal => auth,
            DualStep::CipherInit | DualStep::CipherFinal => cipher,
            DualStep::Update(_) => auth | cipher,
            DualStep::Done | DualStep::Failed => 0,
        }
    }

    pub(in crate::advanced) fn native_inactive(&self) -> bool {
        self.active_flags == 0 && !self.pending
    }

    pub(in crate::advanced) fn validation_point(&self) -> Result<Option<validation::Point>> {
        if matches!(self.step, DualStep::CipherFinal | DualStep::AuthFinal) {
            Ok(Some(validation::Point {
                function: self.function()?,
                message_index: None,
            }))
        } else {
            Ok(None)
        }
    }

    pub(in crate::advanced) fn pending(&self) -> bool {
        self.pending
    }

    pub(in crate::advanced) fn joined_capacity(&self) -> Result<Option<usize>> {
        if !self.pending {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOperationNotJoinable,
            )));
        }
        self.function()?;
        if self.cipher_output() {
            Ok(Some(
                self.output
                    .as_ref()
                    .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::DualOutputAbsent,
                    )))?
                    .capacity()
                    .checked_sub(self.used)
                    .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::DualOutputProgression,
                    )))?,
            ))
        } else {
            Ok(if self.auth_output() {
                Some(self.authentication.selection().length())
            } else {
                None
            })
        }
    }

    pub(in crate::advanced) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        self.joined_capacity()?;
        let name = self.function()?;
        self.pending = false;
        if let Err(error) = self.check_keys(entry) {
            self.step = DualStep::Failed;
            return Err(error);
        }
        let cipher = self.cipher_output();
        let auth = self.auth_output();
        let target = if cipher {
            Some(&mut self.output.as_mut().unwrap().as_mut()[self.used..])
        } else if auth {
            Some(self.auth.as_mut())
        } else {
            None
        };
        let observed = result.observed;
        let (_, length) = match result.project(name, target) {
            Ok(value) => value,
            Err(error) => {
                self.step = DualStep::Failed;
                s.native.mark_uncertain();
                return Err(error);
            }
        };
        if let Some(length) = length {
            if cipher {
                *self.length = length as CK_ULONG;
            } else {
                *self.auth_length = length as CK_ULONG;
            }
        }
        self.finish_step(
            s,
            entry,
            crate::native_return::protocol::PendingInspection::forwarded(observed),
        )
    }

    pub(in crate::advanced) fn active_categories(&self) -> CK_FLAGS {
        self.active_flags
            | if self.pending {
                match self.step {
                    DualStep::AuthInit => {
                        if !self.mode.mac() {
                            CKF_DIGEST
                        } else if self.mode.decrypt() {
                            CKF_VERIFY
                        } else {
                            CKF_SIGN
                        }
                    }
                    DualStep::CipherInit => {
                        if self.mode.decrypt() {
                            CKF_DECRYPT
                        } else {
                            CKF_ENCRYPT
                        }
                    }
                    _ => 0,
                }
            } else {
                0
            }
    }

    pub(in crate::advanced) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.step == DualStep::Failed {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualFailedExplicitCleanupRequired,
            )));
        }
        self.check_keys(entry)?;
        if self.pending {
            if !observe || !spend(remaining) {
                return Ok(());
            }
            let name = self.function()?;
            let cipher = self.cipher_output();
            let auth = self.auth_output();
            let call = s
                .native
                .asynchronous
                .and_then(|f| f.complete)
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
                )))?;
            self.name.fill(0);
            self.name[..name.len()].copy_from_slice(name.as_bytes());
            let result = if cipher || auth {
                &mut *self.completion as *mut CK_ASYNC_DATA
            } else {
                std::ptr::null_mut()
            };
            s.native.record("C_AsyncComplete")?;
            // SAFETY: descriptor, name and original native buffers remain owned.
            let rv = unsafe { call(entry.handle, self.name.as_mut_ptr(), result) };
            let observed =
                crate::native_return::protocol::PendingInspection::completed(name, rv, |scope| {
                    s.native.observe_async_return(rv);
                    if rv != CKR_PENDING {
                        s.apply_session_failure(entry, rv, scope);
                    }
                })
                .inspect(|| {
                    if cipher || auth {
                        let (pointer, capacity) = if cipher {
                            let out = self.output.as_mut().unwrap();
                            (
                                out.as_mut()[self.used..].as_mut_ptr(),
                                out.capacity() - self.used,
                            )
                        } else {
                            (
                                self.auth.as_mut().as_mut_ptr(),
                                self.authentication.selection().length(),
                            )
                        };
                        if self.completion.ulVersion != 0
                            || self.completion.pValue != pointer
                            || rv == CKR_OK && self.completion.ulValue as u128 > capacity as u128
                        {
                            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                            crate::CombinedOperationsRejection::DualAsynchronousOutputIdentity,
                        )));
                        }
                    }
                    Ok(())
                })
                .resolve(|result, cause| {
                    self.step = DualStep::Failed;
                    s.native.mark_uncertain();
                    if result.code() == CKR_OK {
                        cause
                    } else {
                        self.completion_diagnostic
                            .take()
                            .expect("one terminal dual observation failure")
                            .bind(result.function())
                            .boundary_failure(result.code(), cause)
                    }
                })?;
            if rv == CKR_PENDING {
                return Ok(());
            }
            if rv == CKR_OK && (cipher || auth) {
                let (pointer, capacity) = if cipher {
                    let out = self.output.as_mut().unwrap();
                    (
                        out.as_mut()[self.used..].as_mut_ptr(),
                        out.capacity() - self.used,
                    )
                } else {
                    (
                        self.auth.as_mut().as_mut_ptr(),
                        self.authentication.selection().length(),
                    )
                };
                if self.completion.ulVersion != 0
                    || self.completion.pValue != pointer
                    || self.completion.ulValue as usize > capacity
                {
                    s.native.mark_uncertain();
                    self.step = DualStep::Failed;
                    return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::DualAsynchronousOutputIdentity,
                    )));
                }
                if cipher {
                    *self.length = self.completion.ulValue;
                } else {
                    *self.auth_length = self.completion.ulValue;
                }
            }
            self.pending = false;
            self.finish_step(
                s,
                entry,
                crate::native_return::protocol::PendingInspection::forwarded(observed),
            )?;
        }
        while !matches!(self.step, DualStep::Done | DualStep::Failed) {
            if !spend(remaining) {
                return Ok(());
            }
            self.check_keys(entry)?;
            if s.native.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            let name = self.function()?;
            let native_call = resolved_call::Call::resolve(&s.native.table, self.mode, self.step)?;
            s.native.record(name)?;
            self.active_flags |= self.step_categories();
            // SAFETY: all input/output/parameter/length pointers belong to this
            // ledger frame; no stack or caller buffer can outlive its owner.
            let rv = unsafe {
                match native_call {
                    resolved_call::Call::DigestInit(call) => {
                        call(entry.handle, &mut *self.auth_mechanism)
                    }
                    resolved_call::Call::AuthInit(call) => call(
                        entry.handle,
                        &mut *self.auth_mechanism,
                        self.authentication.key().unwrap().handle,
                    ),
                    resolved_call::Call::CipherInit(call) => call(
                        entry.handle,
                        &mut *self.cipher.mechanism,
                        self.cipher_key.handle,
                    ),
                    resolved_call::Call::Update { call, index } => {
                        let input = &mut self.inputs[index];
                        let output = self.output.as_mut().unwrap();
                        *self.length = (output.capacity() - self.used) as CK_ULONG;
                        call(
                            entry.handle,
                            input.as_mut().as_mut_ptr(),
                            input.capacity() as _,
                            output.as_mut()[self.used..].as_mut_ptr(),
                            &mut *self.length,
                        )
                    }
                    resolved_call::Call::CipherFinal(call) => {
                        let output = self.output.as_mut().unwrap();
                        *self.length = (output.capacity() - self.used) as CK_ULONG;
                        call(
                            entry.handle,
                            output.as_mut()[self.used..].as_mut_ptr(),
                            &mut *self.length,
                        )
                    }
                    resolved_call::Call::Residual(call) => {
                        let output = self.output.as_mut().unwrap();
                        call(
                            entry.handle,
                            output.as_mut()[self.residual_start..].as_mut_ptr(),
                            self.residual_length as _,
                        )
                    }
                    resolved_call::Call::AuthFinal(call) => call(
                        entry.handle,
                        self.auth.as_mut().as_mut_ptr(),
                        &mut *self.auth_length,
                    ),
                    resolved_call::Call::VerifyFinal(call) => call(
                        entry.handle,
                        self.auth.as_mut().as_mut_ptr(),
                        self.authentication.selection().length() as CK_ULONG,
                    ),
                }
            };
            if rv == CKR_PENDING {
                self.pending = true;
                if entry.mode != AdvancedSessionMode::Asynchronous {
                    s.native.mark_uncertain();
                    return Err(Error::Native {
                        function: name,
                        code: rv as u64,
                        may_have_effect: true,
                    });
                }
                return Ok(());
            }
            self.finish_step(
                s,
                entry,
                crate::native_return::protocol::PendingInspection::returned(name, rv, |scope| {
                    s.apply_session_failure(entry, rv, scope);
                }),
            )?;
        }
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for DualOperation {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        super::super::key_roles::Roles::retain_unique(
            self.cipher_key.writer_roles(),
            [self.authentication.key().and_then(KeyLease::writer_roles)],
            retained,
        )?;
        self.cipher_key.retain_credits(retained)?;
        self.authentication.retain_credits(retained)?;
        self.cipher.retain_credits(retained)?;
        self.inputs.retain_credits(retained)?;
        self.layout.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        self.auth.retain_credits(retained)?;
        self._credit.retain_credits(retained)?;
        Ok(())
    }
}
