// SPDX-License-Identifier: Apache-2.0
//! Own signature-message inputs, key bindings and checkpoint progression.
//! Released input and terminal evidence follow the message’s native return state.

use super::*;

impl MacOperation {
    pub(in crate::advanced) fn take_released_inputs(&mut self) -> ReleasedInputs {
        std::mem::take(&mut self.released)
    }

    pub(super) fn retire_stream_input(&mut self, signature: Option<usize>) {
        // A caller-fed data step stops at Ready/Receive before another input
        // can be dispatched. Poll extracts both slots even on a later error.
        assert!(
            self.released.is_empty(),
            "previous message input not reclaimed"
        );
        self.released.fragment = self.stream_fragment.take();
        self.released.signature = signature.map(|index| {
            self.signatures
                .as_mut()
                .expect("retained verification input")
                .bytes[index]
                .take()
        });
    }

    // Only the transfer control calls this after C_AsyncGetID OK: the module
    // has released its access to the original native allocations, not completed.
    pub(in crate::advanced) fn detached_native_release(&mut self) {
        self.activity = NativeActivity::Active;
    }

    pub(in crate::advanced) fn check_rejoin_key(&self, entry: &SessionEntry) -> Result<()> {
        self.key.check(entry)
    }

    pub(in crate::advanced) fn checkpoint_header(
        &self,
    ) -> Result<(record::Descriptor, record::KeyBindings<'_>)> {
        if self
            .pss
            .as_ref()
            .is_some_and(|p| !p.unchanged().unwrap_or(false))
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::PssCheckpointParameterIdentity,
            )));
        }
        let descriptor = record::Descriptor {
            input: self.input,
            family: if self.verify {
                Family::MessageVerify
            } else {
                Family::MessageSign
            },
            profile: if let Some(parameters) = &self.pss {
                parameters.checkpoint_profile()
            } else {
                self.key.checkpoint_profile()?
            },
            phase: record::Function::from_name(if self.input.incremental {
                self.stream_boundary()?.function(self.verify)
            } else if self.complete() {
                if self.verify {
                    "C_MessageVerifyFinal"
                } else {
                    "C_MessageSignFinal"
                }
            } else {
                self.function()?
            })?,
            mechanism: self.mechanism.mechanism as u64,
            size: self.size,
            active_flags: 0,
            validation_requested: false,
            digest_bits: None,
            cipher_options: None,
            carried_messages: 0,
        };
        Ok((
            descriptor,
            record::KeyBindings {
                cipher: None,
                authentication: Some(self.key.checkpoint_key(record::KeyRole::Authentication)?),
            },
        ))
    }

    pub(in crate::advanced) fn write_checkpoint_messages(
        &self,
        budget: &Arc<Budget>,
        writer: &mut super::super::record::Writer<'_>,
        limits: super::super::record::Limits,
    ) -> Result<()> {
        self.write_terminal_messages(budget, writer, limits, None)
    }

    pub(in crate::advanced) fn terminal_valid(&self) -> bool {
        self.outcome.valid()
    }

    pub(in crate::advanced) fn set_terminal(&mut self, valid: bool) {
        self.step = MessageStep::Done;
        self.activity = NativeActivity::Closed;
        self.outcome = if valid {
            MessageOutcome::Nominal
        } else {
            MessageOutcome::Invalid
        };
    }

    pub(in crate::advanced) fn write_terminal_messages(
        &self,
        _budget: &Arc<Budget>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
        processed: Option<usize>,
    ) -> Result<()> {
        use super::super::record::{Message, MessageState, Messages, NonceOrigin};
        if self.pending()
            || self.outcome.closing()
            || !self.outcome.valid() && !self.input.incremental && processed.is_none()
            || self.step == MessageStep::Failed
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::SignatureCheckpointUnavailable,
            )));
        }
        if self.input.incremental {
            return self.write_stream_messages(writer, limits);
        }
        let outputs = &self
            .signatures
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultsAbsent,
            )))?
            .bytes;
        if self.inputs.len() != self.layouts.len() || outputs.len() != self.inputs.len() {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::SignatureCheckpointShape,
            )));
        }
        Messages::write_generated_with_output(
            writer,
            self.inputs.len(),
            limits,
            self.output_record(),
            |i| {
                let parts = self.layouts[i].fragments(&self.inputs[i], self.route)?;
                let output = &outputs[i];
                let (state, next_fragment) = match self.dispatch_step() {
                    MessageStep::Done if processed.is_some_and(|n| i >= n) => {
                        (MessageState::Planned, 0)
                    }
                    MessageStep::Finish | MessageStep::Done => {
                        (MessageState::Finished, parts.len())
                    }
                    MessageStep::Single(current)
                    | MessageStep::Begin(current)
                    | MessageStep::Next(current, _)
                        if i < current =>
                    {
                        (MessageState::Finished, parts.len())
                    }
                    MessageStep::Next(current, fragment) if i == current => {
                        (MessageState::Engaged, fragment)
                    }
                    _ => (MessageState::Planned, 0),
                };
                let result = if !self.verify && state == MessageState::Finished {
                    output.as_slice()
                } else {
                    &[]
                };
                let signature = if self.verify || state == MessageState::Finished {
                    Some(output.as_slice())
                } else {
                    None
                };
                Ok(Message {
                    route: self.route,
                    params: self.record_parameters()?,
                    origin: NonceOrigin::None,
                    state,
                    fragments: parts,
                    next_fragment,
                    produced: result.len(),
                    expected: if self.verify { 0 } else { output.capacity() },
                    result,
                    tag_or_signature: signature,
                    residual_start: 0,
                    residual_length: 0,
                })
            },
        )
    }

    pub(in crate::advanced) fn restore_keys(
        &self,
        session: &Session,
        keys: StateRestoreKeys<'_>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut restoration_keys::BoundKeys,
    ) -> Result<()> {
        if keys.encryption.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::UnexpectedRestorationEncryptionKey,
            )));
        }
        let key = keys.authentication.ok_or(Error::Rejected(
            crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::RestorationAuthenticationKeyRequired,
            ),
        ))?;
        if let Some(parameters) = &self.pss {
            let bits = match (self.verify, key.reference) {
                (false, StateKeyReference::Signing(k)) => {
                    k.message_pss_bits(parameters.selection)?
                }
                (true, StateKeyReference::Verification(k)) => {
                    k.message_pss_bits(parameters.selection)?
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::RestoreRsaReferenceRole,
                    )))
                }
            };
            if (bits / 8 + usize::from(bits % 8 != 0)) != self.size {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::RestoreRsaSize,
                )));
            }
        } else {
            key.symmetric(self.mechanism.mechanism)?;
        }
        let lease = self.key.rebind_selected_retained(
            session,
            key.reference,
            self.mechanism.mechanism,
            self.pss.as_ref().map(|p| p.selection),
            permits,
            &mut bound.authentication,
        )?;
        bound.native_authentication = match key.encoding {
            crate::advanced::StateKeyEncoding::Supplied => lease.handle,
            crate::advanced::StateKeyEncoding::Embedded => fe11_sys::CK_INVALID_HANDLE,
        };
        bound.authentication = Some(lease);
        Ok(())
    }

    /// Return the previous lease for destruction after restore possession ends.
    pub(in crate::advanced) fn bind_restored(
        &mut self,
        mut keys: restoration_keys::BoundKeys,
    ) -> restoration_keys::BoundKeys {
        let replacement = keys
            .authentication
            .take()
            .expect("validated restoration authentication key");
        keys.authentication = Some(std::mem::replace(&mut self.key, replacement));
        keys
    }

    pub(in crate::advanced) fn complete(&self) -> bool {
        self.step == MessageStep::Done
    }

    pub(in crate::advanced) fn result(
        &mut self,
        _entry: &SessionEntry,
    ) -> Result<OperationProgress> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageNotComplete,
            )));
        }
        if self.outcome.closing() {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageResultWithheldAfterFailure,
            )));
        }
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if self.verify
            && self
                .signatures
                .as_ref()
                .is_some_and(|results| results.rejections.iter().any(Option::is_some))
        {
            let results = self.signatures.take().ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageAlreadyPublished,
                ),
            ))?;
            Ok(OperationProgress::MessageVerificationDetails(
                MessageVerificationDetails {
                    results,
                    invalid_seen: !self.outcome.valid(),
                },
            ))
        } else if self.verify {
            Ok(OperationProgress::MessageVerification(
                if self.outcome.valid() {
                    Verification::Valid
                } else {
                    Verification::Invalid
                },
            ))
        } else {
            let signatures = self.signatures.take().ok_or(Error::Rejected(
                crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageAlreadyPublished,
                ),
            ))?;
            self.input.progress.delivered_bytes = self.input.progress.output_bytes;
            Ok(OperationProgress::MessageSignatures(signatures))
        }
    }

    /// Borrow only the current call's operands. The owner, not the call view,
    /// retains them across Pending or an uncertain return. No allocation,
    /// validation with side effects, or selection of another route occurs here.
    pub(super) fn call(
        &mut self,
        selected: resolved_call::Call,
        input_length: CK_ULONG,
    ) -> dispatch::Call<'_> {
        match selected {
            resolved_call::Call::Init(native) => dispatch::Call::Init {
                native,
                mechanism: &mut *self.mechanism,
                key: self.key.handle,
            },
            resolved_call::Call::Begin(native) => dispatch::Call::Begin {
                native,
                parameters: None,
            },
            resolved_call::Call::Data {
                native,
                index: i,
                part,
                last,
            } => {
                let signature = match native {
                    resolved_call::SignatureFunction::Verify(native) => {
                        dispatch::Signature::Verify {
                            native,
                            signature: if last {
                                Some((
                                    self.signatures.as_mut().unwrap().bytes[i].as_mut(),
                                    *self.lengths[i],
                                ))
                            } else {
                                None
                            },
                        }
                    }
                    resolved_call::SignatureFunction::Sign(native) => {
                        dispatch::Signature::Produce {
                            native,
                            output: if last {
                                Some((
                                    self.signatures.as_mut().unwrap().bytes[i].as_mut(),
                                    &mut *self.lengths[i],
                                ))
                            } else {
                                None
                            },
                        }
                    }
                };
                dispatch::Call::Data {
                    parameters: None,
                    input: Some(if self.input.incremental {
                        self.stream_fragment
                            .as_mut()
                            .expect("prepared current message fragment")
                            .as_mut()
                    } else {
                        self.inputs[i][part].as_mut()
                    }),
                    input_length,
                    signature,
                }
            }
            resolved_call::Call::Final(native) => dispatch::Call::Final { native },
        }
    }

    pub(super) fn current_input_bytes(&self) -> Result<Option<usize>> {
        if self.input.incremental {
            return match self.dispatch_step() {
                MessageStep::Single(_)
                | MessageStep::StreamUpdate(_)
                | MessageStep::StreamLast(_) => self
                    .stream_fragment
                    .as_ref()
                    .map(|fragment| Some(fragment.capacity()))
                    .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::CurrentMessageFragmentAbsent,
                    ))),
                _ => Ok(None),
            };
        }
        Ok(match self.dispatch_step() {
            MessageStep::Single(message) => Some(self.inputs[message][0].capacity()),
            MessageStep::Next(message, part) => Some(self.inputs[message][part].capacity()),
            MessageStep::StreamUpdate(_) | MessageStep::StreamLast(_) => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::StreamPhaseOnBufferedMessage,
                )))
            }
            _ => None,
        })
    }

    pub(super) fn signature_capacity(&self, message: usize) -> Result<usize> {
        self.signatures
            .as_ref()
            .and_then(|signatures| signatures.bytes.get(message))
            .map(Buffer::capacity)
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageSignatureStorageAbsent,
            )))
    }

    pub(super) fn terminal_message(&self) -> Option<usize> {
        match self.dispatch_step() {
            MessageStep::Single(i) | MessageStep::StreamLast(i) => Some(i),
            MessageStep::Next(i, j) if j + 1 == self.inputs[i].len() => Some(i),
            _ => None,
        }
    }

    pub(in crate::advanced) fn next_function(&self) -> Result<Option<&'static str>> {
        if matches!(self.step, MessageStep::Ready | MessageStep::Receive(_)) {
            Ok(None)
        } else {
            self.function().map(Some)
        }
    }

    pub(in crate::advanced) fn function(&self) -> Result<&'static str> {
        Ok(match (self.verify, self.dispatch_step()) {
            (false, MessageStep::Init) => "C_MessageSignInit",
            (true, MessageStep::Init) => "C_MessageVerifyInit",
            (false, MessageStep::Single(_)) => "C_SignMessage",
            (true, MessageStep::Single(_)) => "C_VerifyMessage",
            (false, MessageStep::Begin(_)) => "C_SignMessageBegin",
            (true, MessageStep::Begin(_)) => "C_VerifyMessageBegin",
            (
                false,
                MessageStep::Next(..) | MessageStep::StreamUpdate(_) | MessageStep::StreamLast(_),
            ) => "C_SignMessageNext",
            (
                true,
                MessageStep::Next(..) | MessageStep::StreamUpdate(_) | MessageStep::StreamLast(_),
            ) => "C_VerifyMessageNext",
            (false, MessageStep::Finish) => "C_MessageSignFinal",
            (true, MessageStep::Finish) => "C_MessageVerifyFinal",
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageNotActive,
                )))
            }
        })
    }

    pub(in crate::advanced) fn observation_allowed(&self) -> bool {
        // A negative verification remains a completed, explicitly invalid
        // result; its native flags are observations, never authentication.
        !matches!(self.outcome, MessageOutcome::ClosingFailure(_))
            && self.step != MessageStep::Failed
            && self.buffer_request().is_none()
    }

    pub(in crate::advanced) fn message_count(&self) -> usize {
        self.inputs.len()
    }

    pub(in crate::advanced) fn validation_point(&self) -> Result<Option<validation::Point>> {
        let index = self.terminal_message();
        if self.observation_allowed() && (index.is_some() || self.step == MessageStep::Finish) {
            Ok(Some(validation::Point {
                function: self.function()?,
                message_index: index,
            }))
        } else {
            Ok(None)
        }
    }

    pub(in crate::advanced) fn pending(&self) -> bool {
        self.activity.pending()
    }

    pub(in crate::advanced) fn joined_capacity(&self) -> Result<Option<usize>> {
        if !self.pending() {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageOperationNotJoinable,
            )));
        }
        self.function()?;
        Ok(if self.verify {
            None
        } else {
            self.terminal_message()
                .map(|message| self.signature_capacity(message))
                .transpose()?
        })
    }

    pub(in crate::advanced) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        self.joined_capacity()?;
        let name = self.function()?;
        self.activity = NativeActivity::Active;
        if let Err(error) = self.key.check(entry) {
            self.step = MessageStep::Failed;
            return Err(error);
        }
        let index = if self.verify {
            None
        } else {
            self.terminal_message()
        };
        let target = index.map(|i| self.signatures.as_mut().unwrap().bytes[i].as_mut());
        let observed = result.observed;
        let (_, length) = match result.project(name, target) {
            Ok(value) => value,
            Err(error) => {
                self.step = MessageStep::Failed;
                s.native.mark_uncertain();
                return Err(error);
            }
        };
        if let (Some(i), Some(length)) = (index, length) {
            *self.lengths[i] = length as CK_ULONG;
        }
        self.finish_step(
            s,
            entry,
            crate::native_return::protocol::PendingInspection::forwarded(observed),
            CompletionSource::Observation,
        )
    }

    pub(in crate::advanced) fn active_categories(&self) -> CK_FLAGS {
        if self.activity.locally_retirable() {
            0
        } else if self.verify {
            CKF_MESSAGE_VERIFY
        } else {
            CKF_MESSAGE_SIGN
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for MacOperation {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        super::super::key_roles::Roles::retain_unique(self.key.writer_roles(), [], retained)?;
        self.key.retain_credits(retained)?;
        self.released.retain_credits(retained)?;
        self.stream_fragment.retain_credits(retained)?;
        self.inputs.retain_credits(retained)?;
        self.layouts.retain_credits(retained)?;
        self.signatures.retain_credits(retained)?;
        self._metadata.retain_credits(retained)?;
        Ok(())
    }
}
