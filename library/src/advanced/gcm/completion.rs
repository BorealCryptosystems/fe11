// SPDX-License-Identifier: Apache-2.0
//! Validate returned AEAD parameters and publish message completion.
//! Nonce observations, output release and descriptor failures remain distinct facts.

use super::*;

impl GeneratedNonce {
    pub(super) fn as_ref(&self) -> Option<&Buffer> {
        match self {
            Self::Observed(bytes) => Some(bytes),
            Self::NotGenerated | Self::Awaiting(_) => None,
        }
    }
}

pub(super) fn observe_generated_nonce(observed: &mut GeneratedNonce, nonce: &[u8]) -> Result<()> {
    match observed {
        GeneratedNonce::Observed(prior) => {
            if prior.as_slice() != nonce {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageGeneratedNonceChanged,
                )));
            }
        }
        GeneratedNonce::Awaiting(storage) => {
            if storage.capacity() != nonce.len() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadMessageGeneratedNonceLength,
                )));
            }
            storage.as_mut().copy_from_slice(nonce);
            let GeneratedNonce::Awaiting(storage) =
                std::mem::replace(observed, GeneratedNonce::NotGenerated)
            else {
                unreachable!("matched awaiting storage")
            };
            *observed = GeneratedNonce::Observed(storage);
        }
        GeneratedNonce::NotGenerated => {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageUnexpectedGeneratedNonce,
            )));
        }
    }
    Ok(())
}

// Compatibility outputs use the same sequence owner and are copied only into
// storage admitted before Init. No native operation is repeated to publish them.
pub(super) fn complete_single_message(
    session: &Session,
    key: MessageKey<'_>,
    request: Request<'_>,
    kind: CipherKind,
    decrypt: bool,
    route: MessageRoute,
    limits: crate::InputLimits,
    init: MessageInitLayout,
    retained_metadata: usize,
    message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
) -> Result<(Buffer, Buffer, Credit)> {
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::SynchronousMessageFacadeRequiresSynchronousSession,
        )));
    }
    let bytes = request
        .data_len()?
        .checked_add(if decrypt {
            0
        } else {
            request.nonce.tag_bytes()?
        })
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadCompatibilityOutputLength,
        )))?;
    let requests = [request];
    let diagnostics = message_diagnostics;
    let (mut ticket, retained, held) = start_shared_messages(
        session,
        key,
        Requests::Prepared {
            kind,
            decrypt,
            entries: &requests,
        },
        route,
        limits,
        init,
        OperationPacing::Eager,
        false,
        InputAccounting::LegacySingle,
        Some((bytes, retained_metadata)),
        diagnostics,
    )?;
    let result = (|| {
        let (mut bytes, credit) = retained.expect("compatibility storage admitted before Init");
        let mut released = crate::advanced::poll::ReleasedInputs::default();
        let access = session.advanced_access()?;
        let progress = poll::poll_with_access(
            session,
            &mut ticket,
            &access,
            OperationPacing::Eager,
            &mut released,
        )?;
        let mut outputs = match progress {
            OperationProgress::CcmCiphertexts(x) => x.0,
            OperationProgress::CcmPlaintexts(x) => x.0,
            OperationProgress::GcmCiphertexts(x) => x.0,
            OperationProgress::GcmPlaintexts(x) => x.0,
            OperationProgress::StreamAeadCiphertexts(x) => x.0,
            OperationProgress::StreamAeadPlaintexts(x) => x.0,
            OperationProgress::CcmInvalidCiphertext(x) => {
                return Err(Error::Native {
                    function: x.function,
                    code: x.code,
                    may_have_effect: true,
                })
            }
            OperationProgress::InvalidCiphertext(x) => {
                return Err(Error::Native {
                    function: x.function,
                    code: x.code,
                    may_have_effect: true,
                })
            }
            OperationProgress::StreamAeadInvalidCiphertext(x) => {
                return Err(Error::Native {
                    function: x.function,
                    code: x.code,
                    may_have_effect: true,
                })
            }
            OperationProgress::CipherBufferRequired(request) => {
                return Err(Error::CipherBufferRequired(request));
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::SynchronousMessageSequenceDidNotComplete,
                )))
            }
        };
        // These result variants are published only after a successful native
        // process Final. Preserve that effect if local publication fails.
        let publication = (|| {
            if outputs.entries.len() != 1 {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::SingleMessageResultCount,
                )));
            }
            let output = outputs.entries.pop().unwrap();
            let data = output.bytes.as_slice();
            let tag = if decrypt {
                &[][..]
            } else {
                output.tag.as_slice()
            };
            let length = data.len().checked_add(tag.len()).ok_or(Error::Rejected(
                crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::MessageResultLengthOverflow,
                ),
            ))?;
            if length > bytes.capacity() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::MessageResultExceedsAdmittedCapacity,
                )));
            }
            bytes.as_mut()[..data.len()].copy_from_slice(data);
            bytes.as_mut()[data.len()..length].copy_from_slice(tag);
            bytes.set_length(length)?;
            Ok((bytes, output.nonce, credit))
        })();
        diagnostics
            .as_mut()
            .expect("AEAD diagnostics installed")
            .publication
            .as_mut()
            .expect("single-result publication diagnostic")
            .take()?
            .finish(publication)
    })();
    result.map_err(|error| {
        ticket::retain_failure(
            session,
            &mut ticket,
            &held,
            error,
            &mut diagnostics
                .as_mut()
                .expect("AEAD diagnostics installed")
                .parking,
        )
    })
}

impl AeadMessageOperation {
    pub(in crate::advanced) fn complete(&self) -> bool {
        self.step == AeadStep::Done
    }

    pub(super) fn validate_returned_parameters(&mut self, i: usize, completed: bool) -> Result<()> {
        self.validate_binding()?;
        let frame = &mut self.frames[i];
        let out = &mut self.outputs.as_mut().unwrap().entries[i];
        match &self.init {
            InitBinding::WithoutParameters | InitBinding::Declared(_) => {
                Self::validate_frame(frame, &out.nonce, &out.tag, completed, self.decrypt)
            }
            InitBinding::Shared { nonce, tag, .. } => {
                Self::validate_frame(frame, nonce, tag, completed, self.decrypt)?;
                out.nonce.as_mut().copy_from_slice(nonce.as_slice());
                out.tag.as_mut().copy_from_slice(tag.as_slice());
                Ok(())
            }
        }
    }

    /// Keep the prior cleanup cause even when its observation, rather than
    /// its target graph, has an invalid boundary. Both leaves are prepaid.
    pub(super) fn return_boundary_failure(
        &mut self,
        s: &State,
        result: crate::native_return::protocol::ReturnCode,
        cause: Error,
    ) -> Error {
        let size = (self.output_index()).and_then(|index| {
            result.direct_output_size(
                self.outputs.as_ref().expect("retained AEAD output").entries[index]
                    .bytes
                    .capacity()
                    - self.frames[index].used,
                || *self.frames[index].length,
            )
        });
        self.activity = NativeActivity::Active;
        self.step = AeadStep::Failed;
        s.native.mark_uncertain();
        let error = if result.code() == CKR_OK {
            cause
        } else {
            self.return_diagnostic
                .take()
                .expect("one terminal AEAD boundary failure")
                .bind(result.function())
                .boundary_with_output(result.code(), size, cause)
        };
        if matches!(self.outcome, AeadOutcome::Closing { .. }) {
            let AeadOutcome::Closing { diagnostic, .. } =
                std::mem::replace(&mut self.outcome, AeadOutcome::Nominal)
            else {
                unreachable!()
            };
            diagnostic.finish_sequence(Some(error))
        } else {
            error
        }
    }

    pub(super) fn finish_step(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        returned: crate::native_return::protocol::PendingInspection,
        source: CompletionSource,
    ) -> Result<()> {
        let rv = returned.code();
        let name = returned.function();
        // Prepared capacity retains the call for capture until it is issued.
        // No successful byte accounting occurs on an insufficient-buffer return.
        self.step = self.dispatch_step();
        let output = self.output_index();
        let last = self.last();
        use crate::native_return::protocol::SequencePhase;
        use crate::native_return::sequence::{Completion, OutputRequest};
        let inspected = returned.inspect(|| self.inspect_returned_boundary(rv));
        let version = s.native.table.version;
        let phase = if self.step == AeadStep::Init {
            SequencePhase::Initialize
        } else {
            SequencePhase::Continue(OutputRequest::Buffer)
        };
        let initialization_refused =
            inspected.initialization_refused((version.major, version.minor), phase);
        let completion = inspected.completion((version.major, version.minor), phase);
        let result =
            inspected.resolve(|result, cause| self.return_boundary_failure(s, result, cause))?;
        self.activity = if initialization_refused {
            NativeActivity::InitializationRefused
        } else if completion == Completion::Terminated {
            NativeActivity::Closed
        } else {
            NativeActivity::Active
        };
        if self.step == AeadStep::Finish && matches!(self.outcome, AeadOutcome::Closing { .. }) {
            let AeadOutcome::Closing {
                diagnostic,
                mut rejection,
            } = std::mem::replace(&mut self.outcome, AeadOutcome::Nominal)
            else {
                unreachable!()
            };
            if self.activity == NativeActivity::Closed {
                if let Err(error) = self.validate_binding() {
                    self.activity = NativeActivity::Active;
                    self.step = AeadStep::Failed;
                    s.native.mark_uncertain();
                    return Err(diagnostic.finish_sequence(Some(error)));
                }
                // Final OK or already-inactive proves cleanup, never validity.
                self.step = AeadStep::Done;
                if let Some(ref mut rejected) = rejection {
                    rejected.cleanup_code = rv as u64;
                }
                if let Some(rejected) = rejection {
                    self.outcome = AeadOutcome::Rejected(rejected);
                    return Ok(());
                }
                self.step = AeadStep::Failed;
                return Err(diagnostic.finish_sequence(None));
            }
            self.step = AeadStep::Failed;
            self.poison_if_active(entry);
            return Err(diagnostic.finish_sequence(Some(Error::Native {
                function: name,
                code: rv as u64,
                may_have_effect: true,
            })));
        }
        // Every facade owns the same stable data-call operands. The source
        // of those bytes (queued list or caller-fed fragment) cannot change
        // the native insufficient-buffer continuation into implicit cleanup.
        if source == CompletionSource::Call && rv == fe11_sys::CKR_BUFFER_TOO_SMALL {
            if let Some(index) = output {
                if let Err(error) = self.validate_returned_parameters(index, false) {
                    self.step = AeadStep::Failed;
                    s.native.mark_uncertain();
                    return Err(error);
                }
                let frame = &self.frames[index];
                let request = super::super::CipherBufferRequest {
                    function: name,
                    code: rv as u64,
                    required: usize::try_from(*frame.length).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadNativeLengthWidth,
                        ))
                    })?,
                    previous_capacity: self
                        .outputs
                        .as_ref()
                        .expect("retained AEAD outputs")
                        .entries[index]
                        .bytes
                        .capacity()
                        .checked_sub(frame.used)
                        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadRetainedOutputRange,
                        )))?,
                };
                // PKCS#11 3.2 sections 5.2, 5.9 and 5.11 preserve this data
                // request. Keep its input, prefix and generated parameters;
                // neither cleanup nor a new native call is implicit here.
                self.step = AeadStep::Output(output::Pending::new(self.step, request)?);
                return Ok(());
            }
        }
        if rv != CKR_OK {
            let error = Error::Native {
                function: name,
                code: rv as u64,
                may_have_effect: crate::native_return::effect_uncertain(rv)
                    || !(self.step == AeadStep::Init && self.activity.locally_retirable()),
            };
            let ordinary = result.memory_returned()
                && crate::native_return::native_context_scope(rv)
                    == crate::native_return::FailureScope::None;
            if ordinary
                && matches!(
                    self.step,
                    AeadStep::Single(_)
                        | AeadStep::Begin(_)
                        | AeadStep::Next(..)
                        | AeadStep::StreamUpdate(_)
                        | AeadStep::StreamLast(_)
                )
            {
                if self.input.is_some() {
                    if rv == fe11_sys::CKR_BUFFER_TOO_SMALL {
                        // Only the direct data-call branch above establishes
                        // a retryable capacity request. An observation or a
                        // Begin return cannot silently become a new message.
                        self.step = AeadStep::Failed;
                        return Err(error);
                    }
                    let index = match self.step {
                        AeadStep::Single(index)
                        | AeadStep::Begin(index)
                        | AeadStep::StreamUpdate(index)
                        | AeadStep::StreamLast(index) => index,
                        _ => {
                            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                                crate::AeadMessagesRejection::AeadStreamRefusalPhase,
                            )))
                        }
                    };
                    // PKCS#11 3.2 §§5.9/5.11 distinguish this message from
                    // its initialized parent. Retain the exact refusal and
                    // allow only an explicit next message or parent Final.
                    if let Err(local) = self
                        .validate_returned_parameters(index, false)
                        .and_then(|()| self.refuse_message(name, rv as u64))
                    {
                        self.step = AeadStep::Failed;
                        s.native.mark_uncertain();
                        return Err(self
                            .input
                            .as_mut()
                            .expect("caller-fed AEAD failure owner")
                            .native_and_local_failure(name, rv as u64, local));
                    }
                    return Err(error);
                }
                let rejection = if self.decrypt
                    && output.is_some()
                    && matches!(
                        rv,
                        CKR_AEAD_DECRYPT_FAILED
                            | CKR_ENCRYPTED_DATA_INVALID
                            | CKR_ENCRYPTED_DATA_LEN_RANGE
                    ) {
                    Some(GcmRejection {
                        function: name,
                        code: rv as u64,
                        cleanup_code: 0,
                    })
                } else {
                    None
                };
                return self.begin_cleanup(error, rejection);
            }
            self.step = AeadStep::Failed;
            self.poison_if_active(entry);
            return Err(error);
        }
        let mut produced = 0usize;
        let validated = (|| {
            self.validate_binding()?;
            if self.step == AeadStep::Init {
                if let InitBinding::Shared { nonce, tag, .. } = &self.init {
                    let (origin, _, expected_tag) = self.init.reference(&self.frames)?;
                    let input_nonce = if self.decrypt {
                        nonce.as_slice() == origin.iv()
                    } else {
                        origin.fixed_bits_unchanged(nonce.as_slice())
                            && (origin.generated() || nonce.as_slice() == origin.iv())
                    };
                    if !input_nonce
                        || expected_tag
                            .is_some_and(|expected| tag.as_slice() != expected.as_slice())
                    {
                        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadMessageInitInputBytesMutation,
                        )));
                    }
                }
            }
            if let AeadStep::Begin(i) = self.step {
                self.validate_parameters(i)?;
            }
            if let Some(i) = output {
                self.validate_parameters(i)?;
                let frame = &mut self.frames[i];
                let output = &mut self.outputs.as_mut().unwrap().entries[i].bytes;
                produced = bounds::final_length(*frame.length, output.capacity() - frame.used)?;
                frame.used += produced;
                if last {
                    output.set_length(frame.used)?;
                }
            }
            Ok(())
        })();
        if let Err(e) = validated {
            // A binding or capacity violation is not a bounded semantic error.
            self.activity = NativeActivity::Active;
            s.native.mark_uncertain();
            self.step = AeadStep::Failed;
            return self
                .return_diagnostic
                .take()
                .expect("one terminal AEAD publication failure")
                .bind(name)
                .finish_native(rv, Err(e));
        }
        let semantic = if let (true, Some(index)) = (last, output) {
            self.terminal_input(index).and_then(|accepted| {
                let frame = &self.frames[index];
                if accepted.is_some_and(|bytes| bytes != frame.used as u128)
                    || self.kind == CipherKind::Ccm && frame.used != frame.expected
                {
                    Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                        crate::CipherContinuationRejection::CipherResultLengthOutsideMechanismContract,
                    )))
                } else { Ok(()) }
            })
        } else {
            Ok(())
        };
        // The native call accepted these bytes and returned bounded output even
        // if the terminal relation is inconsistent. Commit that observation and
        // retire returned operands exactly once before reporting the anomaly.
        self.complete_input(produced)?;
        self.retire_queued_success(last);
        if let Err(cause) = semantic {
            // The parent can remain active; this proves neither its closure nor
            // authentication. Its failed owner cannot publish or replay output.
            self.step = AeadStep::Failed;
            return self
                .return_diagnostic
                .take()
                .expect("one terminal AEAD publication failure")
                .bind(name)
                .finish_native(rv, Err(cause));
        }
        self.advance_after_success(last)
    }
}

impl crate::symmetric::memory::RetainedStorage for Frame {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.aad.retain_credits(retained)?;
        self.inputs.retain_credits(retained)?;
        self.retirement.retain_credits(retained)?;
        self.layout.retain_credits(retained)?;
        self.observed_nonce.retain_credits(retained)?;
        self.expected_tag.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for GeneratedNonce {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::NotGenerated => Ok(()),
            Self::Awaiting(bytes) | Self::Observed(bytes) => bytes.retain_credits(retained),
        }
    }
}
