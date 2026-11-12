// SPDX-License-Identifier: Apache-2.0
//! Advance signature messages and their cleanup after native returns.
//! Starting another message does not erase a boundary failure or an active sequence.

use super::*;

impl MacOperation {
    pub(super) fn start_message(&self, i: usize) -> MessageStep {
        if self.route == MessageRoute::Single {
            MessageStep::Single(i)
        } else {
            MessageStep::Begin(i)
        }
    }

    pub(super) fn after_message(&self, i: usize) -> MessageStep {
        if self.input.incremental {
            return MessageStep::Ready;
        }
        if self.outcome.valid() && i + 1 < self.inputs.len() {
            self.start_message(i + 1)
        } else {
            MessageStep::Finish
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
        let size = (if self.verify {
            None
        } else {
            self.terminal_message()
        })
        .and_then(|index| {
            result.direct_output_size(
                self.signatures
                    .as_ref()
                    .expect("retained signature output")
                    .bytes[index]
                    .capacity(),
                || *self.lengths[index],
            )
        });
        self.activity = NativeActivity::Active;
        self.step = MessageStep::Failed;
        s.native.mark_uncertain();
        let error = if result.code() == CKR_OK {
            cause
        } else {
            self.completion_diagnostic
                .take()
                .expect("one terminal message boundary failure")
                .bind(result.function())
                .boundary_with_output(result.code(), size, cause)
        };
        // A damaged cleanup return must retain the earlier message failure
        // as well as its native/local cleanup causes, including async paths.
        if self.outcome.closing() {
            let outcome = std::mem::replace(&mut self.outcome, MessageOutcome::Nominal);
            let diagnostic = match outcome {
                MessageOutcome::ClosingInvalid(d) | MessageOutcome::ClosingFailure(d) => d,
                _ => unreachable!(),
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
        use crate::native_return::protocol::SequencePhase;
        use crate::native_return::sequence::{Completion, OutputRequest};
        let inspected = returned.inspect(|| {
            if self.mechanism.mechanism != self.kind
                || self.pss.is_none()
                    && (!self.mechanism.pParameter.is_null() || self.mechanism.ulParameterLen != 0)
            {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::MessageNativeParameterIdentity,
                )));
            }
            if let Some(pss) = &mut self.pss {
                if self.mechanism.mechanism
                    != pss
                        .selection
                        .mechanism(crate::HashExecution::Pkcs11Combined)?
                    || self.mechanism.pParameter
                        != (&mut **pss as *mut CK_RSA_PKCS_PSS_PARAMS).cast()
                    || self.mechanism.ulParameterLen
                        != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG
                    || !pss.unchanged()?
                {
                    return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::PssNativeParameterIdentity,
                    )));
                }
            }
            if rv == CKR_OK && !self.verify {
                if let Some(message) = self.terminal_message() {
                    bounds::final_length(
                        *self.lengths[message],
                        self.signature_capacity(message)?,
                    )?;
                }
            }
            Ok(())
        });
        let version = s.native.table.version;
        let phase = if self.step == MessageStep::Init {
            SequencePhase::Initialize
        } else {
            SequencePhase::Continue(OutputRequest::Buffer)
        };
        let initialization_refused =
            inspected.initialization_refused((version.major, version.minor), phase);
        let completion = inspected.completion((version.major, version.minor), phase);
        let result =
            inspected.resolve(|result, cause| self.return_boundary_failure(s, result, cause))?;
        if !result.memory_returned() {
            // The module may still own every pointer of this call. In
            // particular, descriptor witnesses cannot be read to diagnose an
            // uncertain return. Retain the operation until proven closure.
            self.activity = NativeActivity::Active;
            self.step = MessageStep::Failed;
            s.native.mark_uncertain();
            self.poison_if_active(entry);
            return Err(Error::Native {
                function: name,
                code: rv as u64,
                may_have_effect: true,
            });
        }
        let terminal = self.terminal_message();
        self.activity = if initialization_refused {
            NativeActivity::InitializationRefused
        } else if completion == Completion::Terminated {
            NativeActivity::Closed
        } else {
            NativeActivity::Active
        };
        if self.step == MessageStep::Finish && self.outcome.closing() {
            let outcome = std::mem::replace(&mut self.outcome, MessageOutcome::Nominal);
            let (diagnostic, invalid) = match outcome {
                MessageOutcome::ClosingInvalid(d) => (d, true),
                MessageOutcome::ClosingFailure(d) => (d, false),
                _ => unreachable!(),
            };
            if self.activity.inactive() {
                if invalid {
                    self.outcome = MessageOutcome::Invalid;
                    self.step = MessageStep::Done;
                    return Ok(());
                }
                self.step = MessageStep::Failed;
                return Err(diagnostic.finish_sequence(None));
            }
            self.step = MessageStep::Failed;
            self.poison_if_active(entry);
            return Err(diagnostic.finish_sequence(Some(Error::Native {
                function: name,
                code: rv as u64,
                may_have_effect: true,
            })));
        }
        if source == CompletionSource::Call && !self.verify && rv == fe11_sys::CKR_BUFFER_TOO_SMALL
        {
            if let Some(message) = terminal {
                let request = super::super::SignatureBufferRequest {
                    function: name,
                    code: rv as u64,
                    required: usize::try_from(*self.lengths[message]).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageNativeLengthWidth,
                        ))
                    })?,
                    previous_capacity: self.signature_capacity(message)?,
                };
                let pending = output::Pending::new(self.step, request)?;
                // PKCS#11 preserves this terminal data call on BUFFER_TOO_SMALL.
                // Its input remains owned and unconsumed. Poll carries the
                // old output outside possession before erasure/credit release;
                // replacement admission need not hold both output allocations.
                assert!(
                    self.released.signature.is_none(),
                    "message output retirement pending"
                );
                self.released.signature = Some(
                    self.signatures
                        .as_mut()
                        .expect("retained message output")
                        .bytes[message]
                        .take(),
                );
                self.step = MessageStep::Output(pending);
                return Ok(());
            }
        }
        if rv != CKR_OK {
            let error = Error::Native {
                function: name,
                code: rv as u64,
                may_have_effect: crate::native_return::effect_uncertain(rv)
                    || !(self.step == MessageStep::Init && self.activity.locally_retirable()),
            };
            let ordinary = result.memory_returned()
                && crate::native_return::native_context_scope(rv)
                    == crate::native_return::FailureScope::None;
            if ordinary
                && matches!(
                    self.step,
                    MessageStep::Single(_)
                        | MessageStep::Begin(_)
                        | MessageStep::Next(..)
                        | MessageStep::StreamUpdate(_)
                        | MessageStep::StreamLast(_)
                )
            {
                let invalid = self.verify
                    && terminal.is_some()
                    && matches!(rv, CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE);
                if invalid {
                    // The refused data call has returned; it is no longer a
                    // retained submission. Keep its issued ordinal, without
                    // counting its input bytes as successfully consumed.
                    self.input.retained_submission = false;
                    if self.input.incremental {
                        // An invalid message is a native result, not an
                        // implicit request to finish the parent's process.
                        // Preserve its cumulative verdict while permitting
                        // the caller to submit another message or Final.
                        let message = terminal.expect("terminal verification refusal");
                        self.retire_stream_input(Some(message));
                        self.outcome = MessageOutcome::Invalid;
                        self.step = MessageStep::Ready;
                        return Ok(());
                    }
                }
                if self.input.incremental {
                    if !self.verify && terminal.is_some() && rv == fe11_sys::CKR_BUFFER_TOO_SMALL {
                        // Direct capacity negotiation was handled above. A
                        // completion observation cannot invent another size
                        // negotiation or establish that this message ended.
                        self.step = MessageStep::Failed;
                        return Err(error);
                    }
                    // A returned message error ends this row, not its parent.
                    // Retain output allocations and native length cells, but
                    // exclude this row from signature and verdict publication.
                    let message = match self.step {
                        MessageStep::Single(index)
                        | MessageStep::Begin(index)
                        | MessageStep::StreamUpdate(index)
                        | MessageStep::StreamLast(index) => index,
                        _ => unreachable!("caller-fed message refusal"),
                    };
                    self.signatures
                        .as_mut()
                        .expect("retained message results")
                        .rejections[message] = Some(crate::NativeMessageRejection {
                        function: name,
                        code: rv as u64,
                    });
                    self.input.retained_submission = false;
                    self.retire_stream_input(if self.verify { terminal } else { None });
                    self.step = MessageStep::Ready;
                    return Err(error);
                }
                return self.begin_cleanup(error, invalid);
            }
            self.step = MessageStep::Failed;
            self.poison_if_active(entry);
            return Err(error);
        }
        if !self.verify {
            if let Some(i) = terminal {
                let capacity = self.signature_capacity(i)?;
                let length = match bounds::final_length(*self.lengths[i], capacity) {
                    Ok(length) => length,
                    Err(error) => {
                        self.activity = NativeActivity::Active;
                        s.native.mark_uncertain();
                        self.step = MessageStep::Failed;
                        return Err(error);
                    }
                };
                // Capacity is a storage bound, not a cryptographic acceptance
                // rule. Publish only the prefix established by the module.
                self.signatures.as_mut().unwrap().bytes[i].set_length(length)?;
            }
        }
        // Only an established successful data return consumes the fragment.
        // Init/Begin/parent Final do not contribute fictitious submissions.
        if let Some(bytes) = self.current_input_bytes()? {
            let mut completed = self.input.accepted(bytes, false)?;
            if !self.verify {
                if let Some(message) = terminal {
                    completed = completed.produced(bounds::final_length(
                        *self.lengths[message],
                        self.signature_capacity(message)?,
                    )?)?;
                }
            }
            self.input = completed;
            if self.input.incremental {
                // Do not erase input or notify its budget under possession.
                // A completed expected signature has the same retirement path.
                self.retire_stream_input(if self.verify { terminal } else { None });
            }
        }
        self.step = match self.step {
            MessageStep::Init if self.input.incremental => MessageStep::Ready,
            MessageStep::Init => self.start_message(0),
            MessageStep::Single(i) => self.after_message(i),
            MessageStep::Begin(i) if self.input.incremental => MessageStep::Receive(i),
            MessageStep::Begin(i) => MessageStep::Next(i, 0),
            MessageStep::StreamUpdate(i) => MessageStep::Receive(i),
            MessageStep::StreamLast(_) => MessageStep::Ready,
            MessageStep::Next(i, _) if terminal.is_some() => self.after_message(i),
            MessageStep::Next(i, j) => MessageStep::Next(i, j + 1),
            MessageStep::Finish => MessageStep::Done,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                    crate::SignatureMessagesRejection::DuplicateMessageCompletion,
                )))
            }
        };
        Ok(())
    }

    pub(super) fn begin_cleanup(&mut self, error: Error, invalid: bool) -> Result<()> {
        if matches!(error.without_object_marker(), Error::CleanupFailed { .. }) {
            return Err(error);
        }
        // Native failure cannot acquire memory needed by its own cleanup.
        // Metadata owns these leaves even after the outcome is published.
        let mut diagnostic = self
            .cleanup_diagnostic
            .take()
            .expect("one terminal message cleanup");
        diagnostic.replace_operation(error);
        self.outcome = if invalid {
            MessageOutcome::ClosingInvalid(diagnostic)
        } else {
            MessageOutcome::ClosingFailure(diagnostic)
        };
        self.step = MessageStep::Finish;
        Ok(())
    }

    fn poison_if_active(&self, entry: &SessionEntry) {
        if !self.activity.locally_retirable() {
            entry.poisoned.store(true, Ordering::Release);
        }
    }

    pub(in crate::advanced) fn initialization_refused(&self) -> bool {
        self.activity == NativeActivity::InitializationRefused
    }

    pub(in crate::advanced) fn native_inactive(&self) -> bool {
        self.activity.inactive()
    }

    pub(in crate::advanced) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        match self.drive_inner(s, entry, observe, remaining) {
            Err(error) if self.outcome.closing() => {
                let outcome = std::mem::replace(&mut self.outcome, MessageOutcome::Nominal);
                let diagnostic = match outcome {
                    MessageOutcome::ClosingInvalid(d) | MessageOutcome::ClosingFailure(d) => d,
                    _ => unreachable!(),
                };
                self.step = MessageStep::Failed;
                Err(diagnostic.finish_sequence(Some(error)))
            }
            result => result,
        }
    }

    pub(super) fn drive_inner(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.step == MessageStep::Failed {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageFailedExplicitCleanupRequired,
            )));
        }
        self.key.check(entry)?;
        if self.pending() {
            if !observe || !spend(remaining) {
                return Ok(());
            }
            let name = self.function()?;
            let output = if self.verify {
                None
            } else {
                self.terminal_message()
            };
            let call = s
                .native
                .asynchronous
                .and_then(|f| f.complete)
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
                )))?;
            self.name.fill(0);
            self.name[..name.len()].copy_from_slice(name.as_bytes());
            let result = if output.is_some() {
                &mut *self.completion as *mut CK_ASYNC_DATA
            } else {
                std::ptr::null_mut()
            };
            s.native.record("C_AsyncComplete")?;
            // SAFETY: the observation storage and name belong to the installed frame.
            let rv = unsafe { call(entry.handle, self.name.as_mut_ptr(), result) };
            let observed =
                crate::native_return::protocol::PendingInspection::completed(name, rv, |scope| {
                    s.native.observe_async_return(rv);
                    if rv != CKR_PENDING {
                        s.apply_session_failure(entry, rv, scope);
                    }
                })
                .inspect(|| {
                    if let Some(index) = output {
                        let pointer = self.signatures.as_mut().unwrap().bytes[index]
                            .as_mut()
                            .as_mut_ptr()
                            .cast();
                        if self.completion.ulVersion != 0
                            || self.completion.pValue != pointer
                            || rv == CKR_OK
                                && self.completion.ulValue as u128
                                    > self.signature_capacity(index)? as u128
                        {
                            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageAsynchronousResultIdentity,
                        )));
                        }
                    }
                    Ok(())
                })
                .resolve(|result, cause| self.return_boundary_failure(s, result, cause))?;
            if rv == CKR_PENDING {
                return Ok(());
            }
            if rv == CKR_OK {
                if let Some(i) = output {
                    let pointer = self.signatures.as_mut().unwrap().bytes[i]
                        .as_mut()
                        .as_mut_ptr()
                        .cast();
                    if self.completion.ulVersion != 0
                        || self.completion.pValue != pointer
                        || self.completion.ulValue as u128 > self.signature_capacity(i)? as u128
                    {
                        s.native.mark_uncertain();
                        self.step = MessageStep::Failed;
                        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageAsynchronousResultIdentity,
                        )));
                    }
                    *self.lengths[i] = self.completion.ulValue;
                }
            }
            self.activity = NativeActivity::Active;
            self.finish_step(
                s,
                entry,
                crate::native_return::protocol::PendingInspection::forwarded(observed),
                CompletionSource::Observation,
            )?;
        }
        while !matches!(self.step, MessageStep::Done | MessageStep::Failed) {
            if matches!(self.step, MessageStep::Ready | MessageStep::Receive(_))
                || self.buffer_request().is_some()
                || !spend(remaining)
            {
                return Ok(());
            }
            self.key.check(entry)?;
            if s.native.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            let name = self.function()?;
            let f =
                s.native
                    .messages
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::MessageInterfaceUnavailable,
                    )))?;
            let native_call = resolved_call::Call::resolve(
                f,
                self.verify,
                self.dispatch_step(),
                self.terminal_message().is_some(),
            )?;
            // Resolve fallible ABI dimensions before counting or arming the
            // native call. Init, Begin and Final do not consume an input span.
            let input_length = self
                .current_input_bytes()?
                .map(bounds::ck_length)
                .transpose()?
                .unwrap_or(0);
            // Compute progress bounds before C. A retained native call is not
            // another submission when completion is later observed or joined.
            let submission = self
                .current_input_bytes()?
                .map(|bytes| self.input.submission(bytes, false))
                .transpose()?;
            if !self.verify {
                if let Some(message) = self.terminal_message() {
                    submission
                        .as_ref()
                        .map_or(self.input, |next| next.completed)
                        .produced(self.signature_capacity(message)?)?;
                }
            }
            s.native.record(name)?;
            if let Some(submission) = submission {
                self.input = submission.issued;
            }
            self.activity = NativeActivity::Active;
            // Prepared replacement storage is not a new input submission.
            // Drop only its logical wait marker at the actual dispatch point;
            // captures before this point still describe the retained call.
            self.step = self.dispatch_step();
            // SAFETY: inputs, outputs, lengths and mechanism are stable owned
            // allocations installed before Init. Intermediate Next uses null
            // signature/length as specified; no caller pointer is retained.
            let rv = unsafe { self.call(native_call, input_length).invoke(entry.handle) };
            if rv == CKR_PENDING {
                self.activity = NativeActivity::Pending;
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
                CompletionSource::Call,
            )?;
        }
        Ok(())
    }
}
