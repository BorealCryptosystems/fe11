// SPDX-License-Identifier: Apache-2.0
//! Synchronous message calls with explicit caller-input and capacity boundaries.
use super::{
    invalid, CapacityStorage, DataKind, Execution, MessageOutput, NativeMessageOperation, Phase,
};
use crate::advanced::{spend, NativeActivity, SignatureBufferRequest};
use crate::module::{SessionEntry, State};
use crate::{bounds, Error, MessageRoute, Result};
use fe11_sys::*;
use std::sync::atomic::Ordering;

pub(super) fn functions(
    state: &State,
    verify: bool,
    route: MessageRoute,
) -> Result<crate::interfaces::MessageFunctions> {
    let functions = state.native.messages.ok_or(Error::Unsupported(
        crate::UnsupportedReason::NativeMessages(
            crate::NativeMessagesUnsupported::MessageInterface,
        ),
    ))?;
    let present = if verify {
        functions.verify_init.is_some()
            && functions.verify_finish.is_some()
            && match route {
                MessageRoute::Single => functions.verify_message.is_some(),
                MessageRoute::Multipart => {
                    functions.verify_begin.is_some() && functions.verify_next.is_some()
                }
            }
    } else {
        functions.sign_init.is_some()
            && functions.sign_finish.is_some()
            && match route {
                MessageRoute::Single => functions.sign_message.is_some(),
                MessageRoute::Multipart => {
                    functions.sign_begin.is_some() && functions.sign_next.is_some()
                }
            }
    };
    if present {
        Ok(functions)
    } else {
        Err(Error::Unsupported(
            crate::UnsupportedReason::NativeMessages(
                crate::NativeMessagesUnsupported::MessageSignatureFunctionTuple,
            ),
        ))
    }
}

impl NativeMessageOperation {
    /// Check every fallible projection before recording/revoking/issuing C.
    fn validate_operands(&self) -> Result<()> {
        match &self.phase {
            Phase::Init | Phase::Final => Ok(()),
            Phase::Begin(index) => {
                if self.route != MessageRoute::Multipart || *index >= self.messages.len() {
                    return Err(invalid());
                }
                Ok(())
            }
            Phase::Data(call)
            | Phase::Capacity {
                call,
                storage: CapacityStorage::Prepared,
                ..
            } => {
                let message = self.messages.get(call.message).ok_or_else(invalid)?;
                if call.part >= message.parts.len()
                    || (call.kind == DataKind::Single) != (self.route == MessageRoute::Single)
                    || call.signature.is_some() != (self.verify && call.kind.terminal())
                    || matches!(message.output, MessageOutput::Verify { .. }) != self.verify
                {
                    return Err(invalid());
                }
                if call.kind.terminal() && matches!(message.output, MessageOutput::Sign(None)) {
                    return Err(invalid());
                }
                if let MessageOutput::Sign(Some(output)) = &message.output {
                    output.capacity()?;
                }
                Ok(())
            }
            _ => Err(invalid()),
        }
    }

    fn terminal_index(&self) -> Option<usize> {
        self.data()
            .filter(|call| call.kind.terminal())
            .map(|call| call.message)
    }

    fn mutates_key(&self) -> Result<bool> {
        Ok(match &self.phase {
            Phase::Init => self.binding.primary.contract.mutates_key(),
            Phase::Begin(index) => self
                .messages
                .get(*index)
                .ok_or_else(invalid)?
                .begin
                .as_ref()
                .is_some_and(super::Parameters::mutates_key),
            Phase::Data(call)
            | Phase::Capacity {
                call,
                storage: CapacityStorage::Prepared,
                ..
            } => self
                .messages
                .get(call.message)
                .ok_or_else(invalid)?
                .parts
                .get(call.part)
                .ok_or_else(invalid)?
                .mutates_key(),
            _ => false,
        })
    }

    fn uncertain(&mut self, state: &State, entry: &SessionEntry, rv: CK_RV) {
        // Keep Phase intact: it owns the possibly borrowed input/signature.
        self.execution = Execution::Failed;
        self.activity = if rv == CKR_PENDING {
            NativeActivity::Pending
        } else {
            NativeActivity::Active
        };
        state.native.mark_uncertain();
        entry.poisoned.store(true, Ordering::Release);
    }

    pub(in crate::advanced) fn drive(
        &mut self,
        state: &State,
        entry: &SessionEntry,
        remaining: &mut usize,
    ) -> Result<()> {
        self.drive_inner(state, entry, remaining)
    }

    fn drive_inner(
        &mut self,
        state: &State,
        entry: &SessionEntry,
        remaining: &mut usize,
    ) -> Result<()> {
        if matches!(self.execution, Execution::Captured) {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::CapturedGenericMessageRequiresDestinationBinding,
            )));
        }
        if self.pending() || matches!(self.execution, Execution::Failed) {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageRequiresExplicitCleanup,
            )));
        }
        while let Some(function) = self.next_function() {
            self.binding.check(entry)?;
            if state.native.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            let functions = functions(state, self.verify, self.route)?;
            // Login and other allowed native calls may have touched retained
            // graphs since the prior dispatch. Recheck under possession before
            // giving any pointer back to C, not only after the next call.
            if !self.unchanged() {
                self.uncertain(state, entry, CKR_OK);
                return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                    crate::NativeMessagesRejection::GenericMessageRetainedInputMutation,
                )));
            }
            self.validate_operands()?;
            let native_call =
                super::resolved_call::Call::resolve(functions, self.verify, &self.phase)?;
            let mutates = self.mutates_key()?;
            if mutates && !self.binding.writer {
                return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                    crate::NativeMessagesRejection::MessageWriteRequiresItsDeclaredWriter,
                )));
            }
            let submission = self
                .data()
                .map(|call| self.input.submission(call.bytes.bytes().len(), false))
                .transpose()?;
            let terminal = self.terminal_index();
            if let Some(index) = terminal {
                if let MessageOutput::Sign(Some(output)) = &mut self.messages[index].output {
                    let capacity = output.capacity()?;
                    submission
                        .as_ref()
                        .map_or(self.input, |next| next.completed)
                        .produced(capacity)?;
                    *output.length = bounds::ck_length(capacity)?;
                }
            }
            if !spend(remaining) {
                return Ok(());
            }
            state.native.record(function)?;
            let initializing = matches!(self.phase, Phase::Init);
            if mutates {
                self.binding.primary.arm();
            }
            if let Some(submission) = &submission {
                self.input = submission.issued;
            }
            if matches!(
                self.phase,
                Phase::Capacity {
                    storage: CapacityStorage::Prepared,
                    ..
                }
            ) {
                let Phase::Capacity { call, .. } = std::mem::replace(&mut self.phase, Phase::Ready)
                else {
                    unreachable!()
                };
                self.phase = Phase::Data(call);
            }
            self.activity = NativeActivity::Active;
            // SAFETY: the complete tuple and all projections were checked above.
            // Initialization, per-call graphs, input/signature, output and length
            // storage remain owned by this installed operation after invocation.
            let rv = unsafe {
                // The only phase transition since validation is Capacity to
                // Data with the same owned call. Direction and operand indices
                // cannot change; the non-null native entry was selected above.
                self.operands(native_call)
                    .expect("validated generic message operands")
                    .invoke(entry.handle)
            };
            use crate::native_return::protocol::{PendingInspection, SequencePhase};
            use crate::native_return::sequence::{Completion, OutputRequest};
            let inspected = PendingInspection::returned(function, rv, |scope| {
                state.apply_session_failure(entry, rv, scope);
            })
            .inspect(|| {
                if !self.unchanged() {
                    return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                        crate::NativeMessagesRejection::GenericMessageInputMutation,
                    )));
                }
                if rv == CKR_OK && !self.verify {
                    if let Some(index) = terminal {
                        if let MessageOutput::Sign(Some(output)) = &self.messages[index].output {
                            bounds::final_length(*output.length, output.capacity)?;
                        }
                    }
                }
                Ok(())
            });
            let version = state.native.table.version;
            let phase = if initializing {
                SequencePhase::Initialize
            } else {
                SequencePhase::Continue(OutputRequest::Buffer)
            };
            let size = if !self.verify {
                terminal.and_then(|index| match &self.messages[index].output {
                    MessageOutput::Sign(Some(output)) => crate::NativeOutputSize::buffer_refusal(
                        function,
                        rv,
                        output.capacity,
                        || *output.length,
                    ),
                    _ => None,
                })
            } else {
                None
            };
            let initialization_refused =
                inspected.initialization_refused((version.major, version.minor), phase);
            let completion = inspected.completion((version.major, version.minor), phase);
            inspected.resolve(|result, error| {
                self.uncertain(state, entry, rv);
                if result.code() == CKR_OK {
                    error
                } else {
                    // Failed/uncertain precedes consumption of the prepaid
                    // leaf; polling cannot repeat this native call.
                    let mut cause = self.diagnostic.take().expect("prepared generic diagnostic");
                    *cause = error;
                    match size {
                        Some(size) => Error::NativeOutputAndLocalFailure { size, cause },
                        None => Error::NativeAndLocalFailure {
                            function: result.function(),
                            code: result.code() as u64,
                            cause,
                        },
                    }
                }
            })?;
            if !crate::native_return::call_memory_returned(rv) {
                self.uncertain(state, entry, rv);
                return Err(Error::Native {
                    function,
                    code: rv as u64,
                    may_have_effect: true,
                });
            }
            self.activity = if initialization_refused {
                NativeActivity::InitializationRefused
            } else if completion == Completion::Terminated {
                NativeActivity::Closed
            } else {
                NativeActivity::Active
            };

            if rv == CKR_BUFFER_TOO_SMALL && terminal.is_some() && !self.verify {
                let index = terminal.expect("checked terminal signature call");
                let MessageOutput::Sign(Some(output)) = &mut self.messages[index].output else {
                    unreachable!("validated signing output")
                };
                let required = match usize::try_from(*output.length) {
                    Ok(required) => required,
                    Err(_) => {
                        // A local representation failure after C must not leave
                        // Data runnable: another poll would replay this call.
                        self.execution = Execution::Failed;
                        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                            crate::SignatureMessagesRejection::MessageNativeLengthWidth,
                        )));
                    }
                };
                let request = SignatureBufferRequest {
                    function,
                    code: rv as u64,
                    required,
                    previous_capacity: output.capacity,
                };
                assert!(
                    self.released.output.is_none(),
                    "message output retirement pending"
                );
                self.released.output = Some(output.bytes.take());
                let Phase::Data(call) = std::mem::replace(&mut self.phase, Phase::Ready) else {
                    unreachable!("terminal call retains its input")
                };
                self.phase = Phase::Capacity {
                    call,
                    request,
                    storage: CapacityStorage::Missing,
                };
                return Ok(());
            }

            if rv != CKR_OK {
                let ordinary = crate::native_return::native_context_scope(rv)
                    == crate::native_return::FailureScope::None;
                if ordinary
                    && self.verify
                    && terminal.is_some()
                    && matches!(rv, CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE)
                {
                    let index = terminal.expect("terminal verification refusal");
                    self.messages[index].output = MessageOutput::Verify { verdict: Some(rv) };
                    self.invalid_seen = true;
                    self.input.retained_submission = false;
                    self.returned_to(Phase::Ready);
                    return Ok(());
                }
                let error = Error::Native {
                    function,
                    code: rv as u64,
                    may_have_effect: self.binding.primary.own_revocation
                        || crate::native_return::effect_uncertain(rv)
                        || !(initializing && self.activity.locally_retirable()),
                };
                if ordinary && matches!(self.phase, Phase::Begin(_) | Phase::Data(_)) {
                    // PKCS#11 3.2 §§5.14/5.16 distinguish a message's end from
                    // parent Final. No cleanup call is implied by this refusal.
                    let index = match &self.phase {
                        Phase::Begin(index) => *index,
                        Phase::Data(call) => call.message,
                        _ => unreachable!("returned message refusal"),
                    };
                    self.messages[index].rejection = Some(super::NativeMessageRejection {
                        function,
                        code: rv as u64,
                    });
                    self.input.retained_submission = false;
                    self.returned_to(Phase::Ready);
                    return Err(error);
                }
                self.execution = Execution::Failed;
                if !self.activity.locally_retirable() {
                    entry.poisoned.store(true, Ordering::Release);
                }
                return Err(error);
            }

            if let Some(index) = terminal {
                match &mut self.messages[index].output {
                    MessageOutput::Sign(Some(output)) => {
                        let length = match bounds::final_length(*output.length, output.capacity) {
                            Ok(length) => length,
                            Err(error) => {
                                self.uncertain(state, entry, rv);
                                return Err(error);
                            }
                        };
                        output.produced = Some(length);
                        output
                            .bytes
                            .set_length(output.offset + length)
                            .expect("validated message signature allocation");
                        self.input = submission
                            .as_ref()
                            .expect("terminal input submission")
                            .completed
                            .produced(length)?;
                    }
                    MessageOutput::Verify { verdict } => {
                        *verdict = Some(CKR_OK);
                        self.input = submission.as_ref().expect("terminal input").completed;
                    }
                    MessageOutput::Sign(None) => unreachable!("validated terminal output"),
                }
            } else if let Some(submission) = submission {
                self.input = submission.completed;
            }
            let next = match &self.phase {
                Phase::Init => Phase::Ready,
                Phase::Begin(index) => Phase::Receive(*index),
                Phase::Data(call) if !call.kind.terminal() => Phase::Receive(call.message),
                Phase::Data(_) => Phase::Ready,
                Phase::Final => {
                    if let Err(error) = self.finish_outputs().and_then(|()| self.finish_graphs()) {
                        self.uncertain(state, entry, rv);
                        return Err(error);
                    }
                    Phase::Complete
                }
                _ => unreachable!("dispatchable generic message phase"),
            };
            self.returned_to(next);
        }
        Ok(())
    }

    /// Final may still access cells lent by prior message calls. Re-read every
    /// native length, including earlier messages, before establishing the final
    /// publication extents. No signature bytes have been delivered at this point.
    fn finish_outputs(&mut self) -> Result<()> {
        let mut total = 0u128;
        for message in self
            .messages
            .iter()
            .filter(|message| message.rejection.is_none())
        {
            if let MessageOutput::Sign(Some(output)) = &message.output {
                let length = bounds::final_length(*output.length, output.capacity()?)?;
                total = total.checked_add(length as u128).ok_or_else(invalid)?;
            }
        }
        if self.input.progress.delivered_bytes != 0 {
            return Err(invalid());
        }
        for message in self
            .messages
            .iter_mut()
            .filter(|message| message.rejection.is_none())
        {
            if let MessageOutput::Sign(Some(output)) = &mut message.output {
                let length = bounds::final_length(*output.length, output.capacity()?)?;
                output.bytes.set_length(output.offset + length)?;
                output.produced = Some(length);
            }
        }
        self.input.progress.output_bytes = total;
        Ok(())
    }

    fn finish_graphs(&mut self) -> Result<()> {
        self.initialization
            .as_deref_mut()
            .ok_or_else(invalid)?
            .finish()?;
        for message in self
            .messages
            .iter_mut()
            .filter(|message| message.rejection.is_none())
        {
            if let Some(begin) = &mut message.begin {
                begin.graph.finish()?;
            }
            for part in &mut message.parts {
                part.graph.finish()?;
            }
        }
        Ok(())
    }
}
