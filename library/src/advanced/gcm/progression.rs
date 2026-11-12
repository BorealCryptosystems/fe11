// SPDX-License-Identifier: Apache-2.0
//! Shared native message boundaries and the adapter for already supplied input.
//!
//! The protocol reaches Ready or Receive after an established successful call.
//! Caller-fed owners stop there. A list facade has already supplied its next
//! input and parent termination, so it selects that request without another
//! admission, allocation, native call, or change to the caller's pacing.
use super::{AeadMessageOperation, AeadStep};
use crate::{Error, Result};

impl AeadMessageOperation {
    /// Commit exactly one successful native transition. Message completion is
    /// distinct from parent Final, independently of how input was supplied.
    pub(super) fn advance_after_success(&mut self, last: bool) -> Result<()> {
        let completed = self.step;
        let boundary = match completed {
            AeadStep::Init | AeadStep::Single(_) | AeadStep::StreamLast(_) => AeadStep::Ready,
            AeadStep::Begin(index) | AeadStep::StreamUpdate(index) => AeadStep::Receive(index),
            AeadStep::Next(_, _) if last => AeadStep::Ready,
            AeadStep::Next(index, _) => AeadStep::Receive(index),
            AeadStep::Finish => AeadStep::Done,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::DuplicateGcmCompletion,
                )))
            }
        };
        self.step = if self.input.is_some() {
            boundary
        } else {
            self.queued_after_success(completed, boundary)?
        };
        Ok(())
    }

    /// Preloaded buffers remain owned by the existing list/recovery adapter.
    /// It preserves original fragment boundaries, Single versus Multipart and
    /// the completed prefix carried by an explicitly authorized fresh decryption run.
    fn queued_after_success(&self, completed: AeadStep, boundary: AeadStep) -> Result<AeadStep> {
        Ok(match (completed, boundary) {
            (AeadStep::Init, AeadStep::Ready) => {
                if self.restart_at == self.frames.len() {
                    AeadStep::Finish
                } else {
                    self.start_message(self.restart_at)
                }
            }
            (AeadStep::Single(index) | AeadStep::Next(index, _), AeadStep::Ready) => {
                if index + 1 < self.frames.len() {
                    self.start_message(index + 1)
                } else {
                    AeadStep::Finish
                }
            }
            (AeadStep::Begin(index), AeadStep::Receive(_)) => AeadStep::Next(index, 0),
            (AeadStep::Next(index, part), AeadStep::Receive(_)) => AeadStep::Next(index, part + 1),
            (AeadStep::Finish, AeadStep::Done) => AeadStep::Done,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadQueuedInputTransition,
                )))
            }
        })
    }
}

use super::*;

impl AeadMessageOperation {
    pub(super) fn start_message(&self, i: usize) -> AeadStep {
        if self.route == MessageRoute::Single {
            AeadStep::Single(i)
        } else {
            AeadStep::Begin(i)
        }
    }

    pub(in crate::advanced) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        match self.drive_inner(s, entry, observe, remaining) {
            Err(error) if matches!(self.outcome, AeadOutcome::Closing { .. }) => {
                let AeadOutcome::Closing { diagnostic, .. } =
                    std::mem::replace(&mut self.outcome, AeadOutcome::Nominal)
                else {
                    unreachable!()
                };
                self.step = AeadStep::Failed;
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
        if self.step == AeadStep::Failed {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageFailedExplicitCleanupRequired,
            )));
        }
        self.key.check(entry)?;
        if self.pending() {
            if !observe || !spend(remaining) {
                return Ok(());
            }
            let name = self.function()?;
            let output = self.output_index();
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
            // SAFETY: observation storage belongs to this retained operation.
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
                        let frame = &self.frames[index];
                        let out = &mut self.outputs.as_mut().unwrap().entries[index].bytes;
                        let pointer = out.as_mut()[frame.used..].as_mut_ptr();
                        if self.completion.ulVersion != 0
                            || self.completion.pValue != pointer
                            || rv == CKR_OK
                                && self.completion.ulValue as u128
                                    > (out.capacity() - frame.used) as u128
                        {
                            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                                crate::AeadMessagesRejection::AeadMessageAsynchronousOutputIdentity,
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
                    let frame = &mut self.frames[i];
                    let out = &mut self.outputs.as_mut().unwrap().entries[i].bytes;
                    let pointer = out.as_mut()[frame.used..].as_mut_ptr();
                    if self.completion.ulVersion != 0
                        || self.completion.pValue != pointer
                        || self.completion.ulValue as usize > out.capacity() - frame.used
                    {
                        s.native.mark_uncertain();
                        self.step = AeadStep::Failed;
                        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadMessageAsynchronousOutputIdentity,
                        )));
                    }
                    *frame.length = self.completion.ulValue;
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
        while !matches!(
            self.step,
            AeadStep::Ready | AeadStep::Receive(_) | AeadStep::Done | AeadStep::Failed
        ) && self.buffer_request().is_none()
        {
            if !spend(remaining) {
                return Ok(());
            }
            self.key.check(entry)?;
            if s.native.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            if let AeadStep::Single(i) | AeadStep::Begin(i) = self.step {
                if let Err(error) = self.prepare_message(i) {
                    s.native.mark_uncertain();
                    self.step = AeadStep::Failed;
                    return Err(error);
                }
            }
            let name = self.function()?;
            let f =
                s.native
                    .messages
                    .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::MessageInterfaceUnavailable,
                    )))?;
            let native_call = resolved_call::Call::resolve(f, self.decrypt, self.dispatch_step())?;
            let flags = if self.last() { CKF_END_OF_MESSAGE } else { 0 };
            // A failed local conversion must not count as a native invocation
            // or change activity. Only Single/Next pass an output-length slot.
            let output_length = match self.dispatch_step() {
                AeadStep::Single(i)
                | AeadStep::Next(i, _)
                | AeadStep::StreamUpdate(i)
                | AeadStep::StreamLast(i) => {
                    let frame = &self.frames[i];
                    let output = &self.outputs.as_ref().unwrap().entries[i].bytes;
                    bounds::ck_length(output.capacity() - frame.used)?
                }
                _ => 0,
            };
            self.check_queued_retirement()?;
            let submission = self.input_submission(output_length as usize)?;
            s.native.record(name)?;
            self.activity = NativeActivity::Active;
            if let Some(submission) = submission {
                self.input
                    .as_mut()
                    .expect("preflighted AEAD stream input")
                    .state = submission.issued;
            }
            // SAFETY: all parameters/IV/tag/inputs/outputs/lengths belong to the
            // installed frame. Null is never used for a size probe/implicit retry.
            let rv = unsafe {
                self.call_operands(native_call, output_length, flags)
                    .invoke(entry.handle)
            };
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
