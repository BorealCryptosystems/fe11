// SPDX-License-Identifier: Apache-2.0
//! Drive operation-state capture and restoration through native return boundaries.
//! Pending observations and terminal publication keep their exact context and owner.

use super::*;

impl StateIo {
    pub(in crate::advanced) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        self.drive_selected(s, entry, observe, remaining, true, &mut || Ok(()))
    }

    pub(in crate::advanced) fn drive_before_restore(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
        before_restore: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.drive_selected(s, entry, observe, remaining, true, before_restore)
    }

    /// Observe only the invocation already borrowing this frame. A terminal
    /// sizing/info result must not start the next capture phase after withdrawal.
    pub(in crate::advanced) fn observe_pending(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        self.drive_selected(s, entry, observe, remaining, false, &mut || Ok(()))
    }

    pub(super) fn drive_selected(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
        allow_dispatch: bool,
        before_restore: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if self.flow.phase() == Phase::Failed {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateIoFailed,
            )));
        }
        while !self.complete() {
            if !allow_dispatch && !self.pending {
                return Ok(());
            }
            // The native size response is already committed. Resource
            // preparation belongs to the outer driver, after guard release.
            if matches!(self.flow.phase(), Phase::Sized { .. }) {
                return Ok(());
            }
            if self.pending && !observe || !spend(remaining) {
                return Ok(());
            }
            entry.snapshot.check()?;
            if s.native.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            let name = self.function()?;
            let completing = self.pending;
            let rv = if self.pending {
                let call =
                    s.native
                        .asynchronous
                        .and_then(|f| f.complete)
                        .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                            crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
                        )))?;
                s.native.record("C_AsyncComplete")?;
                // SAFETY: function name and result storage remain in this frame.
                unsafe {
                    call(
                        entry.handle,
                        self.name.as_mut_ptr(),
                        if self.flow.phase() == Phase::Restore {
                            std::ptr::null_mut()
                        } else {
                            &mut *self.completion
                        },
                    )
                }
            } else {
                self.name.fill(0);
                self.name[..name.len()].copy_from_slice(name.as_bytes());
                let native_call = resolved_call::Call::resolve(
                    &s.native.table,
                    self.flow.phase(),
                    self.flow.direction(),
                )?;
                s.native.record(name)?;
                if self.flow.phase() == Phase::Restore {
                    before_restore()?;
                }
                // SAFETY: sizes, writable output and opaque input owners were
                // installed before the call. No borrowed caller buffer is used.
                unsafe {
                    match native_call {
                        resolved_call::Call::Info(call) => call(entry.handle, &mut *self.info),
                        resolved_call::Call::Size(call) => {
                            call(entry.handle, std::ptr::null_mut(), &mut *self.length)
                        }
                        resolved_call::Call::Bytes(call) => call(
                            entry.handle,
                            self.flow.bytes_mut().unwrap().as_mut().as_mut_ptr(),
                            &mut *self.length,
                        ),
                        resolved_call::Call::Restore {
                            call,
                            encryption,
                            authentication,
                        } => call(
                            entry.handle,
                            self.flow.bytes_mut().unwrap().as_mut().as_mut_ptr(),
                            *self.length,
                            encryption,
                            authentication,
                        ),
                    }
                }
            };
            use crate::native_return::protocol::PendingInspection;
            let observe_context = |_| Self::observe_context(s, entry, rv, name);
            let pending = if completing {
                s.native.observe_async_return(rv);
                PendingInspection::completed(name, rv, observe_context)
            } else {
                PendingInspection::returned(name, rv, observe_context)
            };
            let inspected = pending.inspect(|| {
                if completing && self.flow.phase() != Phase::Restore {
                    if self.completion.ulVersion != 0 {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateAsynchronousVersion,
                        )));
                    }
                    if matches!(self.flow.phase(), Phase::Size | Phase::Bytes) {
                        let pointer = if self.flow.phase() == Phase::Size {
                            std::ptr::null_mut()
                        } else {
                            self.flow.bytes_mut().unwrap().as_mut().as_mut_ptr().cast()
                        };
                        if self.completion.pValue != pointer {
                            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                                crate::OperationStateRejection::StateAsynchronousOutputIdentity,
                            )));
                        }
                    }
                }
                if rv == CKR_OK && self.flow.phase() == Phase::Bytes {
                    let length = if completing {
                        self.completion.ulValue
                    } else {
                        *self.length
                    };
                    bounds::final_length(length, self.flow.bytes_mut().unwrap().capacity())?;
                }
                Ok(())
            });
            let size = if !completing && matches!(self.flow.phase(), Phase::Size | Phase::Bytes) {
                let capacity = self.flow.bytes_mut().map_or(0, |bytes| bytes.capacity());
                crate::NativeOutputSize::buffer_refusal(name, rv, capacity, || *self.length)
            } else {
                None
            };
            let disposition = inspected.resolve(|result, cause| {
                self.pending = true;
                s.native.mark_uncertain();
                if result.code() == CKR_OK {
                    cause
                } else {
                    self.return_diagnostic
                        .take()
                        .expect("one terminal state-control boundary failure")
                        .bind(result.function())
                        .boundary_with_output(result.code(), size, cause)
                }
            });
            let result = match disposition {
                Ok(result) => result,
                Err(error) => {
                    // Failed retains attached bytes and prevents a repeated poll
                    // from consuming the terminal diagnostic leaf again.
                    self.flow.transition(Phase::Failed)?;
                    return Err(error);
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
            if !result.memory_returned() {
                // GENERAL_ERROR from a completion query does not restore
                // access to its parent's output graph. Do not inspect AsyncComplete's
                // descriptor or project bytes before preserving that distinction.
                // No proof ends the native memory loan. Failed prevents any
                // further dispatch; pending retains IO/keys/permissions until
                // established session close, including restoration refusal paths.
                self.pending = true;
                self.flow.transition(Phase::Failed)?;
                s.native.mark_uncertain();
                return Err(Error::Native {
                    function: name,
                    code: rv as u64,
                    may_have_effect: name == "C_SetOperationState",
                });
            }
            // Only a validated returned boundary can credit a captured state.
            // An earlier anomaly retained the frame and withdrew native use.
            self.note_capture(rv);
            if self.pending && self.flow.phase() != Phase::Restore {
                if self.completion.ulVersion != 0 {
                    s.native.mark_uncertain();
                    return Err(Error::Rejected(crate::RejectionReason::OperationState(
                        crate::OperationStateRejection::StateAsynchronousVersion,
                    )));
                }
                if matches!(self.flow.phase(), Phase::Size | Phase::Bytes) {
                    let pointer = if self.flow.phase() == Phase::Size {
                        std::ptr::null_mut()
                    } else {
                        self.flow.bytes_mut().unwrap().as_mut().as_mut_ptr().cast()
                    };
                    if self.completion.pValue != pointer {
                        s.native.mark_uncertain();
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateAsynchronousOutputIdentity,
                        )));
                    }
                    if rv == CKR_OK {
                        *self.length = self.completion.ulValue;
                    }
                }
            }
            self.pending = false;
            if let Some(size) = size {
                self.flow.transition(Phase::Failed)?;
                return Err(size.buffer_too_small());
            }
            self.finish_terminal(entry, rv, name)?;
        }
        Ok(())
    }

    pub(super) fn note_capture(&mut self, rv: CK_RV) {
        if rv == CKR_OK {
            if let Flow::Capture {
                phase: CapturePhase::Bytes(_),
                captured,
                ..
            } = &mut self.flow
            {
                *captured = true;
            }
        }
    }

    pub(super) fn finish_terminal(
        &mut self,
        entry: &SessionEntry,
        rv: CK_RV,
        name: &'static str,
    ) -> Result<()> {
        if rv != CKR_OK {
            self.flow.transition(Phase::Failed)?;
            return check(rv, name, name == "C_SetOperationState");
        }
        if let Err(error) = self.advance(entry) {
            self.flow.transition(Phase::Failed)?;
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn observe_context(s: &State, entry: &SessionEntry, rv: CK_RV, name: &str) {
        if rv == CKR_PENDING {
            return;
        }
        let scope = if name == "C_GetOperationState" {
            crate::native_return::state_read_scope(rv)
        } else {
            crate::native_return::failure_scope(rv)
        };
        if scope == crate::native_return::FailureScope::Session {
            entry.poisoned.store(true, Ordering::Release);
        }
        s.apply_session_failure(entry, rv, scope);
    }

    pub(super) fn advance(&mut self, entry: &SessionEntry) -> Result<()> {
        let next = match self.flow.phase() {
            Phase::Info => {
                validate_info(
                    &self.info,
                    self.source_info_slot.unwrap_or(entry.slot),
                    entry.read_write,
                )?;
                match self.flow.direction() {
                    Direction::Inspect => Phase::Done,
                    Direction::Capture { .. } => Phase::Size,
                    Direction::Restore { expected, .. } => {
                        if self.info.state != expected {
                            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                                crate::OperationStateRejection::OperationStateSessionMismatch,
                            )));
                        }
                        Phase::Restore
                    }
                }
            }
            Phase::Size => {
                let Direction::Capture { maximum } = self.flow.direction() else {
                    unreachable!()
                };
                let size = crate::error::checked_native_size(
                    "C_GetOperationState",
                    CKR_OK,
                    *self.length,
                    maximum,
                )?;
                Phase::Sized { length: size }
            }
            Phase::Bytes => {
                let length = *self.length;
                let bytes = self.flow.bytes_mut().unwrap();
                bytes.set_length(bounds::final_length(length, bytes.capacity())?)?;
                Phase::Done
            }
            Phase::Restore => Phase::Done,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::DuplicateStateCompletion,
                )))
            }
        };
        self.flow.transition(next)
    }
}
