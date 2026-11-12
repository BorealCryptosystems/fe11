// SPDX-License-Identifier: Apache-2.0
//! Inject caller-provided bytes or a key into a possessed digest sequence.
//! Resolve the input and validate its owner before the selected native update.

use super::*;

/// A function pointer and the exact input borrowed from the installed frame.
/// The borrow prevents replacing that input until invocation has consumed it.
enum ResolvedInput<'a> {
    Bytes {
        call: unsafe extern "C" fn(
            fe11_sys::CK_SESSION_HANDLE,
            fe11_sys::CK_BYTE_PTR,
            CK_ULONG,
        ) -> fe11_sys::CK_RV,
        input: &'a mut Buffer,
        length: CK_ULONG,
    },
    Key {
        call:
            unsafe extern "C" fn(fe11_sys::CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> fe11_sys::CK_RV,
        handle: CK_OBJECT_HANDLE,
    },
}

impl<'a> ResolvedInput<'a> {
    fn prepare(
        table: &crate::interfaces::CommonFunctions,
        input: &'a mut OwnedInput,
    ) -> Result<Self> {
        let missing = || {
            Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestInputFunctionUnavailable,
            ))
        };
        Ok(match input {
            OwnedInput::Bytes { input, length, .. } => Self::Bytes {
                call: table.C_DigestUpdate.ok_or_else(missing)?,
                input,
                length: *length,
            },
            OwnedInput::Key { handle, .. } => Self::Key {
                call: table.C_DigestKey.ok_or_else(missing)?,
                handle: *handle,
            },
        })
    }

    /// The caller retains and arms the session frame before consuming this loan.
    unsafe fn invoke(self, session: fe11_sys::CK_SESSION_HANDLE) -> fe11_sys::CK_RV {
        // SAFETY: prepare couples the chosen signature to the installed input;
        // the caller holds its session, image and key/byte owner through return.
        unsafe {
            match self {
                Self::Bytes {
                    call,
                    input,
                    length,
                } => call(session, input.as_mut().as_mut_ptr(), length),
                Self::Key { call, handle } => call(session, handle),
            }
        }
    }
}

pub(super) fn validate_injection(
    session: &Session,
    operation: &crate::advanced::Operation,
    access: &State,
    request: &Input<'_>,
) -> Result<&'static str> {
    if operation.cancellation.is_withdrawn()
        || operation.cancel.is_submitted()
        || operation.state_io().is_some()
        || operation.transfer.as_ref().is_some()
        || operation.joined.is_some()
        || operation.continuation_status.is_frozen()
        || operation.validation_pending()
    {
        return Err(Error::Busy(crate::BusyReason::DigestContinuation(
            crate::DigestContinuationBusy::DigestControlInProgress,
        )));
    }
    operation.check_control_access(&session.entry)?;
    let OperationBody::Digest(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::DigestTicketRequired,
        )));
    };
    if body.activity.pending()
        || body.activity.inactive()
        || !matches!(body.step, Step::Update(_) | Step::Final)
    {
        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::DigestInputPhase,
        )));
    }
    let function = match request {
        Input::Bytes(..) if access.native.table.C_DigestUpdate.is_some() => "C_DigestUpdate",
        Input::Key(..) if access.native.table.C_DigestKey.is_some() => "C_DigestKey",
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestInputFunctionUnavailable,
            )))
        }
    };
    Ok(function)
}

pub(super) fn inject(
    session: &Session,
    ticket: &mut OperationTicket,
    request: Input<'_>,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    retired_owner: &mut Option<Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<()> {
    synchronous(session)?;
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
        )));
    }

    let admission = crate::admission_wait::current();
    // These locals outlive every guard below. Failure/abandonment therefore
    // performs its bounded local maintenance only after releasing possession.
    let mut prepared: Option<PreparedInput> = None;
    let mut waiter: Option<progress::Waiter<'_>> = None;
    loop {
        let mut permit = None;
        let mut retired_reader = None;
        let mut input;
        // Only established, unchanged input data may leave NativeFrame.
        // These owners outlive the outer operation/session guards, including
        // an error that removes the crypto owner from the registry.
        let held;
        let _returned: Option<crate::native::frame::CallData<InputFrame>>;
        let access = session.advanced_access()?;
        if session.entry.advanced_progress.retired(ticket.id)? {
            ticket.id = 0;
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
            )));
        }
        held = access.operations.get(session.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleDigestTicket,
            )));
        }
        let function = validate_injection(session, &operation, &access, &request)?;
        request.checked_bytes(session)?;
        if diagnostics.is_none() {
            drop(operation);
            drop(held);
            drop(access);
            *diagnostics = Some(progress::FailureDiagnostics::prepare(session, ticket.id)?);
            continue;
        }
        if waiter.as_ref().is_some_and(progress::Waiter::changed) {
            waiter
                .as_mut()
                .expect("registered input waiter")
                .succeed()?;
            drop(operation);
            drop(held);
            drop(access);
            drop(prepared.take());
            drop(waiter.take());
            continue;
        }
        if prepared.is_none() {
            waiter = Some(progress::Waiter::new(
                session,
                operation.id,
                progress::Effect::PreserveOwner,
            )?);
            drop(operation);
            drop(held);
            drop(access);
            let waiting = waiter.as_mut().expect("registered input waiter");
            let diagnostics = diagnostics
                .as_mut()
                .expect("digest input diagnostics prepared");
            let candidate =
                PreparedInput::prepare(session, diagnostics.budget(), &request, &admission, || {
                    crate::advanced::preparation::context(session)?;
                    if waiting.changed() {
                        return Err(Error::Busy(crate::BusyReason::DigestContinuation(
                            crate::DigestContinuationBusy::DigestControlInProgress,
                        )));
                    }
                    Ok(())
                });
            match candidate {
                Ok(candidate) => prepared = Some(candidate),
                Err(_) if waiting.changed() => {
                    waiting.succeed()?;
                }
                Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
            }
            continue;
        }
        match prepared
            .as_ref()
            .expect("prepared digest input")
            .read_permit(&mut permit)
        {
            Ok(()) => (),
            Err(Error::Busy(_)) => {
                drop(operation);
                drop(held);
                drop(access);
                let waiting = waiter.as_mut().expect("registered input waiter");
                let result = prepared
                    .as_ref()
                    .expect("prepared digest input")
                    .wait_available(&admission, || {
                        crate::advanced::preparation::context(session)?;
                        if waiting.changed() {
                            return Err(Error::Busy(crate::BusyReason::DigestContinuation(
                                crate::DigestContinuationBusy::DigestControlInProgress,
                            )));
                        }
                        Ok(())
                    });
                match result {
                    Ok(()) => {}
                    Err(_) if waiting.changed() => {
                        waiting.succeed()?;
                    }
                    Err(error) => {
                        return Err(waiting.fail_prepared(
                            error,
                            diagnostics
                                .as_mut()
                                .expect("digest input diagnostics prepared"),
                        ));
                    }
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        input = Some(PreparedInput::bind_retained(
            &mut prepared,
            session,
            &access,
            &request,
            &mut permit,
            &mut retired_reader,
        )?);
        waiter
            .as_mut()
            .expect("registered input waiter")
            .succeed()?;
        access
            .operations
            .claim_progress(&session.entry, operation.id)?;
        let OperationBody::Digest(body) = &mut operation.body else {
            unreachable!()
        };
        let (bytes, key) = match &request {
            Input::Bytes(bytes, _) => (bytes.len(), false),
            Input::Key(_) => (0, true),
        };
        let submission = body.input.submission(bytes, key)?;
        let mut frame = NativeFrame::session_with(
            || input.take().expect("bound digest input"),
            access.clone(),
        )?;
        let (returned, native) = frame.session_parts();
        let call = match ResolvedInput::prepare(&access.native.table, &mut native.data.input) {
            Ok(call) => call,
            Err(error) => {
                let completed = frame.into_inner()?;
                _returned = Some(completed.data);
                drop(completed.access);
                return Err(error);
            }
        };
        if let Err(error) = access.native.record(function) {
            drop(call);
            // Nothing was issued: detach the stable operand before returning,
            // so the outer guards leave before its permit and bytes.
            let completed = frame.into_inner()?;
            _returned = Some(completed.data);
            drop(completed.access);
            return Err(error);
        }
        body.input = submission.issued;
        returned.arm();
        // SAFETY: the input buffer or admitted key permit, session access and image
        // belong to the stable frame. They remain retained on an uncompleted call.
        let rv = returned.observe(unsafe { call.invoke(session.entry.handle) }, &access.native);
        use crate::native_return::protocol::{PendingInspection, SequencePhase};
        use crate::native_return::sequence::{Completion, OutputRequest};
        let inspected = PendingInspection::returned(function, rv, |scope| {
            access.apply_session_failure(&session.entry, rv, scope);
        })
        .inspect(|| {
            if !native.data.unchanged() {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::NativeDigestInputChanged,
                )));
            }
            Ok(())
        });
        let version = access.native.table.version;
        let released = crate::native_return::sequence::digest_input_returned(
            (version.major, version.minor),
            function,
            rv,
        );
        let OperationBody::Digest(body) = &mut operation.body else {
            unreachable!()
        };
        body.activity = if inspected.completion(
            (version.major, version.minor),
            SequencePhase::Continue(OutputRequest::Buffer),
        ) == Completion::Terminated
        {
            NativeActivity::Closed
        } else {
            NativeActivity::Active
        };
        let disposition = inspected.resolve(|result, cause| {
            body.activity = NativeActivity::Active;
            body.step = Step::Failed;
            returned.quarantine(&access.native);
            if result.code() == fe11_sys::CKR_OK {
                cause
            } else {
                body.frame
                    .completion_diagnostic
                    .take()
                    .expect("one terminal digest boundary failure")
                    .bind(result.function())
                    .boundary_failure(result.code(), cause)
            }
        });
        let mut detachable = false;
        let result = if let Err(error) = disposition {
            Err(error)
        } else if !released {
            // An unexpected pending call has its own retained input frame; do not
            // submit any operation, including Final, through the crypto ticket.
            body.step = Step::Failed;
            session.entry.poisoned.store(true, Ordering::Release);
            returned.uncompleted();
            match check(rv, function, true) {
                Err(error) => Err(error),
                Ok(()) => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestInputCompletionUnproven,
                ))),
            }
        } else {
            returned.terminated();
            // An established refusal is the end of this submission, even when
            // DigestKey leaves the digest active. A later explicit input is a
            // new ordinal, not a capacity retry of the refused key.
            body.input.retained_submission = false;
            detachable = true;
            if body.activity.inactive() {
                body.step = Step::Failed;
            }
            if rv == fe11_sys::CKR_OK {
                body.input = submission.completed;
            }
            // A refused DigestKey leaves the digest and its next planned step
            // available. Only the caller decides whether to submit more input.
            check(rv, function, true)
        };
        if detachable {
            // into_inner requires the established Owned disposition. Moving
            // CallData keeps its inline addresses; only the guard clone and
            // unused recovery bookkeeping are released here, not the operand.
            let completed = frame.into_inner()?;
            _returned = Some(completed.data);
            drop(completed.access);
        } else {
            // Unknown returns and mutated native input keep the existing
            // NativeFrame quarantine/recovery path and all its referents.
            _returned = None;
        }
        // The call has returned. Its exact result must survive a concurrent
        // withdrawal; the next request validates the retained operation again.
        if let Err(error) = result {
            // The public injection owns the terminal leaves after registry removal.
            *retired_owner = Some(held.clone());
            let (error, released) = operation.retire_terminal_error(&access, &session.entry, error);
            if released {
                ticket.id = 0;
            }
            return Err(error);
        }
        return Ok(());
    }
}
