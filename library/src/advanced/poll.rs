// SPDX-License-Identifier: Apache-2.0
//! Shared publication and completion driver for registered operation owners.
use super::{
    admission::{PreparedResource, ResourceCandidate},
    preparation, progress,
};
use super::{
    drive, unfinished, OperationBody, OperationPacing, OperationProgress, OperationTicket,
};
use crate::{Error, Result, Session};
use std::sync::Arc;

/// Returned native operands are erased only after session/operation possession
/// has unwound. Callers declare a fresh owner before acquiring that possession.
#[derive(Default)]
pub(super) struct ReleasedInputs {
    inputs: ReturnedInputs,
    // Result extraction can precede a fallible authentication/report/retirement
    // check. Keep an unpublished result outside possession on those paths too.
    result: Option<OperationProgress>,
    // An extra Arc keeps the entire retired body, role leases and identity alive
    // until the caller releases session/module guards, even on terminal error.
    owner: Option<Arc<crate::advanced::ledger::OperationCell>>,
}

impl ReleasedInputs {
    /// Transfer the retired metadata anchor to a public result-projection root.
    /// Returned native operands keep their own guard-free destruction scope.
    pub(super) fn take_owner(&mut self) -> Option<Arc<super::ledger::OperationCell>> {
        self.owner.take()
    }
}

#[derive(Default)]
enum ReturnedInputs {
    #[default]
    None,
    Typed {
        _inputs: super::messages::ReleasedInputs,
    },
    Native {
        _inputs: super::native_messages::ReleasedInput,
    },
    Aead {
        _inputs: super::gcm::ReleasedInput,
    },
    Signature {
        _inputs: super::signature::ReturnedOperands,
    },
    Cipher {
        _inputs: super::cipher::ReturnedOperands,
    },
    Digest {
        _inputs: super::fragment_retirement::ReturnedOperands,
    },
}

/// Kept at the public boundary when a facade projects a poll error or result.
/// Moving an envelope out of Admission moves its existing credit, not a second
/// reservation. Empty roots allocate nothing for other operation families.
#[derive(Default)]
pub(crate) struct PollDiagnostics {
    failure: Option<progress::FailureDiagnostics>,
    // A conflicting signature Init can publish an error without installing a
    // new ticket. Its leaf must remain charged after start_retained returns.
    pub(super) competing_signature: Option<crate::symmetric::memory::Credit>,
    // Only a synchronous creation facade needs this uncertainty marker. It is
    // prepaid with initial admission and kept here even when poll returns Pending.
    pub(super) pending: Option<crate::error::PreparedCompletionStorage>,
    // A terminal error can remove the ledger entry while its prepaid leaves
    // are still being projected by a facade. Keep that operation's metadata
    // credit alive through the actual public return, after every guard leaves.
    pub(super) retired_owner: Option<Arc<crate::advanced::ledger::OperationCell>>,
}
impl PollDiagnostics {
    fn retained_bytes(&self) -> usize {
        usize::from(self.failure.is_some()) * progress::FailureDiagnostics::allocation_bytes()
            + usize::from(self.competing_signature.is_some())
                * crate::error::CompletionStorage::allocation_bytes()
            + usize::from(self.pending.is_some())
                * crate::error::PreparedCompletionStorage::allocation_bytes()
    }
}

// The borrowed facade is never retained by native code. Every pending buffer,
// lease and operation remains owned by the registry exactly as for AdvancedSession.
// The public root supplies and retains diagnostics through its final projection.
pub(super) fn poll_operation_with_diagnostics(
    session: &Session,
    ticket: &mut OperationTicket,
    admission: crate::session::CleanupAdmission,
    pacing: OperationPacing,
    diagnostics: &mut PollDiagnostics,
) -> Result<OperationProgress> {
    match poll_live_operation(session, ticket, admission, pacing, diagnostics) {
        Ok(result) => Ok(result),
        Err(error) => match publish_retained_completion(session, ticket, admission, diagnostics)? {
            Some(result) => Ok(result),
            None => Err(error),
        },
    }
}

/// A refused live admission does not invalidate an already-owned result.
/// This path has no native driver: identity and full loan restitution are its
/// authority, not a renewed claim about the token's current availability.
fn publish_retained_completion(
    session: &Session,
    ticket: &mut OperationTicket,
    admission: crate::session::CleanupAdmission,
    diagnostics: &mut PollDiagnostics,
) -> Result<Option<OperationProgress>> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Ok(None);
    }
    // Both anchors outlive every coordination guard, including error exits.
    let mut retired_owner = None;
    let mut released = ReleasedInputs::default();
    let result = (|| {
        // Coordinate with native users and administration without asserting
        // that this original runtime/token is still valid for a native call.
        let state = session.inner.state.read_admitted(matches!(
            admission,
            crate::session::CleanupAdmission::Module
        ))?;
        // Preserve the exact drain authority already checked by the public
        // owner. Observing a drain never grants that authority to an ordinary
        // caller; these guards still authorize no native operation.
        let _token = match admission {
            crate::session::CleanupAdmission::Module => {
                session.snapshot.module_cleanup_activity()?
            }
            crate::session::CleanupAdmission::Token => session.snapshot.cleanup_activity(true)?,
            crate::session::CleanupAdmission::Ordinary => {
                session.snapshot.observation_activity()?
            }
        };
        let _session = session.entry.operation.acquire(&session.admission())?;
        if session.entry.advanced_progress.retired(ticket.id)? {
            return Ok(None);
        }
        let held = state.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id || !operation._token.identity().matches(&session.entry) {
            return Ok(None);
        }
        if matches!(
            &operation.body,
            OperationBody::Admission(_) | OperationBody::Control
        ) || !operation.body.complete()
            || !operation.terminal_retirable()
            || operation.cancellation.is_withdrawn()
            || operation.continuation_status.is_frozen()
            || operation
                .validation
                .as_ref()
                .is_some_and(|capture| !capture.publication_ready())
        {
            return Ok(None);
        }
        released.owner = Some(held.clone());
        // Retirement is fallible, so perform it before moving any result.
        // The session gate excludes replacement; the exact owner remains
        // anchored until after all guards leave, even if projection fails.
        retired_owner = state.operations.take_closed(&session.entry)?;
        ticket.id = 0;
        publish_completed_result(&mut operation, session, ticket, &mut released)?;
        Ok(released.result.take())
    })();
    // Preserve the same public-boundary credit anchor as the live driver.
    // Replacing an earlier anchor here happens after every guard has left.
    if let Some(owner) = released.take_owner() {
        diagnostics.retired_owner = Some(owner);
    }
    drop(retired_owner);
    match result {
        // A local coordination refusal must not replace the original driver
        // error. Only a consumed local publication owns its projection error.
        Err(_) if ticket.id != 0 => Ok(None),
        result => result,
    }
}

fn poll_live_operation(
    session: &Session,
    ticket: &mut OperationTicket,
    admission: crate::session::CleanupAdmission,
    pacing: OperationPacing,
    diagnostics: &mut PollDiagnostics,
) -> Result<OperationProgress> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::Authentication(
            crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
        )));
    }
    let resource_admission = crate::admission_wait::current();
    let mut prepared: Option<ResourceCandidate> = None;
    let mut waiter: Option<progress::Waiter<'_>> = None;
    let mut remaining = pacing.budget();
    let mut observe = true;
    loop {
        // No error from the previous iteration is being published on a retry.
        // Release its anchor before another preparation or possession begins.
        drop(diagnostics.retired_owner.take());
        // Declared before access: operand erasure and credit notification run
        // after operation, session, token and module possession has unwound.
        let mut retired_diagnostics = None;
        let mut released = ReleasedInputs::default();
        let access = session.advanced_access_admitted(admission)?;
        // Move prepaid storage before poll_owned can retire its owner. A new
        // public retry replenishes a consumed envelope outside all possession;
        // cancellation never acquires resources merely to observe its result.
        let replenish = {
            session.entry_common(&access)?;
            if session.entry.advanced_progress.retired(ticket.id)? {
                ticket.id = 0;
                return Err(Error::Rejected(crate::RejectionReason::Authentication(
                    crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
                )));
            }
            let held = access.operations.get(ticket.uid)?;
            let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            let withdrawn = operation.cancellation.is_withdrawn();
            if let OperationBody::Admission(body) = &mut operation.body {
                if diagnostics.failure.is_none() {
                    diagnostics.failure = body.resource_diagnostics.take();
                } else {
                    retired_diagnostics = body.resource_diagnostics.take();
                }
                if diagnostics.failure.is_none() && !withdrawn && body.may_prepare_resource() {
                    Some(Arc::clone(body.resource_budget()))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(budget) = replenish {
            drop(access);
            drop(retired_diagnostics);
            diagnostics.failure = Some(progress::FailureDiagnostics::prepare_for_poll(
                session,
                &budget,
                diagnostics.retained_bytes(),
                ticket.id,
                admission,
            )?);
            continue;
        }
        let mut claimed = false;
        if let Some(waiting) = waiter.as_mut() {
            session.entry_common(&access)?;
            if session.entry.advanced_progress.retired(ticket.id)? {
                ticket.id = 0;
                return Err(Error::Rejected(crate::RejectionReason::Authentication(
                    crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
                )));
            }
            let held = access.operations.get(ticket.uid)?;
            let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            operation.check_control_access(&session.entry)?;
            let current = match &operation.body {
                OperationBody::Admission(body) => body.resource_need(),
                _ => None,
            };
            let valid = !waiting.changed()
                && current.as_ref().is_some_and(|need| {
                    prepared
                        .as_ref()
                        .is_some_and(|candidate| need.same(&candidate.need()))
                });
            waiting.succeed()?;
            if !valid {
                drop(operation);
                drop(held);
                drop(access);
                drop(prepared.take());
                drop(waiter.take());
                continue;
            }
            access
                .operations
                .claim_progress(&session.entry, operation.id)?;
            claimed = true;
            let OperationBody::Admission(body) = &mut operation.body else {
                unreachable!()
            };
            body.attach_resource(prepared.take().expect("matching resource candidate"))?;
        }
        let result = poll_owned(
            session,
            ticket,
            &access,
            observe,
            &mut remaining,
            claimed,
            &mut released,
        );
        // The destination was cleared before possession. Moving this anchor
        // cannot destroy an old body under the session/operation guards.
        diagnostics.retired_owner = released.owner.take();
        let result = result?;
        if !matches!(result, OperationProgress::Ready) {
            if matches!(result, OperationProgress::Pending) && diagnostics.failure.is_some() {
                let held = access.operations.get(ticket.uid)?;
                let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
                if operation.id == ticket.id {
                    if let OperationBody::Admission(body) = &mut operation.body {
                        if body.resource_diagnostics.is_none() {
                            body.resource_diagnostics = diagnostics.failure.take();
                        }
                    }
                }
            }
            return Ok(result);
        }
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        let request = match &operation.body {
            OperationBody::Admission(body) => body
                .resource_need()
                .map(|need| (need, Arc::clone(body.resource_budget()))),
            _ => None,
        };
        let Some((need, budget)) = request else {
            if let OperationBody::Admission(body) = &mut operation.body {
                if body.resource_diagnostics.is_none() {
                    body.resource_diagnostics = diagnostics.failure.take();
                }
            }
            return Ok(result);
        };
        operation.check_control_access(&session.entry)?;
        // A failed response preparation preserves Admission, its cursor, any created
        // objects and the exact native response. It performs no terminal retire.
        waiter = Some(progress::Waiter::new(
            session,
            operation.id,
            progress::Effect::PreserveOwner,
        )?);

        drop(operation);
        drop(held);
        drop(access);
        drop(retired_diagnostics);
        let waiting = waiter.as_mut().expect("registered resource waiter");

        match ResourceCandidate::prepare(
            need,
            &budget,
            diagnostics.retained_bytes(),
            &resource_admission,
            || {
                preparation::context(session)?;
                Ok(waiting.changed().then_some(()))
            },
        ) {
            Ok(PreparedResource::Ready(candidate)) => prepared = Some(candidate),
            Ok(PreparedResource::Redirect(())) => {
                waiting.succeed()?;
            }
            Err(error) => {
                return Err(waiting.fail_prepared(
                    error,
                    diagnostics
                        .failure
                        .as_mut()
                        .expect("prepaid admission poll diagnostics"),
                ));
            }
        }
        observe = false;
    }
}

// A synchronous contextual sequence supplies the same exclusive access from
// before Init through login and key use. Recheck identity/epoch even when no
// lock acquisition is needed for the next step.
pub(super) fn poll_with_access(
    session: &Session,
    ticket: &mut OperationTicket,
    s: &crate::session::SessionAccess<'_>,
    pacing: OperationPacing,
    released: &mut ReleasedInputs,
) -> Result<OperationProgress> {
    // The caller declares this fresh retirement owner before acquiring s.
    // It must outlive that access, including all error-return paths.
    poll_owned(
        session,
        ticket,
        s,
        true,
        &mut pacing.budget(),
        false,
        released,
    )
}

fn poll_owned(
    session: &Session,
    ticket: &mut OperationTicket,
    s: &crate::session::SessionAccess<'_>,
    observe: bool,
    remaining: &mut usize,
    claimed: bool,
    released: &mut ReleasedInputs,
) -> Result<OperationProgress> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::Authentication(
            crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
        )));
    }
    if !s.owns_session(session) {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOperationDriverAccess,
        )));
    }
    session.entry_common(s)?;
    if session.entry.advanced_progress.retired(ticket.id)? {
        ticket.id = 0;
        return Err(Error::Rejected(crate::RejectionReason::Authentication(
            crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
        )));
    }
    let held = s.operations.get(ticket.uid)?;
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    if operation.id != ticket.id {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::StaleOperationTicket,
        )));
    }
    // Each caller supplies a fresh retirement owner declared before access.
    // Install this anchor before any driver or cancellation can retire a slot.
    released.owner = Some(held.clone());
    // A successful crypto cancellation does not release an independently
    // pending validation query. Observe only that query, never resume crypto.
    if operation.cancellation.is_withdrawn()
        && !operation.cancel.is_submitted()
        && operation.uncancellable_pending()
    {
        if operation.state_io().is_some_and(|c| c.pending()) {
            operation
                .state_io_mut()
                .unwrap()
                .drive(s, &session.entry, observe, remaining)?;
        } else if operation.validation_pending() {
            operation
                .validation
                .as_mut()
                .unwrap()
                .drive(s, &session.entry, observe, remaining)?;
        } else if let OperationBody::Admission(body) = &mut operation.body {
            body.drive(s, &session.entry, observe, remaining)?;
        }
        if operation.uncancellable_pending() {
            return Ok(OperationProgress::Pending);
        }
        if operation.active_categories() == 0 && !operation.uncancellable_retained() {
            ticket.id = 0;
            drop(operation);
            s.operations.release_closed(&session.entry)?;
        }
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::CancelledOperationCannotContinue,
        )));
    }
    let awaiting_resource =
        matches!(&operation.body, OperationBody::Admission(body) if body.resource_need().is_some());
    if !claimed && !awaiting_resource && (*remaining != 0 || operation.body.complete()) {
        operation.check_continuation_authentication(&session.entry)?;
        s.operations.claim_progress(&session.entry, operation.id)?;
    }
    if let OperationBody::Admission(body) = &mut operation.body {
        if let Some(result) = body.deferred_creation_failure(session)? {
            return Ok(result);
        }
    }
    let driven = drive(s, &session.entry, &mut operation, observe, remaining);
    // Take established-return operands before error retirement can remove
    // the registered owner. Pending/uncertain operands remain in the body.
    released.inputs = match &mut operation.body {
        OperationBody::Messages(body) => ReturnedInputs::Typed {
            _inputs: body.take_released_inputs(),
        },
        OperationBody::NativeMessages(body) => ReturnedInputs::Native {
            _inputs: body.take_released_input(),
        },
        OperationBody::AeadMessages(body) => ReturnedInputs::Aead {
            _inputs: body.take_released_input(),
        },
        OperationBody::Signature(body) => ReturnedInputs::Signature {
            _inputs: body.take_returned_operands(),
        },
        OperationBody::Cipher(body) => ReturnedInputs::Cipher {
            _inputs: body.take_returned_operands(),
        },
        OperationBody::Digest(body) => ReturnedInputs::Digest {
            _inputs: body.take_returned_operands(),
        },
        _ => ReturnedInputs::None,
    };
    if let Err(error) = driven {
        // Retiring a terminal descriptive failure can release the operation's
        // registry entry. Retain completed creations before that release.
        let created = if let OperationBody::Admission(body) = &operation.body {
            body.created_objects(&session.inner)?
        } else {
            None
        };
        let (error, released) = operation.retire_terminal_error(s, &session.entry, error);
        if released {
            ticket.id = 0;
        }
        if let Some(objects) = created {
            return Ok(OperationProgress::CreatedObjects(crate::CreatedObjects {
                objects,
                observation: Err(error),
                remainder: None,
            }));
        }
        return Err(error);
    }
    if let OperationBody::Admission(body) = &mut operation.body {
        if !body.complete() {
            return Ok(unfinished(body.pending()));
        }
        // Finished native search/reads have no live output owners. A local
        // absent/ambiguous selector is terminal without poisoning the session.

        let result = body.result(s, session);
        // Publication can fail after creation. Keep its ticket, reservation
        // and buffers while targeted native destruction is still required.
        if !body.complete() {
            return result;
        }
        let retirement_diagnostic = body.take_retirement_diagnostic();
        // Consume the ticket once: result extraction must not be replayed after
        // a local ledger refusal. Failed retirement leaves the registry owner
        // retained; the already-published object references still reach the caller.
        ticket.id = 0;
        drop(operation);
        return match (result, s.operations.release_closed(&session.entry)) {
            (Ok(OperationProgress::CreatedObjects(mut outcome)), Err(failure)) => {
                outcome.observation = Err(match outcome.observation {
                    Ok(_) => failure,
                    Err(cause) => {
                        let mut diagnostic = retirement_diagnostic
                            .expect("prepared generation retirement diagnostic");
                        diagnostic.replace_operation(cause);
                        diagnostic.finish_sequence(Some(failure))
                    }
                });
                Ok(OperationProgress::CreatedObjects(outcome))
            }
            (result, Ok(())) => result,
            (_, Err(failure)) => Err(failure),
        };
    }
    if let Some(capture) = &operation.validation {
        if capture.waiting() {
            return Ok(unfinished(capture.pending()));
        }
    }
    if let OperationBody::Messages(body) = &operation.body {
        if let Some(request) = body.buffer_request() {
            return Ok(OperationProgress::SignatureBufferRequired(request));
        }
    }
    if let OperationBody::NativeMessages(body) = &operation.body {
        if let Some(request) = body.buffer_request() {
            return Ok(OperationProgress::SignatureBufferRequired(request));
        }
    }
    if let OperationBody::Signature(body) = &operation.body {
        if let Some(request) = body.buffer_request() {
            return Ok(OperationProgress::SignatureBufferRequired(request));
        }
    }
    if let OperationBody::Recover(body) = &operation.body {
        if let Some(request) = body.buffer_request() {
            return Ok(OperationProgress::RecoveryBufferRequired(request));
        }
    }
    if let OperationBody::AeadMessages(body) = &operation.body {
        if let Some(request) = body.buffer_request() {
            return Ok(OperationProgress::CipherBufferRequired(request));
        }
    }
    if let OperationBody::Cipher(body) = &operation.body {
        if let Some(request) = body.buffer_request() {
            return Ok(OperationProgress::CipherBufferRequired(request));
        }
    }
    if !operation.body.complete() {
        return Ok(unfinished(operation.body.pending()));
    }
    // All publication failures pass through the same ownership check,
    // including report extraction and the digest's requested observation.
    let publication = publish_completed_result(&mut operation, session, ticket, released);
    match publication {
        Ok(()) => {}
        Err(error) => {
            let (error, released) = operation.retire_terminal_error(s, &session.entry, error);
            if released {
                ticket.id = 0;
            }
            return Err(error);
        }
    };
    ticket.id = 0;
    drop(operation);
    s.operations.release_closed(&session.entry)?;
    Ok(released.result.take().expect("completed publication"))
}

/// Project a completed crypto body without any native call or current-token check.
fn publish_completed_result(
    operation: &mut super::Operation,
    session: &Session,
    ticket: &mut OperationTicket,
    released: &mut ReleasedInputs,
) -> Result<()> {
    let digest_validation = if matches!(&operation.body, OperationBody::Digest(d) if d.validation_requested)
    {
        Some(
            operation
                .validation
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::ValidationCollectorAbsent,
                )))?
                .first()?,
        )
    } else {
        None
    };
    let result = match &mut operation.body {
        OperationBody::Control => {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ControlHasNoCryptographicResult,
            )))
        }
        OperationBody::Admission(_) => {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::AdmissionResultOwner,
            )))
        }
        OperationBody::Dual(body) => body.result(&session.entry)?,
        OperationBody::Recover(body) => body.result(&session.entry)?,
        OperationBody::Signature(body) => body.result(&session.entry)?,
        OperationBody::Cipher(body) => body.result(&session.entry)?,
        OperationBody::AeadMessages(body) => body.result(&session.entry)?,
        OperationBody::Messages(body) => body.result(&session.entry)?,
        OperationBody::NativeMessages(body) => body.result(&session.entry)?,
        OperationBody::Digest(body) => {
            // Final established native termination and checked the selected width.
            if let Some(extension) = body.frame.extension.take() {
                OperationProgress::ExtensionDigest(extension.result(&mut body.frame.output))
            } else {
                body.frame
                    .selection
                    .result(&mut body.frame.output, digest_validation)?
            }
        }
    };
    released.result = Some(result);
    // No renewed native authorization is needed to publish completed output.
    ticket.validation_report = operation
        .validation
        .as_mut()
        .map(|c| c.take())
        .transpose()?;
    Ok(())
}
