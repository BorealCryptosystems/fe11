// SPDX-License-Identifier: Apache-2.0
//! A second Init preserves its predecessor on refusal, or replaces a clean
//! same-family owner after an intact native success. Mixed owners stay retained.
use super::SignatureOperation;
use crate::{native::frame::NativeFrame, session::SessionAccess, Error, Result, Session};
use crate::advanced::{ledger::OperationCell, OperationTicket};
use std::sync::{atomic::Ordering, Arc};

struct Call {
    operation: SignatureOperation,
    _credit: crate::symmetric::memory::Credit,
}

pub(super) struct Prepared {
    pub(super) frame_credit: crate::symmetric::memory::Credit,
    pub(super) diagnostic: crate::error::CompletionStorage,
    pub(super) diagnostic_credit: crate::symmetric::memory::Credit,
}

pub(super) fn preparation_bytes() -> usize {
    std::mem::size_of::<Call>() - std::mem::size_of::<SignatureOperation>()
        + crate::native::frame::SessionFrame::<'_, Call>::allocation_bytes()
        + crate::error::CompletionStorage::allocation_bytes()
}

pub(super) fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Prepared> {
    let mut frame_credit = prepaid.split(preparation_bytes())?;
    let diagnostic_credit =
        frame_credit.split(crate::error::CompletionStorage::allocation_bytes())?;
    Ok(Prepared {
        frame_credit,
        diagnostic: crate::error::CompletionStorage::allocate()?,
        diagnostic_credit,
    })
}

pub(super) fn attempt(
    session: &Session,
    access: SessionAccess<'_>,
    body: SignatureOperation,
    credit: crate::symmetric::memory::Credit,
    diagnostic: crate::error::CompletionStorage,
    replacement: &mut crate::advanced::operation::SignatureReplacement,
    retirement: &mut crate::advanced::PollDiagnostics,
    remaining: &mut usize,
) -> Result<(OperationTicket, Arc<OperationCell>)> {
    // The earlier owner remains in the ledger throughout. In particular this
    // attempt never uses retire_terminal_error, whose UID belongs to that owner.
    if crate::advanced::init_reader_borrow(session, &access, body.kind.category())?.is_none() {
        return Err(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::CompetingInitOwnerAbsent,
            ),
        ));
    }
    if !super::super::spend(remaining) {
        return Err(Error::Busy(crate::BusyReason::SignatureContinuation(
            crate::SignatureContinuationBusy::SignatureInitDispatchCredit,
        )));
    }
    let function = body.kind.init();
    // Prepared outside possession. The caller keeps its separate charge until
    // the public result transfer, even if the native frame must be retained.
    let diagnostic = diagnostic.bind(function);
    // The anchor and returned payload outlive the frame's access. In particular
    // an unwind drops the operation mutex before native recovery takes access.
    let retired;
    let _retired_anchor;
    let owner = access.operations.get(session.uid)?;
    let mut frame = NativeFrame::session(
        access,
        Call {
            operation: body,
            _credit: credit,
        },
    )?;
    let (returned, call) = frame.session_parts();
    let state = &call.access;
    let mut held = Some(owner.lock().map_err(|_| Error::Poisoned)?);
    let operation = held.as_mut().expect("resident owner locked");
    let id = operation.id;
    let ready = id == session.entry.advanced_operation.load(Ordering::Acquire)
        && operation._token.identity().matches(&session.entry)
        && session.entry.advanced_progress.replacement_ready(id)?
        && operation.signature_replacement_target(call.data.operation.kind).is_some();
    let new_id = if ready {
        Some(state.operations.reserve_ticket()?)
    } else {
        // Preserve the existing native dispatch on mixed/control owners. They
        // cannot be discarded, and no new local refusal is introduced here.
        drop(held.take());
        None
    };
    call.data.operation.check_key(&session.entry)?;
    // Resolve before recording or arming this competing attempt. The earlier
    // operation remains owned by the ledger throughout the native call.
    let native_call = super::resolved_call::Call::resolve(
        &state.native,
        call.data.operation.kind,
        call.data.operation.stage,
        call.data.operation.route,
    )?;
    let classic = match (&native_call, call.data.operation.kind) {
        (super::resolved_call::Call::Init(_), super::Kind::Sign) =>
            Some(crate::native::frame::ClassicInit::Sign),
        (super::resolved_call::Call::Init(_), super::Kind::Verify) =>
            Some(crate::native::frame::ClassicInit::Verify),
        _ => None,
    };
    state.native.record(function)?;
    call.data.operation.revoke_before_init();
    returned.arm();
    // SAFETY: the new frame owns its mechanism graph, key protection and input
    // storage at stable addresses. Session possession excludes another C call;
    // no pointer or ticket of the earlier owner is transferred or released.
    let rv = returned.observe(
        unsafe { call.data.operation.dispatch(native_call, &session.entry) },
        &state.native,
    );
    let version = state.native.table.version;
    let inspected =
        crate::native_return::protocol::PendingInspection::returned(function, rv, |scope| {
            state.apply_session_failure(&session.entry, rv, scope)
        })
        .inspect(|| {
            if call.data.operation.unchanged() {
                Ok(())
            } else {
                Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureNativeInputMutation,
                    ),
                ))
            }
        });
    let initialization_refused = inspected.initialization_refused(
        (version.major, version.minor),
        crate::native_return::protocol::SequencePhase::Initialize,
    );
    let result = match inspected.resolve(|_, cause| cause) {
        Ok(result) => result,
        Err(cause) => {
            returned.quarantine(&state.native);
            session.poison(state);
            return Err(diagnostic.boundary_failure(rv, cause));
        }
    };
    if initialization_refused {
        // A refused non-NULL Init returned B’s own loan. Release B only: no
        // Final, cancel, ledger removal, or mutation of A's public ticket.
        returned.attempt_returned();
        return result
            .check(call.data.operation.contract.mutates_key())
            .and(Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::ConflictingInitReturnedNoError,
                ),
            )));
    }
    if rv == fe11_sys::CKR_OK {
        if let (Some(id), Some(kind), Some(operation)) =
            (new_id, classic, held.as_mut())
        {
            // Reborrow the prevalidated resident slots before publication. No
            // other operation can change them while possession/body are held.
            let transfer = returned.accepted_init(kind, function, &state.native);
            let target = operation.signature_replacement_target(call.data.operation.kind);
            if let (Ok(transfer), Some(target)) = (transfer, target) {
                call.data.operation.accept_initialization();
                let ticket = OperationTicket {
                    owner: session.inner.clone(),
                    uid: session.uid,
                    id,
                    validation_report: None,
                    state_provenance: None,
                };
                if let Err(cause) = state.operations.publish_replacement(&session.entry, id) {
                    if state.native.is_uncertain() {
                        returned.quarantine(&state.native);
                    } else {
                        returned.recoverable();
                    }
                    session.poison(state);
                    return diagnostic.finish_native(rv, Err(cause));
                }
                // From publication through disarming: pointer/field swaps only.
                // No allocation, Result, new lock, callback or resource Drop.
                target.commit(&mut call.data.operation, transfer, replacement, id);
                _retired_anchor = retirement.retired_owner.replace(owner.clone());
                drop(held);
                // The transfer proved Owned; ordinary extraction now happens
                // outside the resident mutex, never on an Active frame. The old
                // payload is destroyed only after its access has been released.
                // into_inner's Err is unreachable here: replace_into just set
                // Owned and neither it nor the metadata commit can take body.
                retired = match frame.into_inner() {
                    Ok(frame) => frame.retire_after_access(),
                    Err(cause) => return diagnostic.finish_native(rv, Err(cause)),
                };
                drop(retired);
                return Ok((ticket, owner));
            }
        }
        // A simultaneous control/mixed owner or independent uncertainty cannot
        // be erased. Retain both payloads until explicit native recovery.
        if new_id.is_some() && state.native.is_uncertain() {
            returned.quarantine(&state.native);
        } else {
            // With no eligible replacement, preserve the existing disposition.
            // This does not clear independent module uncertainty or authorize
            // releasing a graph when native close itself is quarantined.
            returned.recoverable();
        }
    } else {
        // Pending or an altered graph cannot use the ordinary
        // close lifetime. Preserve the stronger memory/execution quarantine.
        returned.quarantine(&state.native);
    }
    // Neither operation may resume through an ambiguous native sequence. This
    // withdrawal does not forbid explicit logout or session closure.
    session.poison(state);
    let cause = Error::Rejected(crate::RejectionReason::SignatureContinuation(
        crate::SignatureContinuationRejection::CompetingSignatureInitOutcomeUncertain,
    ));
    if rv == fe11_sys::CKR_OK {
        // This names completion of Init only, never of the signature sequence.
        diagnostic.finish_native(rv, Err(cause))
    } else {
        Err(diagnostic.boundary_failure(rv, cause))
    }
}
