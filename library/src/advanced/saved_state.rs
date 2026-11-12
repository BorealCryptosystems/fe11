// SPDX-License-Identifier: Apache-2.0
//! Owned native state; captured and service-asserted imported provenance remain distinct.
use super::continuation::Continuation;

use super::{
    ownership, preparation, progress, record, rejoin, AdvancedSession, Operation, OperationBody,
    OperationTicket,
};

use crate::{
    module::{Inner, SessionEntry, State, TokenSnapshot},
    symmetric::memory::{Budget, Buffer, Credit},
    Error, Result, Session,
};
use fe11_sys::CK_STATE;
use std::sync::{Arc, Weak};

/// How the state entered this process; not an archive-authentication verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateProvenance {
    /// Captured from a locally initiated operation observed by this process.
    CapturedInProcess,
    /// Derived from an explicit trusted-service import, including later captures.
    Imported,
}
#[doc = include_str!("../../docs/api/advanced/saved_state/SavedOperationState.md")]
pub struct SavedOperationState {
    pub(super) provenance: StateProvenance,
    pub(super) owner: Weak<Inner>,
    pub(super) snapshot: Arc<TokenSnapshot>,
    pub(super) authentication: u64,
    pub(super) session_state: CK_STATE,
    pub(super) bytes: Option<Buffer>,
    pub(super) continuation: Continuation,
    pub(super) _credit: Credit,
}
impl SavedOperationState {
    /// Provenance is never promoted by recapture or by a serialized field.
    pub fn provenance(&self) -> StateProvenance {
        self.provenance
    }

    pub(super) fn write_checkpoint_with_native(
        &self,
        budget: &Arc<Budget>,
        limits: record::Limits,
        context: &record::Context,
        native: &[u8],
        writer: &mut record::Writer<'_>,
    ) -> Result<()> {
        context.write(writer)?;
        self.continuation.write_checkpoint(budget, writer, limits)?;
        writer.bytes(native)
    }

    pub(super) fn checkpoint_context(&self) -> Result<record::Context> {
        let owner =
            self.owner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::Persistence(
                    crate::PersistenceRejection::CapturedModuleNoLongerOwned,
                )))?;
        self.snapshot
            .check_authentication_unchanged(self.authentication)?;
        record::Context::from_snapshot(&owner, &self.snapshot, self.session_state)
    }
}
/// Explicit progress of the state-capture control, distinct from crypto output.
pub enum StateCaptureProgress {
    /// Yielded between completed native calls; poll the capture explicitly.
    Ready,
    /// Native control is pending and retains all its owned buffers.
    Pending,
    /// Complete in-process capture. No archive-integrity assertion is implied.
    Captured(SavedOperationState),
}
pub(super) struct CaptureOwner {
    provenance: StateProvenance,
    owner: Weak<Inner>,
    snapshot: Arc<TokenSnapshot>,
    authentication: u64,
    continuation: Continuation,
    // An idle capture retains one prepaid waiter envelope across public polls.
    // An invocation borrows it exclusively; concurrent invocations prepare
    // their own envelope before engaging, never share consumable error leaves.
    pub(super) resource_diagnostics: Option<progress::FailureDiagnostics>,
    _credit: Credit,
}
impl CaptureOwner {
    pub(super) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + std::mem::size_of::<SavedOperationState>()
    }
    pub(super) fn from_continuation_prepaid(
        session: &Session,
        provenance: Option<StateProvenance>,
        continuation: Continuation,
        credit: Credit,
    ) -> Self {
        Self {
            provenance: provenance.unwrap_or(StateProvenance::CapturedInProcess),
            owner: Arc::downgrade(&session.inner),
            snapshot: session.snapshot.clone(),
            authentication: session.snapshot.authentication_stamp(),
            continuation,
            resource_diagnostics: None,
            _credit: credit,
        }
    }
    pub(super) fn write_checkpoint(
        &self,
        budget: &Arc<Budget>,
        w: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        self.snapshot
            .check_authentication_unchanged(self.authentication)?;
        self.continuation.write_checkpoint(budget, w, limits)
    }
    pub(super) fn check_keys(&self, entry: &SessionEntry) -> Result<()> {
        self.snapshot
            .check_authentication_unchanged(self.authentication)?;
        rejoin::check_keys(&self.continuation.body, entry)
    }
}
fn check_ticket(session: &Session, ticket: &OperationTicket) -> Result<()> {
    if ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner) {
        return Err(Error::Rejected(crate::RejectionReason::Authentication(
            crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
        )));
    }
    Ok(())
}

impl Operation {
    pub(super) fn cleanup_capture_resource_failure(&mut self) {
        let Some(owner) = self.capture_owner() else {
            return;
        };
        let Some(io) = self.state_io() else {
            return;
        };
        let freeze = io.captured() && owner.continuation.encrypting;
        let removable = !io.pending() && self.joined.is_none();
        if freeze {
            self.continuation_status =
                ownership::ContinuationStatus::Frozen(ownership::FreezeReason::CapturedEncryption);
        }
        if removable {
            self.state.take();
        }
    }
}

enum CaptureAdvance {
    Progress(StateCaptureProgress),
    NeedBuffer(usize),
}

impl AdvancedSession {
    /// Capture the currently active cryptographic operation and its owned plan.
    /// Maximum native state length is explicit and also charged to the common
    /// byte budget. No retry, cancellation or persistence service is introduced.
    /// Run a cooperative plan to choose a boundary between native steps.
    /// If a successful native size query exceeds the bound, OutputSizeRejected
    /// retains that query's code, length and maximum. No state bytes are captured
    /// by that query and the library does not raise the maximum or repeat it.
    pub fn start_state_capture(
        &self,
        ticket: &OperationTicket,
        maximum_bytes: usize,
    ) -> Result<StateCaptureProgress> {
        self.capture_control(ticket, Some(maximum_bytes))
    }
    /// Observe at most one pending completion, then follow the selected pacing.
    /// A completed sizing response is retained while memory admission waits;
    /// this never repeats GetOperationState's sizing call or renews a deadline.
    /// OutputSizeRejected preserves a size query rejected by the caller's bound,
    /// with the same diagnostic contract as start_state_capture.
    pub fn poll_state_capture(&self, ticket: &OperationTicket) -> Result<StateCaptureProgress> {
        self.capture_control(ticket, None)
    }

    fn capture_control(
        &self,
        ticket: &OperationTicket,
        maximum: Option<usize>,
    ) -> Result<StateCaptureProgress> {
        check_ticket(&self.session, ticket)?;
        preparation::context(&self.session)?;
        // Kept through the complete public start/poll call, including helper
        // errors and re-preparation. Waiter registration never owns this credit.
        let mut diagnostics = None;
        let admission = crate::admission_wait::current();
        // These owners precede every access guard, including error/unwind exits.
        let mut initial = maximum
            .map(|maximum| {
                super::capture_preparation::prepare(
                    &self.session,
                    ticket,
                    maximum,
                    &mut diagnostics,
                )
            })
            .transpose()?;
        let mut prepared: Option<Buffer> = None;
        let mut waiter: Option<progress::Waiter<'_>> = None;
        let mut retired_state = None;
        let mut _retired_operation = None;
        let mut remaining = self.pacing.budget();
        let mut observe = maximum.is_none();
        loop {
            // A peer may have returned an unused envelope while this call was
            // preparing a buffer. Its destruction must follow the guards, but
            // precede any further resource wait in this invocation.
            let mut retired_diagnostics = None;
            let access = self.session.advanced_access()?;
            let held = access.operations.get(ticket.uid)?;
            let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            // The atomic resource-wait predicate only routed this caller.
            // Revalidate authority before attaching any prepared candidate.
            operation.check_authentication(&self.session.entry)?;
            if initial.is_none() || operation.cancellation.is_withdrawn() {
                if let Some(owner) = operation.capture_owner_mut() {
                    if diagnostics.is_none() {
                        diagnostics = owner.resource_diagnostics.take();
                    } else {
                        retired_diagnostics = owner.resource_diagnostics.take();
                    }
                }
            }
            if operation.cancellation.is_withdrawn() {
                if let Some(waiting) = waiter.as_mut() {
                    waiting.succeed()?;
                }
                // Neither prepared input nor a newly admitted buffer belongs
                // to a withdrawn capture. Only its existing native borrower may
                // be observed, with the original pacing/observation allowance.
                return match self.advance_state_capture(
                    &access,
                    &mut operation,
                    observe,
                    &mut remaining,
                    &mut retired_state,
                )? {
                    CaptureAdvance::Progress(progress) => Ok(progress),
                    CaptureAdvance::NeedBuffer(_) => {
                        Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::CancelledStateCapture,
                        )))
                    }
                };
            }
            let mut claimed = false;
            if initial.is_some() {
                if operation.capture_owner().is_some() {
                    return Err(Error::Busy(crate::BusyReason::CheckpointCapture(
                        crate::CheckpointCaptureBusy::StateCaptureActive,
                    )));
                }
                if initial
                    .as_ref()
                    .is_some_and(|prepared| prepared.waiter.changed())
                {
                    initial
                        .as_mut()
                        .expect("initial capture")
                        .waiter
                        .succeed()?;
                    drop(operation);
                    drop(held);
                    drop(access);
                    drop(initial.take());
                    initial = Some(super::capture_preparation::prepare(
                        &self.session,
                        ticket,
                        maximum.expect("initial capture maximum"),
                        &mut diagnostics,
                    )?);
                    continue;
                }
                let mut prepared = initial.take().expect("initial capture");
                Continuation::check_capture(&operation, &self.session.entry)?;
                prepared.waiter.succeed()?;
                let (io, owner) = (prepared.io, prepared.owner);
                access
                    .operations
                    .claim_progress(&self.session.entry, operation.id)?;
                claimed = true;
                operation.begin_capture(|| (io, owner))?;
            }
            if operation.capture_owner().is_none() || operation.state_io().is_none() {
                return Err(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateCaptureAbsent,
                )));
            }
            if diagnostics.is_none() {
                // A peer may currently own the envelope, or a previous
                // error consumed it. The ordinary Ready/Pending path keeps
                // it prepaid. Replenishment precedes every native effect
                // of this invocation and retains the original deadline.
                drop(operation);
                drop(held);
                drop(access);
                diagnostics = Some(progress::FailureDiagnostics::prepare(
                    &self.session,
                    ticket.id,
                )?);
                continue;
            }
            if let Some(waiting) = waiter.as_mut() {
                let valid = !waiting.changed()
                    && prepared.as_ref().is_some_and(|bytes| {
                        operation.state_io().and_then(|io| io.buffer_needed())
                            == Some(bytes.capacity())
                    });
                waiting.succeed()?;
                if valid {
                    access
                        .operations
                        .claim_progress(&self.session.entry, operation.id)?;
                    claimed = true;
                    operation
                        .state_io_mut()
                        .unwrap()
                        .attach_capture_buffer(prepared.take().unwrap())?;
                } else {
                    // No copied native/source owner escapes the old revision.
                    // Discard its unused candidate only after releasing guards.
                    drop(operation);
                    drop(held);
                    drop(access);
                    drop(prepared.take());
                    drop(waiter.take());
                    continue;
                }
            }
            if !claimed
                && operation
                    .state_io()
                    .and_then(|io| io.buffer_needed())
                    .is_none()
                && (remaining != 0 || operation.state_io().is_some_and(|io| io.complete()))
            {
                access
                    .operations
                    .claim_progress(&self.session.entry, operation.id)?;
            }
            let result = self.advance_state_capture(
                &access,
                &mut operation,
                observe,
                &mut remaining,
                &mut retired_state,
            )?;
            match result {
                CaptureAdvance::Progress(progress) => {
                    if matches!(operation.body, OperationBody::Control)
                        && matches!(&progress, StateCaptureProgress::Captured(_))
                    {
                        _retired_operation = access.operations.take_closed(&self.session.entry)?;
                    }
                    if let Some(owner) = operation.capture_owner_mut() {
                        if owner.resource_diagnostics.is_none() {
                            owner.resource_diagnostics = diagnostics.take();
                        }
                        // If a peer returned its own unused envelope first,
                        // this invocation drops its surplus after the guards.
                    }
                    return Ok(progress);
                }
                CaptureAdvance::NeedBuffer(length) => {
                    waiter = Some(progress::Waiter::new(
                        &self.session,
                        operation.id,
                        progress::Effect::RemoveStateIo,
                    )?);
                    let authentication = operation._token.authentication;
                    drop(operation);
                    drop(held);
                    drop(access);
                    drop(retired_diagnostics.take());
                    let waiting = waiter.as_mut().expect("registered resource waiter");
                    let diagnostics = diagnostics.as_mut().expect("capture diagnostics prepared");
                    let result = Buffer::new_controlled_retaining(
                        diagnostics.budget(),
                        length,
                        crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                        &admission,
                        || {
                            preparation::context(&self.session)?;
                            self.session
                                .snapshot
                                .observe_authentication_unchanged(authentication)?;
                            Ok(waiting.changed().then_some(()))
                        },
                    );
                    match result {
                        Ok(crate::symmetric::memory::PreparedBuffer::Ready(bytes)) => {
                            prepared = Some(bytes)
                        }
                        Ok(crate::symmetric::memory::PreparedBuffer::Redirect(())) => {
                            waiting.succeed()?;
                        }
                        Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
                    }
                    // The initial observation allowance and pacing counter are
                    // carried through memory preparation, never reset by it.
                    observe = false;
                }
            }
        }
    }
    fn advance_state_capture(
        &self,
        s: &State,
        op: &mut Operation,
        observe: bool,
        remaining: &mut usize,
        retired: &mut Option<ownership::StateControl>,
    ) -> Result<CaptureAdvance> {
        // A capture can pause between its native calls. Its source operation,
        // not just the newly allocated capture owner, determines the epoch.
        op.check_authentication(&self.session.entry)?;
        if op.cancel.is_submitted() {
            return Err(Error::Busy(crate::BusyReason::Cancellation(
                crate::CancellationBusy::CancellationPending,
            )));
        }
        if op.detachment().is_some() || op.rejoin().is_some() {
            return Err(Error::Busy(crate::BusyReason::OperationState(
                crate::OperationStateBusy::StateCaptureTransfer,
            )));
        }
        let withdrawn = op.cancellation.is_withdrawn();
        let result = (|| -> Result<()> {
            if !op.drive_join(s, &self.session.entry, observe, remaining)? {
                return Ok(());
            }
            let io = op.state_io_mut().ok_or(Error::Rejected(
                crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateIoAbsent,
                ),
            ))?;
            if withdrawn {
                io.observe_pending(s, &self.session.entry, observe, remaining)
            } else {
                io.drive(s, &self.session.entry, observe, remaining)
            }
        })();
        let io = op
            .state_io()
            .ok_or(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateIoAbsent,
            )))?;
        let (captured, pending, complete) = (io.captured(), io.pending(), io.complete());
        // Read local completion metadata under the same guard, then freeze before
        // publication. No provider-owned output is accessed while pending.
        if captured && op.capture_owner().unwrap().continuation.encrypting {
            op.continuation_status =
                ownership::ContinuationStatus::Frozen(ownership::FreezeReason::CapturedEncryption);
        }
        if let Err(error) = result {
            if !pending && op.joined.is_none() && !s.native.is_uncertain() {
                *retired = op.state.take();
            }
            return Err(error);
        }
        if withdrawn {
            if pending || op.joined.is_some() {
                return Ok(CaptureAdvance::Progress(StateCaptureProgress::Pending));
            }
            if !s.native.is_uncertain() {
                *retired = op.state.take();
            }
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::CancelledStateCapture,
            )));
        }
        if let Some(length) = op.state_io().and_then(|io| io.buffer_needed()) {
            return Ok(CaptureAdvance::NeedBuffer(length));
        }
        if !complete {
            return Ok(CaptureAdvance::Progress(if pending {
                StateCaptureProgress::Pending
            } else {
                StateCaptureProgress::Ready
            }));
        }
        let owner = op.capture_owner().unwrap();
        owner
            .snapshot
            .check_authentication_unchanged(owner.authentication)?;
        // All metadata and continuation storage was reserved before native IO.
        // The only state publication is this move of already-owned values.
        let (session_state, bytes) = op.state_io_mut().unwrap().take_capture()?;
        let owner = op.take_capture().unwrap().1;
        Ok(CaptureAdvance::Progress(StateCaptureProgress::Captured(
            SavedOperationState {
                provenance: owner.provenance,
                owner: owner.owner,
                snapshot: owner.snapshot,
                authentication: owner.authentication,
                session_state,
                bytes: Some(bytes),
                continuation: owner.continuation,
                _credit: owner._credit,
            },
        )))
    }
}

impl SavedOperationState {
    /// Storage cannot leave this consumed source before export/restore finishes.
    pub(super) fn retained_bytes(
        &self,
        budget: &Arc<Budget>,
    ) -> Result<crate::symmetric::memory::RetainedBytes> {
        use crate::symmetric::memory::RetainedStorage;
        crate::symmetric::memory::RetainedBytes::measure(budget, |retained| {
            self.bytes.retain_credits(retained)?;
            self.continuation.retain_credits(retained)?;
            retained.add_credit(&self._credit)
        })
    }
}
