// SPDX-License-Identifier: Apache-2.0
//! Explicit transfer from a native pending call into a keyless owned record.
use super::continuation::Continuation;

use super::{
    asynchronous, ownership, progress, record, record_preparation, rejoin, spend, state_io,
    terminal, AdvancedSession, AdvancedSessionMode, NativeActivity, Operation, OperationBody,
    OperationTicket, StateProvenance,
};
use crate::{
    bounds,
    module::State,
    symmetric::memory::{Buffer, Credit},
    Error, Result, Session,
};

use fe11_sys::CK_ULONG;
use std::sync::Arc;
mod preparation;

#[doc = include_str!("../../docs/api/advanced/detachment/DetachedOperation.md")]
pub struct DetachedOperation {
    pub(super) provenance: Option<StateProvenance>,
    pub(super) record: Buffer,
    pub(super) limits: record::Limits,
    pub(super) _credit: Credit,
}
/// Progress of explicit detachment, never a cryptographic result.
pub enum DetachmentProgress {
    /// Between native control calls; poll explicitly to continue the transfer.
    Ready,
    /// The owned session-inspection control still retains its native buffers.
    Pending,
    /// GetID succeeded and the source continuation has been consumed.
    Detached(DetachedOperation),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DetachKind {
    Cryptographic,
    Capture,
    TerminalValidation,
}

impl DetachKind {
    fn select(capture: bool, terminal: bool) -> Result<Self> {
        match (capture, terminal) {
            (false, false) => Ok(Self::Cryptographic),
            (true, false) => Ok(Self::Capture),
            (false, true) => Ok(Self::TerminalValidation),
            _ => Err(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::ConflictingDetachmentOwners,
            ))),
        }
    }
}
pub(super) struct DetachControl {
    get_id: asynchronous::GetId,
    id: Option<CK_ULONG>,
    function: record::Function,
    capacity: Option<usize>,
    context: Option<record::Context>,
    authentication: u64,
    limits: record::Limits,
    kind: DetachKind,
    inspection: Option<Box<state_io::Inspection>>,
    record_storage: Option<Buffer>,
    publication_credit: Option<Credit>,
    _credit: Credit,
}
impl DetachControl {
    pub(super) fn execution_incomplete(&self) -> bool {
        self.get_id.execution_incomplete() || self.inspection_pending()
    }
    fn record_kind(&self) -> record::Kind {
        match self.kind {
            DetachKind::Cryptographic => record::Kind::Detached,
            DetachKind::Capture => record::Kind::DetachedCapture,
            DetachKind::TerminalValidation => record::Kind::DetachedValidation,
        }
    }
    pub(super) fn inspection_pending(&self) -> bool {
        self.inspection.as_ref().is_some_and(|io| io.pending())
    }
}

impl Drop for DetachControl {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(id) = &mut self.id {
            id.zeroize();
        }
    }
}

fn limits(maximum: usize) -> Result<record::Limits> {
    // Same closed per-message bounds as the canonical record, not a store rule.
    if maximum < 17 || maximum > isize::MAX as usize {
        return Err(Error::Rejected(crate::RejectionReason::Detachment(
            crate::DetachmentRejection::DetachmentRecordCeiling,
        )));
    }
    bounds::ck_length(maximum)?;
    Ok(record::Limits {
        bytes: maximum,
        messages: 1024,
        fragments: 1024,
    })
}
fn check_ticket(session: &Session, ticket: &OperationTicket) -> Result<()> {
    if ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner) {
        return Err(Error::Rejected(crate::RejectionReason::Authentication(
            crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
        )));
    }
    Ok(())
}
impl AdvancedSession {
    /// Begin an explicit transfer of the current pending cryptographic call.
    /// Native detachment requires the unsupported native asynchronous mode. Current synchronous
    /// sessions reject it before native detachment. The retained control below
    /// describes that protocol's ownership, not a currently enabled mode.
    ///
    /// This control observes session identity once and requests GetID once.
    /// Ownership and phase checks precede native detachment. No crypto call is retried.
    /// A late record-allocation failure leaves the source frozen with its ID;
    /// poll_detachment can finish local publication without reissuing GetID.
    /// Final opaque-byte state capture is supported separately: rejoin returns
    /// a capture control, never an implicitly restored cryptographic operation.
    /// Its original crypto process stays frozen until explicit cancel or close.
    /// Terminal validation transfers an already completed result and its
    /// pending observation; rejoin never repeats a crypto finalization.
    /// Preparatory capture is supported; other control/admission families
    /// remain limited to the adapters explicitly listed below.
    pub fn start_detachment(
        &self,
        ticket: &mut OperationTicket,
        maximum_bytes: usize,
    ) -> Result<DetachmentProgress> {
        self.session.inner.module_binding.persistent_digest()?;
        check_ticket(&self.session, ticket)?;
        let mut diagnostics = None;
        let mut candidate: Option<preparation::Prepared> = None;
        let mut waiter: Option<progress::Waiter<'_>> = None;
        loop {
            let s = self.session.advanced_access()?;
            if self.session.entry.advanced_progress.retired(ticket.id)? {
                ticket.id = 0;
                return Err(Error::Rejected(crate::RejectionReason::Authentication(
                    crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
                )));
            }
            let operation = s.operations.get(ticket.uid)?;
            let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
            if op.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            if op.rejoin().is_some() {
                return Err(Error::Busy(crate::BusyReason::Cancellation(
                    crate::CancellationBusy::OperationRejoinControl,
                )));
            }
            if op.detachment().is_some() {
                return Err(Error::Busy(crate::BusyReason::Cancellation(
                    crate::CancellationBusy::OperationDetachmentControl,
                )));
            }
            if op.restore_owner().is_some() {
                return Err(Error::Busy(crate::BusyReason::Detachment(
                    crate::DetachmentBusy::RestorationRequiresItsTransferTicket,
                )));
            }
            if self.mode() != AdvancedSessionMode::Asynchronous {
                return Err(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::AsynchronousDetachmentSessionMode,
                )));
            }
            let budget = &self.session.inner.symmetric_budget;
            let limits = limits(maximum_bytes)?;
            let function_name = asynchronous::GetId::checked_function(&op)?;
            op.check_authentication(&self.session.entry)?;
            // No supported family is silently serialized as another operation. The
            // remaining admission/control families have no detachment adapter.
            if !matches!(
                op.body,
                OperationBody::Digest(_)
                    | OperationBody::Messages(_)
                    | OperationBody::AeadMessages(_)
                    | OperationBody::Dual(_)
            ) && !(matches!(op.body, OperationBody::Control) && op.capture_owner().is_some())
            {
                return Err(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::DetachmentOwnerAdapterNotIntegrated,
                )));
            }
            let capture = op.state_io().is_some();
            let capture_context = if let Some(io) = op.state_io() {
                op.capture_owner()
                    .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                        crate::DetachmentRejection::DetachmentCaptureOwnerAbsent,
                    )))?
                    .check_keys(&self.session.entry)?;
                let (state, _) = io.capture_metadata()?;
                Some(record::Context::from_snapshot(
                    &self.session.inner,
                    &self.session.snapshot,
                    state,
                )?)
            } else {
                None
            };
            let terminal = op.validation_pending();
            let kind = DetachKind::select(capture, terminal)?;
            if terminal && !op.body.complete() {
                return Err(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::NonterminalValidationAdapterNotIntegrated,
                )));
            }
            let capacity = op.joined_capacity()?;
            let function = record::Function::from_name(function_name)?;
            if terminal {
                rejoin::check_keys(&op.body, &self.session.entry)?;
                // This preview reads completed crypto/report metadata only. A
                // placeholder context is unnecessary: validate after inspection,
                // before GetID, with the actual source identity.
                record::encoded_size(limits, |w| {
                    terminal::write(&op.body, op.validation.as_ref().unwrap(), budget, w, limits)
                })?;
            }
            let preview_length = if capture {
                Some(record::encoded_size(limits, |w| {
                    capture_context.as_ref().unwrap().write(w)?;
                    op.capture_owner()
                        .unwrap()
                        .write_checkpoint(budget, w, limits)?;
                    record::DetachedRecord::write_tail(w, function, 0, capacity)
                })?)
            } else {
                None
            };
            if s.native.asynchronous.and_then(|f| f.get_id).is_none() {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::CAsyncGetIDUnavailable,
                    ),
                ));
            }
            let shape = preparation::Shape {
                function: function_name,
                preview_length,
                inspection: !capture,
            };
            if diagnostics.is_none() {
                // Do not charge unsupported detachment modes/families. Fund
                // the complete failure shape only after the pure preflight,
                // outside possession, then revalidate before registration.
                drop(op);
                drop(operation);
                drop(s);
                diagnostics = Some(progress::FailureDiagnostics::prepare(
                    &self.session,
                    ticket.id,
                )?);
                continue;
            }
            if let Some(waiting) = waiter.as_mut() {
                if waiting.changed() || candidate.as_ref().is_some_and(|p| p.shape != shape) {
                    waiting.succeed()?;
                    drop(op);
                    drop(operation);
                    drop(s);
                    drop(candidate.take());
                    drop(waiter.take());
                    continue;
                }
            }
            if let Some(mut prepared) = candidate.take() {
                if let Some(preview) = prepared.preview.as_mut() {
                    record::encode_into(record::Kind::DetachedCapture, limits, preview, |w| {
                        capture_context.as_ref().unwrap().write(w)?;
                        op.capture_owner()
                            .unwrap()
                            .write_checkpoint(budget, w, limits)?;
                        record::DetachedRecord::write_tail(w, function, 0, capacity)
                    })?;
                    record::DetachedRecord::read(preview.as_slice(), limits)?;
                }
                waiter.as_mut().expect("detachment waiter").succeed()?;
                s.operations.claim_progress(&self.session.entry, op.id)?;
                op.begin_detachment(|| DetachControl {
                    get_id: prepared.get_id,
                    id: None,
                    function,
                    capacity,
                    context: capture_context,
                    authentication: self.session.snapshot.authentication_stamp(),
                    limits,
                    kind,
                    inspection: prepared.inspection,
                    record_storage: prepared.preview.take(),
                    publication_credit: Some(prepared.publication_credit),
                    _credit: prepared.control_credit,
                })?;
                drop(op);
                drop(operation);
                drop(s);
                drop(prepared.preview);
                return self.drive_detachment(ticket, false, &mut diagnostics);
            }
            let authentication = op._token.authentication;
            waiter = Some(progress::Waiter::new(
                &self.session,
                op.id,
                progress::Effect::PreserveOwner,
            )?);
            drop(op);
            drop(operation);
            drop(s);
            let waiting = waiter.as_mut().expect("detachment waiter");
            let diagnostics = diagnostics
                .as_mut()
                .expect("detachment diagnostics prepared");
            match preparation::prepare(
                &self.session,
                diagnostics.budget(),
                shape,
                authentication,
                waiting,
            ) {
                Ok(Some(prepared)) => candidate = Some(prepared),
                Ok(None) => {
                    waiting.succeed()?;
                    drop(waiter.take());
                }
                Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
            }
        }
    }
    /// Observe this transfer only. A timeout or dropped ticket cannot release
    /// a pending frame; the registry retains it until proven native cleanup.
    pub fn poll_detachment(&self, ticket: &mut OperationTicket) -> Result<DetachmentProgress> {
        let mut diagnostics = None;
        self.drive_detachment(ticket, true, &mut diagnostics)
    }

    /// Native progression stays under possession. Record preparation is local
    /// and may wait only after releasing it, anchored to the exact revision.
    fn drive_detachment(
        &self,
        ticket: &mut OperationTicket,
        observe: bool,
        diagnostics: &mut Option<progress::FailureDiagnostics>,
    ) -> Result<DetachmentProgress> {
        let mut prepared: Option<(Buffer, Credit, progress::Waiter<'_>, bool)> = None;
        // Keep one pacing budget across local preparation. A resource wake
        // never authorizes another observation of the original native call.
        let mut remaining = self.pacing.budget();
        let mut observe = observe;
        loop {
            check_ticket(&self.session, ticket)?;
            let s = self.session.advanced_access()?;
            if self.session.entry.advanced_progress.retired(ticket.id)? {
                ticket.id = 0;
                return Err(Error::Rejected(crate::RejectionReason::Authentication(
                    crate::AuthenticationRejection::ForeignOrConsumedOperationTicket,
                )));
            }
            let operation = s.operations.get(ticket.uid)?;
            let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
            if op.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            op.check_authentication(&self.session.entry)?;
            if op.detachment().is_none() {
                return Err(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::DetachmentAbsent,
                )));
            }
            if let Some((bytes, _, waiter, publication)) = prepared.as_mut() {
                if waiter.changed() {
                    waiter.succeed()?;
                    drop(op);
                    drop(operation);
                    drop(s);
                    drop(prepared.take());
                    // A peer advanced the owner. Reinspect its local phase; do
                    // not repeat a native call already issued by this invocation.
                    continue;
                }
                let control = op.detachment().unwrap();
                if *publication != control.id.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::Detachment(
                        crate::DetachmentRejection::DetachmentRecordPhaseChanged,
                    )));
                }
                record::DetachedRecord::read(bytes.as_slice(), control.limits)?
                    .context
                    .check(control.context.as_ref().ok_or(Error::Rejected(
                        crate::RejectionReason::Detachment(
                            crate::DetachmentRejection::DetachmentContextAbsent,
                        ),
                    ))?)?;
                waiter.succeed()?;
                s.operations.claim_progress(&self.session.entry, op.id)?;
                // The registration remains outside possession on every earlier
                // error. It can move now because it is already unregistered.
                let (bytes, credit, _, _) = prepared.take().unwrap();
                op.detachment_mut().unwrap().record_storage = Some(bytes);
                drop(credit);
            }
            let control = op.detachment().unwrap();
            let publication = control.id.is_some();
            let preview = control.kind == DetachKind::TerminalValidation
                && control.context.is_some()
                && control.record_storage.is_none()
                && !publication;
            if publication && control.record_storage.is_some() {
                let limits = control.limits;
                let kind = control.record_kind();
                let mut bytes = op.detachment_mut().unwrap().record_storage.take().unwrap();
                let result = (|| -> Result<()> {
                    record::encode_into(kind, limits, &mut bytes, |writer| {
                        self.write_detachment_record(&op, writer, true)
                    })?;
                    record::DetachedRecord::read(bytes.as_slice(), limits)?
                        .context
                        .check(op.detachment().unwrap().context.as_ref().unwrap())?;
                    Ok(())
                })();
                if let Err(error) = result {
                    op.detachment_mut().unwrap().record_storage = Some(bytes);
                    return Err(error);
                }
                if let Err(error) = s.operations.claim_progress(&self.session.entry, op.id) {
                    op.detachment_mut().unwrap().record_storage = Some(bytes);
                    return Err(error);
                }
                return self.finish_detachment(&s, &mut op, ticket, bytes);
            }
            if publication || preview {
                let limits = control.limits;
                let kind = control.record_kind();
                drop(op);
                drop(operation);
                drop(s);
                let result = record_preparation::copy_registered(
                    &self.session,
                    ticket,
                    kind,
                    limits,
                    0,
                    diagnostics,
                    |op, writer| self.write_detachment_record(op, writer, publication),
                )?;
                prepared = Some((result.0, result.1, result.2, publication));
                continue;
            }
            s.operations.claim_progress(&self.session.entry, op.id)?;
            let result = self.advance_detachment(&s, &mut op, observe, &mut remaining);
            observe = false;
            match result {
                Ok(DetachmentProgress::Ready) => {
                    let control = op.detachment().ok_or(Error::Rejected(
                        crate::RejectionReason::Detachment(
                            crate::DetachmentRejection::DetachmentAbsent,
                        ),
                    ))?;
                    if control.id.is_none()
                        && !(control.kind == DetachKind::TerminalValidation
                            && control.context.is_some()
                            && control.record_storage.is_none())
                    {
                        return Ok(DetachmentProgress::Ready);
                    }
                }
                other => return other,
            }
        }
    }

    fn write_detachment_record(
        &self,
        op: &Operation,
        writer: &mut record::Writer<'_>,
        publication: bool,
    ) -> Result<()> {
        let control =
            op.detachment()
                .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::DetachmentAbsent,
                )))?;
        if publication != control.id.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::DetachmentRecordPhaseChanged,
            )));
        }
        control
            .context
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::DetachmentContextAbsent,
            )))?
            .write(writer)?;
        let budget = &self.session.inner.symmetric_budget;
        match control.kind {
            DetachKind::TerminalValidation => {
                rejoin::check_keys(&op.body, &self.session.entry)?;
                terminal::write(
                    &op.body,
                    op.validation.as_ref().unwrap(),
                    budget,
                    writer,
                    control.limits,
                )?;
            }
            DetachKind::Capture => {
                op.capture_owner()
                    .unwrap()
                    .write_checkpoint(budget, writer, control.limits)?
            }
            DetachKind::Cryptographic => Continuation::write_parts(
                &op.body,
                op.validation.as_ref(),
                budget,
                writer,
                control.limits,
            )?,
        }
        record::DetachedRecord::write_tail(
            writer,
            control.function,
            control.id.unwrap_or(0),
            control.capacity,
        )
    }
    /// Commit publication under the same possession that validated its bytes.
    /// On a ledger refusal, restore the record alongside its still-owned ID and
    /// output credit. Nothing fallible follows successful source retirement.
    fn finish_detachment(
        &self,
        s: &State,
        op: &mut Operation,
        ticket: &mut OperationTicket,
        bytes: Buffer,
    ) -> Result<DetachmentProgress> {
        let control =
            op.detachment()
                .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::DetachmentAbsent,
                )))?;
        let limits = control.limits;
        if control.publication_credit.is_none() {
            op.detachment_mut().unwrap().record_storage = Some(bytes);
            return Err(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::DetachmentPublicationCreditAbsent,
            )));
        }
        let original_crypto =
            control.kind == DetachKind::Capture && !matches!(op.body, OperationBody::Control);
        if !original_crypto {
            if let Err(error) = s.operations.release_closed(&self.session.entry) {
                op.detachment_mut().unwrap().record_storage = Some(bytes);
                return Err(error);
            }
        }
        let credit = op
            .detachment_mut()
            .unwrap()
            .publication_credit
            .take()
            .unwrap();
        let result = DetachedOperation {
            provenance: op.provenance,
            record: bytes,
            limits,
            _credit: credit,
        };
        if original_crypto {
            // GetID transferred the read only. Keep its original crypto body
            // frozen until explicit cancel/close establishes native release.
            op.state.take();
            op.take_detachment();
        }
        ticket.id = 0;
        Ok(DetachmentProgress::Detached(result))
    }
    fn advance_detachment(
        &self,
        s: &State,
        op: &mut Operation,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<DetachmentProgress> {
        let control =
            op.detachment()
                .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::DetachmentAbsent,
                )))?;
        if control.get_id.retains_native_memory() {
            return Err(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::DetachmentNativeStateUncertain,
            )));
        }
        if control.id.is_none() {
            self.session
                .snapshot
                .check_authentication_unchanged(control.authentication)?;
            if let Some(io) = &mut op.detachment_mut().unwrap().inspection {
                if let Err(error) = io.drive(s, &self.session.entry, observe, remaining) {
                    // An uncertain return may clear pending while still retaining
                    // the inspection's native memory loan (GENERAL_ERROR).
                    if !io.pending() && !s.native.is_uncertain() {
                        op.take_detachment();
                    }
                    return Err(error);
                }
                if !io.complete() {
                    return Ok(if io.pending() {
                        DetachmentProgress::Pending
                    } else {
                        DetachmentProgress::Ready
                    });
                }
                let state = io.inspected_state()?;
                let context = record::Context::from_snapshot(
                    &self.session.inner,
                    &self.session.snapshot,
                    state,
                )?;
                let control = op.detachment_mut().unwrap();
                control.context = Some(context);
                control.inspection.take();
            }
            if op.detachment().unwrap().kind == DetachKind::TerminalValidation
                && op.detachment().unwrap().record_storage.is_none()
            {
                // Reject incoherent/oversized metadata before reserving its
                // preview and before GetID. This pass does not allocate or read
                // the pending validation frame.
                let limits = op.detachment().unwrap().limits;
                if let Err(error) = record::encoded_size(limits, |writer| {
                    self.write_detachment_record(op, writer, false)
                }) {
                    op.take_detachment();
                    return Err(error);
                }
                return Ok(DetachmentProgress::Ready);
            }
            if !spend(remaining) {
                return Ok(DetachmentProgress::Ready);
            }
            let result = op
                .detachment_mut()
                .unwrap()
                .get_id
                .dispatch(s, &self.session.entry);
            match result {
                Err(error) => {
                    if !op.detachment().unwrap().get_id.retains_native_memory() {
                        op.take_detachment();
                    }
                    return Err(error);
                }
                Ok(id) => {
                    // Commit transfer before any allocation or further check.
                    op.continuation_status = ownership::ContinuationStatus::Frozen(
                        ownership::FreezeReason::NativeDetachment,
                    );
                    op.detachment_mut().unwrap().id = Some(id);
                    // Only GetID OK permits these reads/releases, even if the
                    // native computation itself continues away from this frame.
                    if op.detachment().unwrap().kind == DetachKind::TerminalValidation {
                        op.validation.as_mut().unwrap().detached_release();
                    } else if op.detachment().unwrap().kind == DetachKind::Capture {
                        op.state_io_mut().unwrap().detached_capture_release();
                    } else {
                        match &mut op.body {
                            OperationBody::Digest(d) => d.activity = NativeActivity::Active,
                            OperationBody::Messages(d) => d.detached_native_release(),
                            OperationBody::AeadMessages(d) => d.detached_native_release(),
                            OperationBody::Dual(d) => d.detached_native_release(),
                            _ => unreachable!("validated detachment owner"),
                        }
                    }
                    op.joined.take();
                }
            }
        }
        // GetID success freezes the original source. Its immutable record is
        // prepared by the outer driver without retaining session possession.
        Ok(DetachmentProgress::Ready)
    }
}

impl DetachedOperation {
    pub(super) fn retained_bytes(
        &self,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    ) -> Result<crate::symmetric::memory::RetainedBytes> {
        crate::symmetric::memory::RetainedBytes::measure(budget, |retained| {
            self.record.retain_credit(retained)?;
            retained.add_credit(&self._credit)
        })
    }
}
