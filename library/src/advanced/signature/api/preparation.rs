// SPDX-License-Identifier: Apache-2.0
//! Prepare signature operands, representation and output changes.
//! Owner checks precede transferring input into a continuing native signature sequence.

use super::*;

pub(super) fn check_owner(
    operation: &Operation,
    session: &Session,
    ticket: &OperationTicket,
) -> Result<()> {
    if operation.id != ticket.id {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::StaleSignatureTicket,
        )));
    }
    operation.check_continuation_control(&session.entry)?;
    if operation.cancellation.is_withdrawn()
        || operation.cancel.is_submitted()
        || operation.state_io().is_some()
        || operation.transfer.is_some()
        || operation.joined.is_some()
        || operation.continuation_status.is_frozen()
        || operation.validation_pending()
    {
        return Err(Error::Busy(crate::BusyReason::SignatureContinuation(
            crate::SignatureContinuationBusy::SignatureControlInProgress,
        )));
    }
    let OperationBody::Signature(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::SignatureTicketRequired,
        )));
    };
    body.check_key(&session.entry)?;
    if !body.input.is_open()
        || !body.input.incremental
        || body.pending()
        || body.stage != Stage::Ready
        || body.fragment.is_some()
    {
        return Err(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureInputBoundaryUnavailable,
            ),
        ));
    }
    Ok(())
}

impl<'a> Change<'a> {
    pub(super) fn operands(self) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
        match self {
            Self::Update(bytes) => (Some(bytes), None),
            Self::Finish(signature) => (None, signature),
            Self::Single { data, signature } => (Some(data), signature),
        }
    }

    pub(super) fn check(self, body: &super::super::SignatureOperation) -> Result<()> {
        let single = matches!(self, Self::Single { .. });
        if single != (body.route == MessageRoute::Single) {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureContinuationRoute,
                ),
            ));
        }
        if let Self::Finish(signature) | Self::Single { signature, .. } = self {
            let required = body.kind == Kind::Verify && body.signature.is_none();
            if required != signature.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureFinishOperands,
                    ),
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn prepare_input(
    budget: &Arc<crate::symmetric::memory::Budget>,
    change: Change<'_>,
    mut before: impl FnMut() -> Result<bool>,
) -> Result<Option<PreparedInput>> {
    let (data, signature) = change.operands();
    let policy = crate::admission_wait::current();
    let mut required = data
        .map_or(0, <[u8]>::len)
        .checked_add(signature.map_or(0, <[u8]>::len))
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureInputAccounting,
            ),
        ))?;
    loop {
        let mut prepaid = match budget.reserve_controlled_retaining::<()>(
            required,
            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
            &policy,
            || Ok(before()?.then_some(())),
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(()) => return Ok(None),
        };
        let data_storage = data
            .map(|bytes| InputBytesStorage::allocate(bytes.len()))
            .transpose()?;
        let signature_storage = signature
            .map(|bytes| InputBytesStorage::allocate(bytes.len()))
            .transpose()?;
        let data_bytes = data_storage
            .as_ref()
            .map(InputBytesStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        let signature_bytes = signature_storage
            .as_ref()
            .map(InputBytesStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        let actual = data_bytes
            .checked_add(signature_bytes)
            .ok_or(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureInputAccounting,
                ),
            ))?;
        if actual > required {
            drop(data_storage);
            drop(signature_storage);
            drop(prepaid);
            required = actual;
            continue;
        }
        prepaid.release(required - actual);
        return Ok(Some(PreparedInput {
            data: data_storage
                .zip(data)
                .map(|(storage, bytes)| storage.bind(bytes, &mut prepaid))
                .transpose()?,
            signature: signature_storage
                .zip(signature)
                .map(|(storage, bytes)| storage.bind(bytes, &mut prepaid))
                .transpose()?,
        }));
    }
}

pub(in crate::advanced::signature) fn change(
    session: &Session,
    ticket: &mut OperationTicket,
    change: Change<'_>,
    limits: InputLimits,
    pacing: OperationPacing,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    poll_diagnostics: &mut poll::PollDiagnostics,
) -> Result<OperationProgress> {
    change_with_budget(
        session,
        ticket,
        change,
        limits,
        pacing,
        &session.inner.symmetric_budget,
        diagnostics,
        poll_diagnostics,
    )
}

/// A complete-input facade carries its descendant account through each input
/// admission. Caller-fed operations use the module account via `change`.
pub(in crate::advanced::signature) fn change_with_budget(
    session: &Session,
    ticket: &mut OperationTicket,
    change: Change<'_>,
    limits: InputLimits,
    pacing: OperationPacing,
    budget: &Arc<crate::symmetric::memory::Budget>,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    poll_diagnostics: &mut poll::PollDiagnostics,
) -> Result<OperationProgress> {
    if !Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedSignatureTicket,
        )));
    }
    if let Change::Update(bytes) | Change::Single { data: bytes, .. } = change {
        limits.validate(session.inner.crypto_options.limits, &[bytes])?;
    }
    for bytes in [change.operands().0, change.operands().1]
        .into_iter()
        .flatten()
    {
        crate::bounds::ck_length(bytes.len())?;
    }
    let mut waiter: Option<progress::Waiter<'_>> = None;
    let mut candidate: Option<PreparedInput> = None;
    loop {
        let access = session.advanced_access()?;
        let installed = access.operations.get(ticket.uid)?;
        let mut operation = installed.lock().map_err(|_| Error::Poisoned)?;
        check_owner(&operation, session, ticket)?;
        let OperationBody::Signature(body) = &operation.body else {
            unreachable!()
        };
        change.check(body)?;
        if let Change::Update(bytes) | Change::Single { data: bytes, .. } = change {
            body.input.submission(bytes.len(), false)?;
        }
        if change.operands() != (None, None) && diagnostics.is_none() {
            drop(operation);
            drop(installed);
            drop(access);
            *diagnostics = Some(progress::FailureDiagnostics::prepare_in(
                session, budget, ticket.id,
            )?);
            continue;
        }
        let ready = if let Some(waiting) = waiter.as_mut() {
            let unchanged = !waiting.changed() && candidate.is_some();
            waiting.succeed()?;
            if !unchanged {
                drop(operation);
                drop(installed);
                drop(access);
                drop(candidate.take());
                drop(waiter.take());
                continue;
            }
            true
        } else {
            change.operands() == (None, None)
        };
        if ready {
            access
                .operations
                .claim_progress(&session.entry, operation.id)?;
            let OperationBody::Signature(body) = &mut operation.body else {
                unreachable!()
            };
            match change {
                Change::Update(_) => {
                    body.fragment = candidate.take().expect("prepared signature input").data;
                    body.stage = Stage::Update;
                }
                Change::Finish(signature) => {
                    if signature.is_some() {
                        body.signature = candidate
                            .take()
                            .expect("prepared verification signature")
                            .signature;
                    }
                    body.input.close();
                }
                Change::Single { signature, .. } => {
                    let prepared = candidate.take().expect("prepared single-part operands");
                    body.fragment = prepared.data;
                    if signature.is_some() {
                        body.signature = prepared.signature;
                    }
                    body.input.close();
                }
            }
            drop(operation);
            drop(installed);
            drop(access);
            drop(waiter.take());
            return poll::poll_operation_with_diagnostics(
                session,
                ticket,
                crate::session::CleanupAdmission::Ordinary,
                pacing,
                poll_diagnostics,
            );
        }
        waiter = Some(progress::Waiter::new(
            session,
            operation.id,
            progress::Effect::PreserveOwner,
        )?);
        drop(operation);
        drop(installed);
        drop(access);
        let waiting = waiter.as_mut().expect("registered signature input waiter");
        let diagnostics = diagnostics
            .as_mut()
            .expect("signature input diagnostics prepared");
        match prepare_input(diagnostics.budget(), change, || {
            crate::advanced::preparation::context(session)?;
            // Recheck the live owner after the wait; its old login stamp
            // is not authorization for the next native signature call.
            // Re-enter possession and re-evaluate the changed owner. The
            // same admission policy keeps its original deadline/cancellation.
            Ok(waiting.changed())
        }) {
            Ok(input) => candidate = input,
            Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
        }
    }
}

pub(in crate::advanced::signature) fn initial_limits(session: &Session) -> InputLimits {
    InputLimits {
        maximum_parts: session.inner.crypto_options.limits.maximum_parts,
        maximum_total_bytes: session.inner.crypto_options.limits.maximum_total_bytes,
    }
}
