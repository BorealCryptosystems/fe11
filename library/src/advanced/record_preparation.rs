// SPDX-License-Identifier: Apache-2.0
//! Copy immutable record views across a release/revalidate resource boundary.
use super::{preparation, progress, record, Operation, OperationTicket};
use crate::{
    symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer},
    Error, Result, Session,
};

/// Internal callbacks observe only the guarded source; they cannot allocate,
/// dispatch C or escape references into the waiter/candidate. The ticket's exact
/// revision remains authoritative after every resource wake.
pub(super) fn copy(
    session: &Session,
    ticket: &OperationTicket,
    kind: record::Kind,
    limits: record::Limits,
    metadata: usize,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    write: impl Fn(&Operation, &mut record::Writer<'_>) -> Result<()>,
) -> Result<(Buffer, Credit)> {
    let (bytes, credit, mut waiter) =
        copy_registered(session, ticket, kind, limits, metadata, diagnostics, write)?;
    waiter.succeed()?;
    Ok((bytes, credit))
}

/// Keep the exact source revision registered until a caller installs or
/// publishes the result under its reacquired session/operation possession.
pub(super) fn copy_registered<'a>(
    session: &'a Session,
    ticket: &OperationTicket,
    kind: record::Kind,
    limits: record::Limits,
    metadata: usize,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    write: impl Fn(&Operation, &mut record::Writer<'_>) -> Result<()>,
) -> Result<(Buffer, Credit, progress::Waiter<'a>)> {
    let policy = crate::admission_wait::current();
    let mut candidate: Option<(Buffer, Credit)> = None;
    let mut waiter: Option<progress::Waiter<'_>> = None;
    loop {
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleRecoveryTicket,
            )));
        }
        operation.check_authentication(&session.entry)?;
        let size = record::encoded_size(limits, |writer| write(&operation, writer))?;
        if diagnostics.is_none() {
            // Reject invalid records before allocating diagnostic storage. The
            // sizing view is only a hint and is recomputed after re-possession.
            drop(operation);
            drop(held);
            drop(access);
            *diagnostics = Some(progress::FailureDiagnostics::prepare(session, ticket.id)?);
            continue;
        }
        let diagnostics = diagnostics.as_mut().expect("record diagnostics prepared");
        let budget = diagnostics.budget().clone();
        if let Some(waiting) = waiter.as_mut() {
            let valid = !waiting.changed()
                && candidate
                    .as_ref()
                    .is_some_and(|(bytes, _)| bytes.capacity() == size);
            if !valid {
                waiting.succeed()?;
                drop(operation);
                drop(held);
                drop(access);
                drop(candidate.take());
                drop(waiter.take());
                continue;
            }
            let (mut bytes, credit) = candidate.take().expect("matching record candidate");
            record::encode_into(kind, limits, &mut bytes, |writer| write(&operation, writer))?;
            return Ok((bytes, credit, waiter.take().expect("record waiter")));
        }
        let authentication = operation._token.authentication;
        waiter = Some(progress::Waiter::new(
            session,
            operation.id,
            progress::Effect::PreserveOwner,
        )?);
        drop(operation);
        drop(held);
        drop(access);
        let waiting = waiter.as_mut().expect("registered record waiter");
        let preparation = (|| -> Result<Option<(Buffer, Credit)>> {
            let mut required = metadata.checked_add(size).ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::RecordStorageAccounting,
                ),
            ))?;
            loop {
                let mut credit = match budget.reserve_controlled_retaining(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    &policy,
                    || {
                        preparation::context(session)?;
                        session
                            .snapshot
                            .observe_authentication_unchanged(authentication)?;
                        Ok(waiting.changed().then_some(()))
                    },
                    || Ok(None),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => return Ok(None),
                };
                let bytes = UnboundBuffer::allocate(size)?;
                let actual = metadata
                    .checked_add(bytes.allocated())
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::RecordStorageAccounting,
                    )))?;
                if actual > required {
                    drop(bytes);
                    drop(credit);
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                let bytes = bytes.bind(&mut credit)?;
                return Ok(Some((bytes, credit)));
            }
        })();
        match preparation {
            Ok(Some(bytes)) => candidate = Some(bytes),
            Ok(None) => {
                waiting.succeed()?;
            }
            Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
        }
    }
}
