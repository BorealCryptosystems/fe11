// SPDX-License-Identifier: Apache-2.0
//! Caller-fed message transitions. Preparation never retains session possession.
mod storage;
use super::{MacOperation, MessageRoute, MessageStep};
use crate::advanced::{
    poll, preparation, progress, Operation, OperationBody, OperationPacing, OperationProgress,
    OperationTicket,
};
use crate::{bounds, Error, InputLimits, Result, Session};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum Submission<'a> {
    Begin,
    Single {
        bytes: &'a [u8],
        expected: Option<&'a [u8]>,
    },
    Update(&'a [u8]),
    Last {
        bytes: &'a [u8],
        expected: Option<&'a [u8]>,
    },
}
impl<'a> Submission<'a> {
    fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Self::Begin => None,
            Self::Single { bytes, .. } | Self::Update(bytes) | Self::Last { bytes, .. } => {
                Some(bytes)
            }
        }
    }
    fn expected(self) -> Option<&'a [u8]> {
        match self {
            Self::Single { expected, .. } | Self::Last { expected, .. } => expected,
            Self::Begin | Self::Update(_) => None,
        }
    }
    fn starts_message(self) -> bool {
        matches!(self, Self::Begin | Self::Single { .. })
    }
    fn terminal(self) -> bool {
        matches!(self, Self::Single { .. } | Self::Last { .. })
    }
    fn step(self, index: usize) -> MessageStep {
        match self {
            Self::Begin => MessageStep::Begin(index),
            Self::Single { .. } => MessageStep::Single(index),
            Self::Update(_) => MessageStep::StreamUpdate(index),
            Self::Last { .. } => MessageStep::StreamLast(index),
        }
    }
}

/// Fixed-size observation of the storage requirement, never source borrows.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Need {
    rows: usize,
    next_rows: usize,
    grow: Option<usize>,
    old_metadata: usize,
    output: Option<usize>,
    report: Option<(usize, usize)>,
}

fn check_owner<'a>(
    operation: &'a Operation,
    session: &Session,
    id: u64,
) -> Result<&'a MacOperation> {
    if operation.id != id {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::StaleMessageSignatureTicket,
        )));
    }
    operation.check_control_access(&session.entry)?;
    if let Some(capture) = &operation.validation {
        // Includes queued observations, not only a native Pending response.
        capture.snapshot_capacity()?;
    }
    let OperationBody::Messages(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSignatureTicketRequired,
        )));
    };
    body.key.check(&session.entry)?;
    if !body.input.incremental
        || !body.input.is_open()
        || body.outcome.closing()
        || body.stream_fragment.is_some()
        || !body.released.is_empty()
        || body.input.retained_submission
        || !matches!(body.step, MessageStep::Ready | MessageStep::Receive(_))
    {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSignatureStreamIsNotAwaitingInput,
        )));
    }
    let outputs = &body
        .signatures
        .as_ref()
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSignaturesAlreadyPublished,
        )))?
        .bytes;
    if body.inputs.len() != body.layouts.len()
        || body.inputs.len() != outputs.len()
        || body.inputs.len() != body.lengths.len()
    {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSignatureStreamRowShape,
        )));
    }
    // Constructors and archive validation establish empty historical input
    // rows. Submissions preserve that invariant; do not rescan all prior
    // messages for every new fragment.
    Ok(body)
}

fn need(operation: &Operation, body: &MacOperation, submission: Submission<'_>) -> Result<Need> {
    let matches = match (submission, body.route, body.step) {
        (Submission::Single { .. }, MessageRoute::Single, MessageStep::Ready)
        | (Submission::Begin, MessageRoute::Multipart, MessageStep::Ready) => true,
        (
            Submission::Update(_) | Submission::Last { .. },
            MessageRoute::Multipart,
            MessageStep::Receive(index),
        ) => index.checked_add(1) == Some(body.inputs.len()),
        _ => false,
    };
    if !matches || submission.terminal() && body.verify != submission.expected().is_some() {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageSignatureSubmissionRoute,
        )));
    }
    if let Some(bytes) = submission.bytes() {
        body.input.submission(bytes.len(), false)?;
    }
    let rows = body.inputs.len();
    let next_rows = rows
        .checked_add(usize::from(submission.starts_message()))
        .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::MessageRowCountOverflow,
        )))?;
    let outputs = &body
        .signatures
        .as_ref()
        .expect("checked message results")
        .bytes;
    let grow = if next_rows > body.inputs.capacity()
        || next_rows > body.layouts.capacity()
        || next_rows > body.lengths.capacity()
        || next_rows > outputs.capacity()
        || next_rows
            > body
                .signatures
                .as_ref()
                .expect("checked message results")
                .rejections
                .capacity()
    {
        // Geometric metadata growth; not a limit on future message count.
        Some(next_rows.checked_next_power_of_two().unwrap_or(next_rows))
    } else {
        None
    };
    let old_metadata = storage::sum(&[
        storage::vector_bytes(&body.inputs)?,
        storage::vector_bytes(&body.layouts)?,
        storage::vector_bytes(&body.lengths)?,
    ])?;
    let output = if submission.starts_message() {
        Some(if body.verify {
            submission.expected().map_or(0, <[u8]>::len)
        } else {
            body.size
        })
    } else if body.verify && submission.terminal() {
        Some(
            submission
                .expected()
                .expect("checked verification input")
                .len(),
        )
    } else {
        None
    };
    if let Some(size) = output {
        bounds::ck_length(size)?;
    }
    let report = if submission.starts_message() {
        let maximum = next_rows.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageReportCountOverflow,
            ),
        ))?;
        operation
            .validation
            .as_ref()
            .map(|capture| -> Result<_> { Ok((maximum, capture.report_growth_bytes(maximum)?)) })
            .transpose()?
    } else {
        None
    };
    Ok(Need {
        rows,
        next_rows,
        grow,
        old_metadata,
        output,
        report,
    })
}

fn ticket_owner(session: &Session, ticket: &OperationTicket) -> Result<()> {
    if !Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
            crate::SignatureMessagesRejection::ForeignOrConsumedMessageSignatureTicket,
        )));
    }
    Ok(())
}

pub(super) fn submit(
    session: &Session,
    ticket: &mut OperationTicket,
    submission: Submission<'_>,
    limits: InputLimits,
    pacing: OperationPacing,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    poll_diagnostics: &mut poll::PollDiagnostics,
) -> Result<OperationProgress> {
    ticket_owner(session, ticket)?;
    let data = submission.bytes();
    let expected = submission.expected();
    let input_bytes = limits.validate_lengths(
        session.inner.crypto_options.limits,
        usize::from(data.is_some()),
        data.into_iter().map(|part| Ok(part.len())),
    )?;
    if let Some(expected) = expected {
        bounds::ck_length(expected.len())?;
        if input_bytes
            .checked_add(expected.len())
            .filter(|total| *total <= limits.maximum_total_bytes)
            .is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageInputCeiling,
            )));
        }
    }
    // Preserve the same absolute deadline/cancellation policy across retries.
    let admission = crate::admission_wait::current();
    // The public invocation owns these diagnostic credits through projection.
    // Source-change retries reuse the same unused leaves without a new root.
    let mut waiter: Option<progress::Waiter<'_>> = None;
    let mut candidate: Option<(Need, storage::Prepared)> = None;
    loop {
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let body = check_owner(&operation, session, ticket.id)?;
        let current = need(&operation, body, submission)?;
        if diagnostics.is_none() {
            drop(operation);
            drop(held);
            drop(access);
            *diagnostics = Some(progress::FailureDiagnostics::prepare(session, ticket.id)?);
            continue;
        }
        if let Some(waiting) = waiter.as_mut() {
            let unchanged = !waiting.changed()
                && candidate
                    .as_ref()
                    .is_some_and(|(planned, _)| *planned == current);
            waiting.succeed()?;
            if !unchanged {
                drop(operation);
                drop(held);
                drop(access);
                drop(candidate.take());
                drop(waiter.take());
                continue;
            }
            if let Some((maximum, _)) = current.report {
                operation
                    .validation
                    .as_ref()
                    .expect("checked message report")
                    .check_report_growth(
                        maximum,
                        candidate
                            .as_ref()
                            .expect("matching message input preparation")
                            .1
                            .report
                            .as_ref(),
                    )?;
            }
            access
                .operations
                .claim_progress(&session.entry, operation.id)?;
            let (_, mut prepared) = candidate
                .take()
                .expect("matching message input preparation");
            // No fallible preparation remains after the borrowed report check.
            // Everything below moves already admitted allocations under the
            // same possession, without changing the native observation frame.
            let old_report = if let Some((maximum, _)) = current.report {
                operation
                    .validation
                    .as_mut()
                    .expect("checked message report")
                    .attach_report_growth(maximum, prepared.report.take())
                    .expect("report growth checked under the same possession")
            } else {
                None
            };
            let OperationBody::Messages(body) = &mut operation.body else {
                unreachable!()
            };
            let retired = prepared.commit(body, current, submission);
            drop(operation);
            drop(held);
            drop(access);
            drop(retired);
            drop(old_report);
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
        drop(held);
        drop(access);
        let waiting = waiter.as_mut().expect("registered message input waiter");
        let diagnostics = diagnostics
            .as_mut()
            .expect("submission diagnostics prepared");
        match storage::Prepared::prepare(
            diagnostics.budget(),
            current,
            submission,
            &admission,
            || {
                preparation::context(session)?;
                if waiting.changed() {
                    return Err(Error::Busy(crate::BusyReason::SignatureMessages(
                        crate::SignatureMessagesBusy::MessageSignatureControlChanged,
                    )));
                }
                Ok(())
            },
        ) {
            Ok(prepared) => candidate = Some((current, prepared)),
            Err(_) if waiting.changed() => {
                waiting.succeed()?;
            }
            Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
        }
    }
}

pub(super) fn finish(
    session: &Session,
    ticket: &mut OperationTicket,
    pacing: OperationPacing,
    poll_diagnostics: &mut poll::PollDiagnostics,
) -> Result<OperationProgress> {
    ticket_owner(session, ticket)?;
    let mut released = crate::advanced::poll::ReleasedInputs::default();
    let access = session.advanced_access()?;
    {
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let body = check_owner(&operation, session, ticket.id)?;
        if body.step != MessageStep::Ready {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::FinishTheCurrentMessageBeforeTheParentProcess,
            )));
        }
        access
            .operations
            .claim_progress(&session.entry, operation.id)?;
        let OperationBody::Messages(body) = &mut operation.body else {
            unreachable!()
        };
        body.input.close();
        body.step = MessageStep::Finish;
    }
    let result = poll::poll_with_access(session, ticket, &access, pacing, &mut released);
    poll_diagnostics.retired_owner = released.take_owner();
    result
}
