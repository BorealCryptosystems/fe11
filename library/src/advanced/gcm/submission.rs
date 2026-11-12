// SPDX-License-Identifier: Apache-2.0
//! One AEAD submission is admitted before taking native possession.
use super::{AeadMessageOperation, AeadOutcome, AeadStep, InitBinding, MessageRoute, Selection};
use crate::advanced::{
    poll, progress, Operation, OperationBody, OperationPacing, OperationProgress, OperationTicket,
};
use crate::{bounds, Error, InputLimits, Result, Session};
use std::sync::Arc;
mod storage;

#[derive(Clone, Copy)]
pub(super) struct Message<'a> {
    pub origin: &'a Selection,
    pub aad: &'a [u8],
    pub expected_tag: Option<&'a [u8]>,
    pub declared_length: usize,
    pub output_capacity: usize,
}

#[derive(Clone, Copy)]
pub(super) enum Submission<'a> {
    Single {
        message: Message<'a>,
        bytes: &'a [u8],
    },
    Begin(Message<'a>),
    Update(&'a [u8]),
    Last {
        bytes: &'a [u8],
        expected_tag: Option<&'a [u8]>,
    },
}
impl<'a> Submission<'a> {
    fn message(self) -> Option<Message<'a>> {
        match self {
            Self::Single { message, .. } | Self::Begin(message) => Some(message),
            _ => None,
        }
    }
    fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Self::Single { bytes, .. } | Self::Update(bytes) | Self::Last { bytes, .. } => {
                Some(bytes)
            }
            Self::Begin(_) => None,
        }
    }
    fn step(self, index: usize) -> AeadStep {
        match self {
            Self::Single { .. } => AeadStep::Single(index),
            Self::Begin(_) => AeadStep::Begin(index),
            Self::Update(_) => AeadStep::StreamUpdate(index),
            Self::Last { .. } => AeadStep::StreamLast(index),
        }
    }
    fn last_tag(self) -> Option<&'a [u8]> {
        match self {
            Self::Last { expected_tag, .. } => expected_tag,
            _ => None,
        }
    }
}

/// No source borrow survives the admission wait. A changed progress revision
/// invalidates this observation even when the resource sizes happen to match.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Need {
    rows: usize,
    grow: Option<usize>,
    old_metadata: usize,
    report: Option<(usize, usize)>,
    generated_nonce: bool,
}

fn ticket_owner(session: &Session, ticket: &OperationTicket) -> Result<()> {
    if !Arc::ptr_eq(&session.inner, &ticket.owner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::ForeignOrConsumedAeadStreamTicket,
        )));
    }
    Ok(())
}

fn check_owner<'a>(
    operation: &'a Operation,
    session: &Session,
    id: u64,
) -> Result<&'a AeadMessageOperation> {
    if operation.id != id {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::StaleAeadStreamTicket,
        )));
    }
    operation.check_control_access(&session.entry)?;
    if let Some(capture) = &operation.validation {
        capture.snapshot_capacity()?;
    }
    let OperationBody::AeadMessages(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::AeadMessageTicketRequired,
        )));
    };
    body.key.check(&session.entry)?;
    let input =
        body.input
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadCallerFedStreamRequired,
            )))?;
    if !input.state.is_open()
        || input.state.retained_submission
        || input.fragment.is_some()
        || body.retired_fragment.is_some()
        || body.retired_output.is_some()
        || !matches!(body.outcome, AeadOutcome::Nominal)
        || !matches!(body.step, AeadStep::Ready | AeadStep::Receive(_))
    {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadStreamIsNotAwaitingInput,
        )));
    }
    let outputs =
        body.outputs
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadOutputAlreadyPublished,
            )))?;
    if body.frames.len() != outputs.entries.len() {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadStreamRowShape,
        )));
    }
    Ok(body)
}

fn need(
    operation: &Operation,
    body: &AeadMessageOperation,
    submission: Submission<'_>,
) -> Result<Need> {
    let matches = match (submission, body.route, body.step) {
        (Submission::Single { .. }, MessageRoute::Single, AeadStep::Ready)
        | (Submission::Begin(_), MessageRoute::Multipart, AeadStep::Ready) => true,
        (
            Submission::Update(_) | Submission::Last { .. },
            MessageRoute::Multipart,
            AeadStep::Receive(index),
        ) => index.checked_add(1) == Some(body.frames.len()),
        _ => false,
    };
    if !matches {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadSubmissionRoute,
        )));
    }
    if let Some(bytes) = submission.bytes() {
        body.input
            .as_ref()
            .expect("checked AEAD input")
            .state
            .submission(bytes.len(), false)?;
    }
    if let Some(message) = submission.message() {
        if message.origin.kind() != body.kind
            || (!body.decrypt && message.expected_tag.is_some())
            || (body.decrypt
                && matches!(submission, Submission::Single { .. })
                && message.expected_tag.is_none())
            || message
                .expected_tag
                .is_some_and(|tag| message.origin.tag_bytes().ok() != Some(tag.len()))
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageSelectionTagRepresentation,
            )));
        }
        message
            .origin
            .validate(message.aad.len(), message.declared_length, body.decrypt)?;
        bounds::ck_length(message.output_capacity)?;
        if let InitBinding::Shared { .. } = &body.init {
            let (origin, _, _) = body.init.reference(&body.frames)?;
            origin.fixed_scalars(message.origin)?;
        }
    }
    if let Submission::Last { expected_tag, .. } = submission {
        let frame = body.frames.last().expect("checked active AEAD message");
        if (!body.decrypt && expected_tag.is_some())
            || (body.decrypt && expected_tag.is_none() && frame.expected_tag.is_none())
            || expected_tag.is_some_and(|tag| frame.origin.tag_bytes().ok() != Some(tag.len()))
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadFinalTagRepresentation,
            )));
        }
    }
    let rows = body.frames.len();
    let next_rows = rows
        .checked_add(usize::from(submission.message().is_some()))
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadRowCountOverflow,
        )))?;
    let outputs = &body.outputs.as_ref().expect("checked AEAD outputs").entries;
    let grow = (next_rows > body.frames.capacity() || next_rows > outputs.capacity())
        .then(|| next_rows.checked_next_power_of_two().unwrap_or(next_rows));
    let report = if submission.message().is_some() {
        let maximum = next_rows.checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadReportCountOverflow,
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
        grow,
        old_metadata: storage::vector_bytes(&body.frames)?,
        report,
        generated_nonce: !body.decrypt
            && submission
                .message()
                .is_some_and(|message| message.origin.generated()),
    })
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
    let message = submission.message();
    let bytes = submission.bytes();
    let input_bytes = limits.validate_lengths(
        session.inner.crypto_options.limits,
        usize::from(bytes.is_some()),
        bytes.into_iter().map(|bytes| Ok(bytes.len())),
    )?;
    let mut total = input_bytes;
    for data in [
        message.map(|m| m.aad),
        message.and_then(|m| m.expected_tag),
        submission.last_tag(),
    ]
    .into_iter()
    .flatten()
    {
        bounds::ck_length(data.len())?;
        total = total.checked_add(data.len()).ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadInputSizeOverflow,
            ),
        ))?;
    }
    if total > limits.maximum_total_bytes {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadInputCeiling,
        )));
    }
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
                    .is_some_and(|(expected, _)| *expected == current);
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
                    .expect("checked AEAD report")
                    .check_report_growth(
                        maximum,
                        candidate
                            .as_ref()
                            .expect("prepared AEAD input")
                            .1
                            .report
                            .as_ref(),
                    )?;
            }
            access
                .operations
                .claim_progress(&session.entry, operation.id)?;
            let (_, mut prepared) = candidate.take().expect("matching AEAD preparation");
            let old_report = if let Some((maximum, _)) = current.report {
                operation
                    .validation
                    .as_mut()
                    .expect("checked AEAD report")
                    .attach_report_growth(maximum, prepared.report.take())
                    .expect("checked report under same possession")
            } else {
                None
            };
            let OperationBody::AeadMessages(body) = &mut operation.body else {
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
        let waiting = waiter.as_mut().expect("registered AEAD input waiter");
        let diagnostics = diagnostics
            .as_mut()
            .expect("submission diagnostics prepared");
        match storage::Prepared::prepare(
            diagnostics.budget(),
            current,
            submission,
            &admission,
            || {
                crate::advanced::preparation::context(session)?;
                if waiting.changed() {
                    return Err(Error::Busy(crate::BusyReason::AeadMessages(
                        crate::AeadMessagesBusy::AeadControlChanged,
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
    let mut released = poll::ReleasedInputs::default();
    let access = session.advanced_access()?;
    {
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        if check_owner(&operation, session, ticket.id)?.step != AeadStep::Ready {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::FinishAeadMessageBeforeItsParent,
            )));
        }
        access
            .operations
            .claim_progress(&session.entry, operation.id)?;
        let OperationBody::AeadMessages(body) = &mut operation.body else {
            unreachable!()
        };
        body.input
            .as_mut()
            .expect("checked AEAD stream")
            .state
            .close();
        body.step = AeadStep::Finish;
    }
    let result = poll::poll_with_access(session, ticket, &access, pacing, &mut released);
    poll_diagnostics.retired_owner = released.take_owner();
    result
}
