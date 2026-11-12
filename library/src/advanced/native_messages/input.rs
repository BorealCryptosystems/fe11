// SPDX-License-Identifier: Apache-2.0
//! Shape planning for exactly one caller-supplied message transition.
mod storage;
use super::{
    DataKind, Execution, Message, MessageOutput, NativeMessageOperation, Parameters, Phase,
};
use crate::advanced::{
    poll, preparation, progress, validation, Operation, OperationBody, OperationPacing,
    OperationProgress, OperationTicket,
};
use crate::mechanism_extension::message::{NativeMessageAction, NativeMessagePart};
use crate::{bounds, Error, ExtensionRequest, InputLimits, MessageRoute, Result, Session};
use std::mem::size_of;
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(super) enum Action<'a> {
    Sign(usize),
    Verify(&'a [u8]),
}
impl<'a> From<NativeMessageAction<'a>> for Action<'a> {
    fn from(action: NativeMessageAction<'a>) -> Self {
        match action {
            NativeMessageAction::Sign { output_capacity } => Self::Sign(output_capacity),
            NativeMessageAction::Verify { signature } => Self::Verify(signature),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Submission<'a> {
    Begin(Option<ExtensionRequest<'a>>),
    Data {
        kind: DataKind,
        part: NativeMessagePart<'a>,
        action: Option<Action<'a>>,
    },
}
impl<'a> Submission<'a> {
    fn parameters(self) -> Option<ExtensionRequest<'a>> {
        match self {
            Self::Begin(parameters) => parameters,
            Self::Data { part, .. } => part.parameters,
        }
    }
    fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Self::Begin(_) => None,
            Self::Data { part, .. } => Some(part.data),
        }
    }
    fn signature(self) -> Option<&'a [u8]> {
        match self {
            Self::Data {
                action: Some(Action::Verify(signature)),
                ..
            } => Some(signature),
            _ => None,
        }
    }
    fn capacity(self) -> Option<usize> {
        match self {
            Self::Data {
                action: Some(Action::Sign(capacity)),
                ..
            } => Some(capacity),
            _ => None,
        }
    }
    fn starts_message(self) -> bool {
        matches!(
            self,
            Self::Begin(_)
                | Self::Data {
                    kind: DataKind::Single,
                    ..
                }
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Need {
    messages: usize,
    parts: usize,
    new_message: bool,
    grow_messages: Option<usize>,
    grow_parts: Option<usize>,
    old_messages_bytes: usize,
    old_parts_bytes: usize,
    mechanism: u64,
    verify: bool,
    report: Option<(usize, usize)>,
}

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageSubmissionAccounting,
    ))
}
fn vector_bytes<T>(capacity: usize) -> Result<usize> {
    capacity.checked_mul(size_of::<T>()).ok_or_else(accounting)
}
fn growth(needed: usize, current: usize) -> Option<usize> {
    (needed > current).then(|| needed.checked_next_power_of_two().unwrap_or(needed))
}

/// Called under the operation's possession after its ticket/control checks.
/// Returns numbers only; no source borrow escapes into an admission wait.
fn plan(
    session: &Session,
    body: &NativeMessageOperation,
    observation: Option<&validation::Capture>,
    submission: Submission<'_>,
    limits: InputLimits,
) -> Result<Need> {
    body.binding.check(&session.entry)?;
    if let Some(observation) = observation {
        observation.snapshot_capacity()?;
    }
    if !matches!(body.execution, Execution::Running)
        || !body.input.is_open()
        || !body.input.incremental
        || body.pending()
        || body.input.retained_submission
        || body.released.call.is_some()
        || body.released.output.is_some()
    {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageInputBoundaryUnavailable,
        )));
    }
    let new_message = submission.starts_message();
    let shape_matches = match (submission, body.route, &body.phase) {
        (Submission::Begin(_), MessageRoute::Multipart, Phase::Ready)
        | (
            Submission::Data {
                kind: DataKind::Single,
                ..
            },
            MessageRoute::Single,
            Phase::Ready,
        ) => true,
        (
            Submission::Data {
                kind: DataKind::Update | DataKind::Last,
                ..
            },
            MessageRoute::Multipart,
            Phase::Receive(index),
        ) => index.checked_add(1) == Some(body.messages.len()),
        _ => false,
    };
    if !shape_matches {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageSubmissionRoute,
        )));
    }
    if let Submission::Data { kind, action, .. } = submission {
        if kind.terminal() != action.is_some()
            || action.is_some_and(|action| matches!(action, Action::Verify(_)) != body.verify)
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageTerminalOperands,
            )));
        }
    }
    let bytes = submission.bytes();
    limits.validate_lengths(
        session.inner.crypto_options.limits,
        usize::from(bytes.is_some()),
        bytes.into_iter().map(|bytes| Ok(bytes.len())),
    )?;
    if let Some(signature) = submission.signature() {
        bounds::ck_length(signature.len())?;
        // InputLimits counts the supplied data pieces, as in the complete
        // message facade. The expected signature has its own ABI length check
        // and is fully charged by aggregate storage admission.
    }
    if let Some(capacity) = submission.capacity() {
        bounds::ck_length(capacity)?;
    }
    if let Some(bytes) = bytes {
        body.input.submission(bytes.len(), false)?;
    }
    if let Some(request) = submission.parameters() {
        request
            .contract
            .check(&session.inner, body.binding.primary.contract.operation())?;
        if request.contract.native_mechanism() != body.initialization().kind()
            || request.contract.mutates_key() && !body.binding.writer
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageParameterDeclarationMismatch,
            )));
        }
    }
    let rows = body.messages.len();
    let next_rows = rows
        .checked_add(usize::from(new_message))
        .ok_or_else(accounting)?;
    let (parts, capacity) = if new_message {
        (0, 0)
    } else {
        let message = body.messages.last().ok_or_else(accounting)?;
        if matches!(message.output, MessageOutput::Sign(Some(_))) {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::MessageOutputAlreadySubmitted,
            )));
        }
        (message.parts.len(), message.parts.capacity())
    };
    let next_parts = parts
        .checked_add(usize::from(bytes.is_some()))
        .ok_or_else(accounting)?;
    let report = if new_message {
        observation
            .map(|capture| -> Result<_> {
                let maximum = next_rows.checked_add(1).ok_or_else(accounting)?;
                Ok((maximum, capture.report_growth_bytes(maximum)?))
            })
            .transpose()?
    } else {
        None
    };
    Ok(Need {
        messages: rows,
        parts,
        new_message,
        grow_messages: growth(next_rows, body.messages.capacity()),
        grow_parts: growth(next_parts, capacity),
        old_messages_bytes: vector_bytes::<Message>(body.messages.capacity())?,
        old_parts_bytes: vector_bytes::<Parameters>(capacity)?,
        mechanism: body.initialization().kind() as u64,
        verify: body.verify,
        report,
    })
}

fn ticket_owner(session: &Session, ticket: &OperationTicket) -> Result<()> {
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::ForeignOrConsumedGenericMessageTicket,
        )));
    }
    Ok(())
}

fn check_owner<'a>(
    operation: &'a Operation,
    session: &Session,
    id: u64,
) -> Result<&'a NativeMessageOperation> {
    if operation.id != id {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::StaleGenericMessageTicket,
        )));
    }
    operation.check_control_access(&session.entry)?;
    if let Some(capture) = &operation.validation {
        capture.snapshot_capacity()?;
    }
    let OperationBody::NativeMessages(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageTicketRequired,
        )));
    };
    body.check_key(&session.entry)?;
    if !matches!(body.execution, Execution::Running)
        || !body.input.incremental
        || !body.input.is_open()
        || body.input.retained_submission
        || body.released.call.is_some()
        || body.released.output.is_some()
        || !matches!(body.phase, Phase::Ready | Phase::Receive(_))
    {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageStreamIsNotAwaitingInput,
        )));
    }
    Ok(body)
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
    submit_with_budget(
        session,
        ticket,
        submission,
        limits,
        pacing,
        &session.inner.symmetric_budget,
        diagnostics,
        poll_diagnostics,
    )
}

pub(super) fn submit_with_budget(
    session: &Session,
    ticket: &mut OperationTicket,
    submission: Submission<'_>,
    limits: InputLimits,
    pacing: OperationPacing,
    budget: &Arc<crate::symmetric::memory::Budget>,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
    poll_diagnostics: &mut poll::PollDiagnostics,
) -> Result<OperationProgress> {
    if !budget.same_account(&session.inner.symmetric_budget) {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::ForeignMessagePreparationBudget,
        )));
    }
    ticket_owner(session, ticket)?;
    // Preserve the same absolute deadline/cancellation policy across retries.
    let admission = crate::admission_wait::current();
    let mut waiter: Option<progress::Waiter<'_>> = None;
    let mut candidate: Option<(Need, storage::Prepared)> = None;
    loop {
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let body = check_owner(&operation, session, ticket.id)?;
        let current = plan(
            session,
            body,
            operation.validation.as_ref(),
            submission,
            limits,
        )?;
        if diagnostics.is_none() {
            drop(operation);
            drop(held);
            drop(access);
            *diagnostics = Some(progress::FailureDiagnostics::prepare_in(
                session, budget, ticket.id,
            )?);
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
            let OperationBody::NativeMessages(body) = &mut operation.body else {
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
            .expect("native submission diagnostics prepared");
        match storage::Prepared::prepare(
            diagnostics.budget(),
            current,
            submission,
            &admission,
            || {
                preparation::context(session)?;
                if waiting.changed() {
                    return Err(Error::Busy(crate::BusyReason::NativeMessages(
                        crate::NativeMessagesBusy::GenericMessageControlChanged,
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
        if !matches!(body.phase, Phase::Ready) {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::FinishTheCurrentMessageBeforeTheParentProcess,
            )));
        }
        access
            .operations
            .claim_progress(&session.entry, operation.id)?;
        let OperationBody::NativeMessages(body) = &mut operation.body else {
            unreachable!()
        };
        body.input.close();
        body.phase = Phase::Final;
    }
    let result = poll::poll_with_access(session, ticket, &access, pacing, &mut released);
    poll_diagnostics.retired_owner = released.take_owner();
    result
}

pub(super) fn poll(
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
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id || !matches!(operation.body, OperationBody::NativeMessages(_))
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageTicketRequired,
            )));
        }
    }
    // Unlike input admission, polling must also accept a retained output call
    // or a finalizing parent. The common driver performs their control checks.
    let result = poll::poll_with_access(session, ticket, &access, pacing, &mut released);
    poll_diagnostics.retired_owner = released.take_owner();
    result
}
