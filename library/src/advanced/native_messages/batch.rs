// SPDX-License-Identifier: Apache-2.0
//! Complete-input messages delegate to the same explicit stream transitions.
use super::{
    input::{self, Submission},
    start, DataKind, MessageOutput, Observer,
};
use crate::advanced::{
    progress, OperationBody, OperationPacing, OperationProgress, OperationTicket,
};
use crate::mechanism_extension::{graph::recipe, parameter_keys::ParameterKeys, OwnedGraph};
use crate::{
    bounds, ContextAuthentication, Error, InputLimits, MessageRoute, NativeMessageAction,
    NativeMessageResult, NativeMessageRoute, NativeObjectRef, Result, Session,
};
use std::sync::Arc;

/// Facade-only error leaves. The root retains their credit after native-owner
/// retirement and until effect mapping has returned the complete result.
pub(super) struct Diagnostics {
    refusal: Option<crate::error::CleanupDiagnostic>,
    parking: Option<crate::error::FailurePair>,
    submission: Option<progress::FailureDiagnostics>,
    credit: crate::symmetric::memory::Credit,
}
impl Diagnostics {
    pub(super) fn allocation_bytes(verify: bool) -> usize {
        crate::error::FailurePair::allocation_bytes()
            + progress::FailureDiagnostics::allocation_bytes()
            + if verify {
                crate::error::CleanupDiagnostic::allocation_bytes()
            } else {
                0
            }
    }

    pub(super) fn preparation_bytes(verify: bool) -> usize {
        Self::allocation_bytes(verify) + crate::symmetric::memory::Budget::observation_bytes()
    }

    pub(super) fn prepare(
        verify: bool,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        let mut credit = prepaid.split(Self::allocation_bytes(verify))?;
        Ok(Self {
            refusal: verify
                .then(crate::error::CleanupDiagnostic::prepare_sequence)
                .transpose()?,
            parking: Some(crate::error::FailurePair::allocate()?),
            submission: Some(progress::FailureDiagnostics::from_prepaid(&mut credit)?),
            credit,
        })
    }

    fn refusal(&mut self, error: Error) -> crate::error::CleanupDiagnostic {
        let mut diagnostic = self
            .refusal
            .take()
            .expect("one facade verification refusal");
        diagnostic.replace_operation(error);
        diagnostic
    }
}

/// Preserve the historical facade's complete-input validation, exact route and
/// fragment boundaries. Allocation and dispatch then use the incremental owner;
/// previously consumed data is not copied into a second batch owner.
/// The public facade retains parking, input and authentication error credits.
#[derive(Default)]
pub(crate) struct Invocation {
    retirement: crate::advanced::PollDiagnostics,
    polling: crate::advanced::PollDiagnostics,
    diagnostics: Option<Diagnostics>,
    authentication: Option<crate::session::ContextDiagnostics>,
}

pub(crate) fn execute(
    session: &Session,
    request: recipe::Request<'_>,
    key: &NativeObjectRef,
    route: NativeMessageRoute<'_>,
    action: NativeMessageAction<'_>,
    limits: InputLimits,
    authentication: Option<ContextAuthentication>,
    keys: ParameterKeys<'_>,
    root: &mut Invocation,
) -> Result<NativeMessageResult> {
    let (verify, signature, capacity) = match &action {
        NativeMessageAction::Sign { output_capacity } => (false, &[][..], *output_capacity),
        NativeMessageAction::Verify { signature } => (true, *signature, 0),
    };
    let (route, begin, updates, last) = match route {
        NativeMessageRoute::Single(part) => (MessageRoute::Single, None, &[][..], part),
        NativeMessageRoute::Multipart {
            begin,
            updates,
            last,
        } => (MessageRoute::Multipart, begin, updates, last),
    };
    let operation = crate::mechanism_extension::message::operation_kind(
        !verify,
        route == MessageRoute::Multipart,
    );
    request.contract.check(&session.inner, operation)?;
    keys.validate(request.parameters.recipe())?;
    OwnedGraph::recipe_bytes(request.parameters.recipe())?;
    bounds::ck_length(capacity)?;
    bounds::ck_length(signature.len())?;
    let count = updates.len().checked_add(1).ok_or(Error::Rejected(
        crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::MessagePartCountOverflow,
        ),
    ))?;
    limits.validate_lengths(
        session.inner.crypto_options.limits,
        count,
        updates
            .iter()
            .chain(std::iter::once(&last))
            .map(|part| Ok(part.data.len())),
    )?;
    let mut mutates = request.contract.mutates_key();
    for parameters in std::iter::once(begin)
        .chain(updates.iter().map(|part| part.parameters))
        .chain(std::iter::once(last.parameters))
        .flatten()
    {
        parameters.contract.check(&session.inner, operation)?;
        if parameters.contract.native_mechanism() != request.contract.native_mechanism() {
            return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::MessageParameterMechanismMismatch,
            )));
        }
        OwnedGraph::allocation_bytes(&parameters.parameters)?;
        mutates |= parameters.contract.mutates_key();
    }
    // Keep invalid authentication requests outside native initialization. Its
    // actual allocation and Login use the shared retained-operation admission.
    crate::session::ContextLoginPlan::new(session, authentication.as_ref())?;
    let result = (|| {
        let (mut ticket, held, prepared_diagnostics) = start::start_retained(
            session,
            key,
            request,
            keys,
            route,
            verify,
            mutates,
            false,
            true,
            authentication.as_ref(),
            &mut root.retirement,
        )?;
        root.diagnostics = prepared_diagnostics;
        let continuation_budget = root
            .diagnostics
            .as_ref()
            .expect("facade diagnostics prepared")
            .credit
            .budget()
            .clone();
        let outcome = (|| {
            if let Some(authentication) = authentication {
                let completed = session.authenticate_context_with_budget(
                    &ticket,
                    authentication,
                    &continuation_budget,
                )?;
                root.authentication = Some(completed.diagnostics);
                completed.result?;
            }
            if route == MessageRoute::Multipart {
                ready(
                    input::submit_with_budget(
                        session,
                        &mut ticket,
                        Submission::Begin(begin),
                        limits,
                        OperationPacing::Eager,
                        &continuation_budget,
                        &mut root
                            .diagnostics
                            .as_mut()
                            .expect("facade diagnostics prepared")
                            .submission,
                        &mut root.polling,
                    )?,
                    mutates,
                )?;
                for part in updates {
                    ready(
                        input::submit_with_budget(
                            session,
                            &mut ticket,
                            Submission::Data {
                                kind: DataKind::Update,
                                part: *part,
                                action: None,
                            },
                            limits,
                            OperationPacing::Eager,
                            &continuation_budget,
                            &mut root
                                .diagnostics
                                .as_mut()
                                .expect("facade diagnostics prepared")
                                .submission,
                            &mut root.polling,
                        )?,
                        mutates,
                    )?;
                }
            }
            ready(
                input::submit_with_budget(
                    session,
                    &mut ticket,
                    Submission::Data {
                        kind: if route == MessageRoute::Single {
                            DataKind::Single
                        } else {
                            DataKind::Last
                        },
                        part: last,
                        action: Some(action.into()),
                    },
                    limits,
                    OperationPacing::Eager,
                    &continuation_budget,
                    &mut root
                        .diagnostics
                        .as_mut()
                        .expect("facade diagnostics prepared")
                        .submission,
                    &mut root.polling,
                )?,
                mutates,
            )?;

            // The streaming API retains per-message verification refusals to
            // permit more messages. The one-message facade returns the original
            // native error after Final, even when Final adds a cleanup failure.
            let refusal = verification_refusal(&held, ticket.id, route, mutates)?.map(|error| {
                root.diagnostics
                    .as_mut()
                    .expect("facade diagnostics prepared")
                    .refusal(error)
            });
            let finished = input::finish(
                session,
                &mut ticket,
                OperationPacing::Eager,
                &mut root.polling,
            )
            .and_then(|progress| match progress {
                OperationProgress::NativeMessages(result) => {
                    NativeMessageResult::from_messages(result)
                }
                _ => Err(Error::Rejected(crate::RejectionReason::NativeMessages(
                    crate::NativeMessagesRejection::GenericMessageFacadeIncomplete,
                ))),
            });
            match (refusal, finished) {
                (Some(primary), Ok(_)) => Err(primary.finish_sequence(None)),
                (
                    Some(primary),
                    Err(Error::Native {
                        function: "C_MessageVerifyFinal",
                        code,
                        ..
                    }),
                ) if code == fe11_sys::CKR_OPERATION_NOT_INITIALIZED as u64 && ticket.id == 0 => {
                    // The common driver retired this inactive owner. Keep
                    // the original Verify refusal without a false second
                    // cleanup failure; no other Final error is suppressed.
                    Err(primary.finish_sequence(None))
                }
                (Some(primary), Err(cleanup)) => Err(primary.finish_sequence(Some(cleanup))),
                (None, result) => result,
            }
        })();
        match outcome {
            Err(error) if ticket.id != 0 => {
                // Never silently retry a size request or erase an active owner
                // after authentication/preparation fails. Transfer its ticket
                // once so the caller can choose explicit continuation or cleanup.
                match park_ticket(session, &mut ticket, &held) {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(root
                        .diagnostics
                        .as_mut()
                        .expect("facade diagnostics prepared")
                        .parking
                        .take()
                        .expect("one facade parking attempt")
                        .finish(error, cleanup)),
                }
            }
            result => result,
        }
    })();
    result.map_err(|error| crate::mechanism_extension::operation::effect(error, mutates))
}

fn ready(progress: OperationProgress, _mutates: bool) -> Result<()> {
    match progress {
        OperationProgress::Ready => Ok(()),
        OperationProgress::SignatureBufferRequired(request) => {
            Err(Error::SignatureBufferRequired(request))
        }
        _ => Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageInputBoundaryNotEstablished,
        ))),
    }
}

fn verification_refusal(
    held: &Arc<crate::advanced::ledger::OperationCell>,
    id: u64,
    route: MessageRoute,
    mutates: bool,
) -> Result<Option<Error>> {
    let operation = held.lock().map_err(|_| Error::Poisoned)?;
    if operation.id != id {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::StaleGenericMessageTicket,
        )));
    }
    let OperationBody::NativeMessages(body) = &operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageTicketRequired,
        )));
    };
    let message =
        body.messages
            .first()
            .ok_or(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::GenericMessageResultAbsent,
            )))?;
    Ok(match message.output {
        MessageOutput::Verify {
            verdict: Some(code),
        } if code != fe11_sys::CKR_OK => Some(Error::Native {
            function: if route == MessageRoute::Single {
                "C_VerifyMessage"
            } else {
                "C_VerifyMessageNext"
            },
            code: code as u64,
            may_have_effect: mutates,
        }),
        _ => None,
    })
}

fn park_ticket(
    session: &Session,
    ticket: &mut OperationTicket,
    held: &Arc<crate::advanced::ledger::OperationCell>,
) -> Result<()> {
    if ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner) {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::ForeignOrConsumedGenericMessageTicket,
        )));
    }
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    if operation.id != ticket.id {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::StaleGenericMessageTicket,
        )));
    }
    let OperationBody::NativeMessages(body) = &mut operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageTicketRequired,
        )));
    };
    if body.observer != Observer::Ticket {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageTicketAlreadyTransferred,
        )));
    }
    body.observer = Observer::Session;
    ticket.id = 0;
    Ok(())
}

pub(super) fn take_ticket(session: &Session) -> Result<OperationTicket> {
    // This is a local ticket transfer, not admission to use native pointers.
    // Keep the module and session gates for ledger identity/close exclusion,
    // but deliberately do not call entry_common or validate native usability:
    // an uncertain/poisoned owner still needs a descriptive cleanup ticket.
    // StateLock retains its normal drain gate; no drain permit is invented.
    let state = session.inner.state.read()?;
    let _session = session.entry.operation.acquire(&session.admission())?;
    let held = state.operations.get(session.uid)?;
    let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
    let OperationBody::NativeMessages(body) = &mut operation.body else {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageTicketRequired,
        )));
    };
    if body.observer != Observer::Session {
        return Err(Error::Rejected(crate::RejectionReason::NativeMessages(
            crate::NativeMessagesRejection::GenericMessageContinuationTicketUnavailable,
        )));
    }
    body.observer = Observer::Ticket;
    Ok(OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id: operation.id,
        validation_report: None,
        state_provenance: None,
    })
}
