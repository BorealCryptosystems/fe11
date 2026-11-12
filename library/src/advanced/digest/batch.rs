// SPDX-License-Identifier: Apache-2.0
//! Complete-input extension digests share the caller-fed digest owner.
use crate::advanced::{poll, OperationBody, OperationPacing, OperationProgress};
use crate::{Error, ExtensionInput, ExtensionResult, InputLimits, Result, Session};

/// Invocation-owned diagnostics remain live through the outer facade's projection.
#[derive(Default)]
pub(crate) struct Invocation {
    retired_owner: Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
    polling: poll::PollDiagnostics,
    parking: Option<crate::error::PreparedFailurePair>,
}

pub(crate) fn execute<'a>(
    session: &Session,
    request: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    root: &mut Invocation,
) -> Result<ExtensionResult> {
    let request = request.into();
    if session.entry.mode != crate::AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::ExtensionDigestAsynchronousModeUnavailable,
        )));
    }
    // Digest has no authentication key role. Do not silently ignore an operand.
    if authentication.is_some() {
        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::DigestHasNoContextAuthenticationRole,
        )));
    }
    let single;
    let (parts, route, capacity) = match input {
        ExtensionInput::Digest {
            input,
            output_capacity,
        } => {
            single = [input];
            (&single[..], crate::MessageRoute::Single, output_capacity)
        }
        ExtensionInput::DigestMultipart {
            parts,
            output_capacity,
        } => (parts, crate::MessageRoute::Multipart, output_capacity),
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::ExtensionDigestFacadeRoute,
            )))
        }
    };
    let (mut ticket, held, prepared_diagnostic) = super::start_retained(
        session,
        parts,
        limits,
        super::DigestSelection::Extension {
            mechanism: request.contract.native_mechanism(),
            capacity,
            route,
        },
        None,
        false,
        false,
        &mut 1,
        crate::advanced::input::InputState::closed(),
        Some(request),
        true,
        &mut root.retired_owner,
    )?;
    root.parking = prepared_diagnostic;
    let result = match poll::poll_operation_with_diagnostics(
        session,
        &mut ticket,
        crate::session::CleanupAdmission::Ordinary,
        OperationPacing::Eager,
        &mut root.polling,
    ) {
        Ok(OperationProgress::ExtensionDigest(result)) => Ok(result),
        Ok(_) => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::ExtensionDigestFacadeIncomplete,
        ))),
        Err(error) => Err(error),
    };
    retain_on_error(
        result,
        &mut ticket,
        &held,
        root.parking.as_mut().expect("facade diagnostic prepared"),
    )
}

/// Complete-input native facades retain exactly the same owner as streaming
/// callers. In particular, BUFFER_TOO_SMALL must not strand a live operation
/// merely because this convenience method cannot return both error and ticket.
pub(super) fn native(
    session: &Session,
    parts: &[&[u8]],
    limits: InputLimits,
    selection: super::DigestSelection,
    oid: Option<&[u8]>,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
    diagnostic: &mut Option<crate::error::PreparedFailurePair>,
) -> Result<crate::NativeDigest> {
    let (mut ticket, held, prepared_diagnostic) = super::start_retained(
        session,
        parts,
        limits,
        selection,
        oid,
        false,
        false,
        &mut 1,
        crate::advanced::input::InputState::closed(),
        None,
        true,
        retired_owner,
    )?;
    *diagnostic = prepared_diagnostic;
    let result = session.finish_native_digest(&mut ticket);
    retain_on_error(
        result,
        &mut ticket,
        &held,
        diagnostic.as_mut().expect("facade diagnostic prepared"),
    )
}

fn retain_on_error<T>(
    result: Result<T>,
    ticket: &mut crate::advanced::OperationTicket,
    held: &std::sync::Arc<crate::advanced::ledger::OperationCell>,
    diagnostic: &mut crate::error::PreparedFailurePair,
) -> Result<T> {
    if result.is_err() && ticket.id != 0 {
        // Hold the installed ledger owner across the call. Parking cannot itself
        // wait for a budget or repeat admission after a deadline has elapsed.
        let parked = (|| -> Result<()> {
            let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::StaleDigestFacadeTicket,
                )));
            }
            let OperationBody::Digest(body) = &mut operation.body else {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestFacadeOwnerChanged,
                )));
            };
            if body.observer != super::Observer::Ticket {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestFacadeObserverChanged,
                )));
            }
            body.observer = super::Observer::Session;
            ticket.id = 0;
            Ok(())
        })();
        if let Err(cleanup) = parked {
            let error = result.err().expect("failed digest facade");
            return Err(diagnostic.finish(error, cleanup));
        }
    }
    result
}
