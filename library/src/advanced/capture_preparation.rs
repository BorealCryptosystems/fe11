// SPDX-License-Identifier: Apache-2.0
//! Initial capture preparation dispatch. Each family owns its shape and copy
//! invariants; the shared result retains the exact source revision until install.
use super::{progress, saved_state::CaptureOwner, state_io::StateIo, OperationTicket};
use crate::{Result, Session};
mod aead;
mod aead_stream;
mod cipher;
mod digest;
mod digest_extension;
mod dual;
mod messages;
mod native_messages;
mod recover;
mod signature;

pub(super) struct PreparedCapture<'a> {
    pub(super) owner: CaptureOwner,
    pub(super) io: StateIo,
    pub(super) waiter: progress::Waiter<'a>,
}

pub(super) fn prepare<'a>(
    session: &'a Session,
    ticket: &OperationTicket,
    state_maximum: usize,
    diagnostics: &mut Option<progress::FailureDiagnostics>,
) -> Result<PreparedCapture<'a>> {
    StateIo::validate_capture_maximum(state_maximum)?;
    enum Family {
        Digest,
        DigestExtension,
        Recover,
        Signature,
        NativeMessages,
        Messages,
        Dual,
        Cipher,
        Aead,
        AeadStream,
    }
    loop {
        let family = {
            let access = session.advanced_access()?;
            let held = access.operations.get(ticket.uid)?;
            let operation = held.lock().map_err(|_| crate::Error::Poisoned)?;
            if operation.id != ticket.id {
                return Err(crate::Error::Rejected(
                    crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::StaleOperationTicket,
                    ),
                ));
            }
            operation.check_authentication(&session.entry)?;
            if operation.capture_owner().is_some() {
                return Err(crate::Error::Busy(crate::BusyReason::CheckpointCapture(
                    crate::CheckpointCaptureBusy::StateCaptureActive,
                )));
            }
            super::continuation::Continuation::check_capture(&operation, &session.entry)?;
            match &operation.body {
                super::OperationBody::Digest(body) if body.frame.extension.is_some() => {
                    Family::DigestExtension
                }
                super::OperationBody::Digest(_) => Family::Digest,
                super::OperationBody::Recover(_) => Family::Recover,
                super::OperationBody::Signature(_) => Family::Signature,
                super::OperationBody::NativeMessages(_) => Family::NativeMessages,
                super::OperationBody::Messages(_) => Family::Messages,
                super::OperationBody::Dual(_) => Family::Dual,
                super::OperationBody::Cipher(_) => Family::Cipher,
                super::OperationBody::AeadMessages(body) if body.caller_fed() => Family::AeadStream,
                super::OperationBody::AeadMessages(_) => Family::Aead,
                _ => {
                    return Err(crate::Error::Rejected(
                        crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::OperationFamilyNotCapturable,
                        ),
                    ))
                }
            }
        };
        // The route is only a hint. Each family reacquires source possession and
        // checks the exact ticket, authentication and capture phase before copying.
        if diagnostics.is_none() {
            *diagnostics = Some(progress::FailureDiagnostics::prepare(session, ticket.id)?);
        }
        let diagnostics = diagnostics.as_mut().expect("capture diagnostics prepared");
        let prepared = match family {
            Family::Digest => digest::prepare(session, ticket, state_maximum, diagnostics),
            Family::DigestExtension => {
                digest_extension::prepare(session, ticket, state_maximum, diagnostics)
            }
            Family::Recover => recover::prepare(session, ticket, state_maximum, diagnostics),
            Family::Signature => signature::prepare(session, ticket, state_maximum, diagnostics),
            Family::NativeMessages => {
                native_messages::prepare(session, ticket, state_maximum, diagnostics)
            }
            Family::Messages => messages::prepare(session, ticket, state_maximum, diagnostics),
            Family::Dual => dual::prepare(session, ticket, state_maximum, diagnostics),
            Family::Cipher => cipher::prepare(session, ticket, state_maximum, diagnostics),
            Family::Aead => aead::prepare(session, ticket, state_maximum, diagnostics),
            Family::AeadStream => aead_stream::prepare(session, ticket, state_maximum, diagnostics),
        }?;
        if let Some(prepared) = prepared {
            return Ok(prepared);
        }
        // A family can change between routing and possession. Re-read the source
        // with the same ticket and admission policy; never fall back to allocation
        // under Operation or replay a native request.
    }
}
