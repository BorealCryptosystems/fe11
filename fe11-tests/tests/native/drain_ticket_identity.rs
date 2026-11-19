// SPDX-License-Identifier: Apache-2.0
//! Drain permits do not authorize a foreign or consumed operation ticket.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    module_controls,
    object_owner::Owner,
    outcome::Failure,
    report::Report,
    ticket_identity_action as digest,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

enum Drain {
    Module(ModuleDrain),
    Token(TokenDrain),
}
impl Drain {
    fn poll(
        &self,
        session: &AdvancedSession,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        match self {
            Self::Module(d) => d.poll_advanced(session, ticket),
            Self::Token(d) => d.poll_advanced(session, ticket),
        }
    }
    fn close(&self, session: &AdvancedSession) -> Result<AdvancedCloseStatus> {
        match self {
            Self::Module(d) => d.close_advanced_session(session),
            Self::Token(d) => d.close_advanced_session(session),
        }
    }
}
fn open(context: &TokenContext) -> std::result::Result<Owner, Failure> {
    let mut session = context.open_session(true)?.into_advanced()?;
    session.set_pacing(OperationPacing::Cooperative)?;
    session.set_validation_capture(ValidationCaptureMode::Disabled)?;
    Ok(Owner::Advanced(session))
}
fn read(path: &Path) -> std::result::Result<(bool, bool), Failure> {
    let mut input = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("drain_ticket_open"))?
        .take(65)
        .read_to_end(&mut input)
        .map_err(|_| Failure::Input("drain_ticket_read"))?;
    match input.as_slice() {
        b"module\nforeign\n" => Ok((false, false)),
        b"module\nconsumed\n" => Ok((false, true)),
        b"token\nforeign\n" => Ok((true, false)),
        b"token\nconsumed\n" => Ok((true, true)),
        _ => Err(Failure::Input("drain_ticket_fields")),
    }
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut origin = None;
    let mut other = None;
    let mut ticket = None;
    let mut published = None;
    let mut drain = None;
    let setup = (|| -> std::result::Result<(bool, Vec<u8>), Failure> {
        let (token_drain, consumed) = read(path)?;
        let identity =
            select_token(&module, &config.label).ok_or(Failure::Input("drain_ticket_token"))?;
        // Keep one exact context for all sessions and its permit. A refreshed
        // snapshot would test a foreign session instead of a foreign ticket.
        let context = module.select(&identity)?;
        origin = Some(open(&context)?);
        if !consumed {
            other = Some(open(&context)?);
        }
        let producer = origin
            .as_ref()
            .ok_or(Failure::Input("drain_ticket_origin"))?;
        ticket = Some(digest::begin(producer)?);
        let expected = hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            32,
        )
        .map_err(Failure::Input)?;
        if consumed {
            let value = digest::finish(
                producer,
                ticket
                    .as_mut()
                    .ok_or(Failure::Input("drain_ticket_producer"))?,
            )?;
            if value.as_bytes() != expected {
                return Err(Failure::Oracle("drain_ticket_digest"));
            }
            published = Some(value);
        }
        drain = Some(if token_drain {
            Drain::Token(context.begin_drain()?)
        } else {
            Drain::Module(module.begin_drain()?)
        });
        Ok((consumed, expected))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((consumed, _)) = &setup else {
            return Ok(());
        };
        let receiver = if *consumed { &origin } else { &other };
        let Some(Owner::Advanced(receiver)) = receiver else {
            return Err(Failure::Input("drain_ticket_receiver"));
        };
        let permit = drain
            .as_ref()
            .ok_or(Failure::Input("drain_ticket_permit"))?;
        let ticket = ticket
            .as_mut()
            .ok_or(Failure::Input("drain_ticket_producer"))?;
        let before = module.call_counts()?;
        match permit.poll(receiver, ticket) {
            Err(Error::Rejected(RejectionReason::Authentication(
                AuthenticationRejection::ForeignOrConsumedOperationTicket,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("drain_ticket_accepted")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("drain_ticket_dispatched"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    for owner in [&other, &origin].into_iter().flatten() {
        if let (Some(permit), Owner::Advanced(session)) = (&drain, owner) {
            match permit.close(session) {
                Ok(AdvancedCloseStatus::Complete) => (),
                Ok(AdvancedCloseStatus::Pending) => {
                    cleanup.push(Failure::Oracle("drain_ticket_close_pending"))
                }
                Err(error) => cleanup.push(error.into()),
            }
        } else {
            cleanup.extend(owner.close(None));
        }
    }
    drop(ticket);
    drop(other);
    drop(origin);
    drop(drain);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let (Ok((_, expected)), Some(value)) = (&setup, &published) {
        if value.as_bytes() != expected {
            cleanup.push(Failure::Oracle("drain_ticket_output_changed"));
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
