// SPDX-License-Identifier: Apache-2.0
//! A token drain cannot close or progress a session belonging to another token.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
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

const PEER_LABEL: &str = "public-drain-peer";

pub(super) fn second_token(
    module: &Module,
    config: &Configuration,
    pins: &Credentials,
) -> std::result::Result<TokenContext, Failure> {
    if config.label == PEER_LABEL {
        return Err(Failure::Input("drain_peer_namespace"));
    }
    let targets = module.administration_targets()?;
    let blank: Vec<_> = targets
        .iter()
        .filter(|target| target.capabilities().flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 == 0)
        .collect();
    if blank.len() != 1 {
        return Err(Failure::Input("drain_peer_blank_token"));
    }
    // The supervisor owns a fresh private token directory for this case. Only
    // its uninitialized slot is selected; never reset an initialized token.
    module.initialize_token(&blank[0], SecretPin::new(pins.officer.to_vec()), PEER_LABEL)?;
    module.refresh_tokens()?;
    let targets = module.administration_targets()?;
    let peer: Vec<_> = targets
        .iter()
        .filter(|target| {
            let capabilities = target.capabilities();
            let end = capabilities
                .label
                .iter()
                .rposition(|b| *b != b' ')
                .map_or(0, |i| i + 1);
            &capabilities.label[..end] == PEER_LABEL.as_bytes()
                && capabilities.flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 != 0
        })
        .collect();
    if peer.len() != 1 {
        return Err(Failure::Input("drain_peer_identity"));
    }
    Ok(module.select(&peer[0].capabilities().identity)?)
}

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut input = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("drain_session_open"))?
        .take(33)
        .read_to_end(&mut input)
        .map_err(|_| Failure::Input("drain_session_read"))?;
    match input.as_slice() {
        b"close_session\n" => Ok("close_session".into()),
        b"close_advanced_session\n" => Ok("close_advanced_session".into()),
        b"poll_advanced\n" => Ok("poll_advanced".into()),
        _ => Err(Failure::Input("drain_session_action")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut peer = None;
    let mut ticket = None;
    let mut drain = None;
    let mut published = None;
    let setup = (|| -> std::result::Result<String, Failure> {
        let action = read(path)?;
        let context_b = second_token(&module, config, pins)?;
        let identity_a =
            select_token(&module, &config.label).ok_or(Failure::Input("drain_origin_token"))?;
        let context_a = module.select(&identity_a)?;
        let session = context_b.open_session(true)?;
        peer = Some(if action == "close_session" {
            Owner::Session(session)
        } else {
            Owner::Advanced(session.into_advanced()?)
        });
        ticket = Some(digest::begin(
            peer.as_ref().ok_or(Failure::Input("drain_peer_session"))?,
        )?);
        drain = Some(context_a.begin_drain()?);
        Ok(action)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(action) = &setup else { return Ok(()) };
        let peer = peer.as_ref().ok_or(Failure::Input("drain_peer_session"))?;
        let permit = drain
            .as_ref()
            .ok_or(Failure::Input("drain_origin_permit"))?;
        let ticket = ticket.as_mut().ok_or(Failure::Input("drain_peer_ticket"))?;
        let before = module.call_counts()?;
        let result = match (action.as_str(), peer) {
            ("close_session", Owner::Session(s)) => permit.close_session(s),
            ("close_advanced_session", Owner::Advanced(s)) => {
                permit.close_advanced_session(s).map(|_| ())
            }
            ("poll_advanced", Owner::Advanced(s)) => permit.poll_advanced(s, ticket).map(|_| ()),
            _ => return Err(Failure::Input("drain_session_pair")),
        };
        match result {
            Err(Error::Rejected(RejectionReason::ModuleLifecycle(
                ModuleLifecycleRejection::ForeignDrainingSession,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("foreign_drain_session_accepted")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("foreign_drain_session_dispatched"));
        }
        // Token B is not drained. Its exact original ticket remains usable
        // under B's ordinary authority, while A's permit is still retained.
        let value = digest::finish(peer, ticket)?;
        let expected = hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            32,
        )
        .map_err(Failure::Input)?;
        if value.as_bytes() != expected {
            return Err(Failure::Oracle("foreign_drain_digest_changed"));
        }
        published = Some(value);
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(peer) = &peer {
        cleanup.extend(peer.close(None));
    }
    drop(ticket);
    drop(peer);
    drop(drain);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Some(value) = published {
        if value.as_bytes().len() != 32 {
            cleanup.push(Failure::Oracle("foreign_drain_output_lost"));
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
