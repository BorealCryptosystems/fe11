// SPDX-License-Identifier: Apache-2.0
//! Local module lifecycle checks retain the real native runtime and its owner.
use super::{
    configuration::{select_token, Budgets, Configuration},
    module_lifecycle,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "active_family_pair.rs"]
mod active_pair;

fn read(path: &Path) -> std::result::Result<(String, String), Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(81)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("fixture_read"))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_utf8"))?;
    let (state, action) = text
        .trim_end_matches('\n')
        .split_once(':')
        .ok_or(Failure::Input("module_control_fixture"))?;
    if !matches!(
        state,
        "OPEN" | "DRAINING" | "CLOSED_WITH_DRAIN" | "CLOSED" | "SHARED_CLIENT"
    ) || !matches!(
        action,
        "begin_drain" | "close" | "drain_close" | "drop_drain" | "observe"
    ) {
        return Err(Failure::Input("module_control_selector"));
    }
    Ok((state.into(), action.into()))
}

fn empty_resources(module: &Module) -> std::result::Result<(), Failure> {
    let value = module.resource_status()?;
    if value.usage != SessionUsage::default() || !value.tokens.is_empty() {
        return Err(Failure::Oracle("module_resources_not_empty"));
    }
    Ok(())
}

fn expect_error<T>(result: fe11::Result<T>, expected: Error) -> std::result::Result<(), Failure> {
    match result {
        Err(actual) if actual == expected => Ok(()),
        Err(actual) => Err(actual.into()),
        Ok(_) => Err(Failure::Oracle("module_refusal_missing")),
    }
}

fn module_closed() -> Error {
    Error::Rejected(RejectionReason::ModuleLifecycle(
        ModuleLifecycleRejection::ModuleClosed,
    ))
}

fn check_owned(
    module: &Module,
    state: &str,
    action: &str,
    closed: &mut bool,
) -> std::result::Result<(), Failure> {
    let mut permit = None;
    if matches!(state, "DRAINING" | "CLOSED_WITH_DRAIN") {
        permit = Some(module.begin_drain()?);
    }
    if state == "CLOSED_WITH_DRAIN" {
        permit
            .as_ref()
            .ok_or(Failure::Input("module_permit"))?
            .close()?;
        *closed = true;
    } else if state == "CLOSED" {
        module.close()?;
        *closed = true;
    } else if state == "SHARED_CLIENT" {
        return Err(Failure::Input("shared_module_requires_shared_owner"));
    }
    let before = module.call_counts()?;
    let mut expected = before.clone();
    let refusal = if matches!(state, "DRAINING" | "CLOSED_WITH_DRAIN") {
        Error::Busy(BusyReason::LocalAdmission(
            LocalAdmissionBusy::ModuleDraining,
        ))
    } else {
        module_closed()
    };
    match action {
        "observe" => empty_resources(module)?,
        "begin_drain" if state != "OPEN" => expect_error(module.begin_drain(), refusal)?,
        "close" if state != "OPEN" => expect_error(module.close(), refusal)?,
        "drain_close" => {
            let drain = permit.as_ref().ok_or(Failure::Input("module_permit"))?;
            if state == "CLOSED_WITH_DRAIN" {
                expect_error(drain.close(), module_closed())?;
            } else if state == "DRAINING" {
                drain.close()?;
                *closed = true;
                let count = expected.entry("C_Finalize").or_default();
                *count = count
                    .checked_add(1)
                    .ok_or(Failure::Input("counter_overflow"))?;
            } else {
                return Err(Failure::Input("drain_close_state"));
            }
        }
        "drop_drain" if state == "CLOSED_WITH_DRAIN" => {
            drop(permit.take());
            expect_error(module.begin_drain(), module_closed())?;
        }
        _ => return Err(Failure::Input("module_control_action")),
    }
    if module.call_counts()? != expected {
        return Err(Failure::Oracle("module_control_dispatch"));
    }
    // A retained drain never escapes the case, including error paths.
    drop(permit);
    Ok(())
}

pub(super) fn finish<W: Write>(
    mut report: Report<W>,
    setup: std::result::Result<(), Failure>,
    body: std::result::Result<(), Failure>,
    cleanup: Vec<Failure>,
) -> io::Result<bool> {
    let started = setup.is_ok();
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "module_owner_and_dispatch_contract",
            Producer::Fe11Local,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}

pub fn execute<W: Write>(
    module: Module, config: &Configuration, path: &Path, mode: &str, report: Report<W>,
) -> io::Result<bool> {
    if mode == "active-pair" {
        return active_pair::execute(module, config, path, report);
    }
    let setup = read(path);
    let mut closed = false;
    let body = match &setup {
        Ok((state, action)) => check_owned(&module, state, action, &mut closed),
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if !closed {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    finish(report, setup.map(|_| ()), body, cleanup)
}

fn shared_body(
    owner: &RuntimeOwner,
    client: Module,
    config: &Configuration,
    action: &str,
    session: &mut Option<Session>,
) -> std::result::Result<(), Failure> {
    let peer = owner.client()?;
    let before = owner.module().call_counts()?;
    let error = Error::Rejected(RejectionReason::ModuleLifecycle(
        ModuleLifecycleRejection::RuntimeOwnerRequired,
    ));
    match action {
        "begin_drain" => expect_error(client.begin_drain(), error)?,
        "close" => expect_error(client.close(), error)?,
        "observe" => empty_resources(&client)?,
        _ => return Err(Failure::Input("shared_module_action")),
    }
    drop(client);
    if owner.module().call_counts()? != before {
        return Err(Failure::Oracle("shared_client_dispatched"));
    }
    let token = select_token(&peer, &config.label).ok_or(Failure::Input("token_not_unique"))?;
    *session = Some(peer.select(&token)?.open_session(true)?);
    module_lifecycle::control(session.as_ref().ok_or(Failure::Input("peer_session"))?)
}

pub fn execute_shared<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let setup = read(path).and_then(|(state, action)| {
        if state != "SHARED_CLIENT" {
            return Err(Failure::Input("shared_module_state"));
        }
        let (owner, client) = config.builder(&Budgets::ordinary()).open_shared()?;
        Ok((owner, client, action))
    });
    let (owner, client, action) = match setup {
        Ok(value) => value,
        Err(error) => return finish(report, Err(error), Ok(()), Vec::new()),
    };
    let mut session = None;
    let body = shared_body(&owner, client, config, &action, &mut session);
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Err(error) = owner.module().close() {
        cleanup.push(error.into());
    }
    finish(report, Ok(()), body, cleanup)
}
