// SPDX-License-Identifier: Apache-2.0
//! Owned-module drain and close transitions with native dispatch observations.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("fixture_read"))?;
    match bytes.as_slice() {
        b"open\n" => Ok("open".into()),
        b"refresh_active\n" => Ok("refresh_active".into()),
        b"drain_roundtrip\n" => Ok("drain_roundtrip".into()),
        b"close_empty\n" => Ok("close_empty".into()),
        b"drain_close\n" => Ok("drain_close".into()),
        _ => Err(Failure::Input("module_lifecycle_fixture")),
    }
}
fn closed_again(module: &Module) -> std::result::Result<(), Failure> {
    match module.close() {
        Err(Error::Rejected(RejectionReason::ModuleLifecycle(
            ModuleLifecycleRejection::ModuleClosed,
        ))) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("closed_module_accepted")),
    }
}
pub(super) fn control(session: &Session) -> std::result::Result<(), Failure> {
    if session.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
        return Err(Failure::Oracle("fresh_session_state"));
    }
    let digest = session.digest_multipart(
        HashAlgorithm::Sha256,
        &[b"abc"],
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
    )?;
    let expected = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected {
        return Err(Failure::Oracle("module_session_digest"));
    }
    Ok(())
}
fn check(
    module: &Module,
    config: &Configuration,
    action: &str,
    session: &mut Option<Session>,
    session_closed: &mut bool,
    module_closed: &mut bool,
) -> std::result::Result<(), Failure> {
    let token = select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
    let context = module.select(&token)?;
    match action {
        "open" => {
            let before = module.call_counts()?;
            let info = module.info();
            let version = match config.interface {
                InterfaceSelection::Legacy240 => (2, 40),
                InterfaceSelection::Standard { version, .. } => version,
                _ => return Err(Failure::Input("module_lifecycle_interface")),
            };
            match &info.provenance {
                ModuleProvenance::File { file, .. }
                    if file.path == config.module && file.sha256 == config.module_sha256 =>
                {
                    ()
                }
                _ => return Err(Failure::Oracle("module_open_provenance")),
            }
            if info.function_list_version != version || module.call_counts()? != before {
                return Err(Failure::Oracle("module_info_or_dispatch"));
            }
            *session = Some(context.open_session(true)?);
            control(session.as_ref().ok_or(Failure::Input("module_session"))?)?;
        }
        "refresh_active" => {
            *session = Some(context.open_session(true)?);
            let before = module.call_counts()?;
            match context.refresh() {
                Err(Error::Rejected(RejectionReason::TokenAdministration(
                    TokenAdministrationRejection::ChangedTokenSessionsRequireClose,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("refresh_live_session_accepted")),
            }
            if module.call_counts()? != before {
                return Err(Failure::Oracle("refresh_refusal_dispatched"));
            }
            let live = session.as_ref().ok_or(Failure::Input("refresh_session"))?;
            control(live)?;
            live.close()?;
            *session_closed = true;
            let _replacement = context.refresh()?;
        }
        "drain_roundtrip" => {
            let before = module.call_counts()?;
            let permit = module.begin_drain()?;
            let rejected = context.open_session(true);
            // Release even after an unexpected return before ordinary cleanup.
            drop(permit);
            match rejected {
                Err(Error::Busy(BusyReason::LocalAdmission(
                    LocalAdmissionBusy::ModuleDraining,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(unexpected) => {
                    *session = Some(unexpected);
                    return Err(Failure::Oracle("ordinary_session_opened_during_drain"));
                }
            }
            if module.call_counts()? != before {
                return Err(Failure::Oracle("drain_local_refusal_dispatched"));
            }
            *session = Some(context.open_session(true)?);
            control(session.as_ref().ok_or(Failure::Input("module_session"))?)?;
        }
        "close_empty" => {
            module.close()?;
            *module_closed = true;
            closed_again(module)?;
        }
        "drain_close" => {
            *session = Some(context.open_session(true)?);
            let permit = module.begin_drain()?;
            permit.close_session(session.as_ref().ok_or(Failure::Input("module_session"))?)?;
            *session_closed = true;
            permit.close()?;
            *module_closed = true;
            drop(permit);
            closed_again(module)?;
        }
        _ => return Err(Failure::Input("module_lifecycle_action")),
    }
    Ok(())
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let setup = read(path);
    let started = setup.is_ok();
    let mut session = None;
    let mut session_closed = false;
    let mut module_closed = false;
    let body = match &setup {
        Ok(action) => check(
            &module,
            config,
            action,
            &mut session,
            &mut session_closed,
            &mut module_closed,
        ),
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if !session_closed {
        if let Some(session) = &session {
            if let Err(error) = session.close() {
                cleanup.push(Failure::from(error));
            }
        }
    }
    drop(session);
    if !module_closed {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
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
            "module_lifecycle_and_exact_native_dispatch",
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
