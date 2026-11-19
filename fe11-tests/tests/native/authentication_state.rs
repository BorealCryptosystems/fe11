// SPDX-License-Identifier: Apache-2.0
//! Token-wide authentication transitions with independent state observations.
use super::{
    authentication_state_action::{self, Resources},
    authentication_state_case::Case,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

fn close(session: &Session, object: Option<&NativeObjectRef>, errors: &mut Vec<Failure>) {
    if let Some(object) = object {
        if let Err(error) = session.destroy_native_object(object) {
            errors.push(error.into());
        }
    }
    match session.info() {
        Ok(info) if authentication_state_action::role(info.state).is_some() => {
            if let Err(error) = session.logout() {
                errors.push(error.into());
            }
        }
        Ok(_) => (),
        Err(error) => errors.push(error.into()),
    }
    if let Err(error) = session.close() {
        errors.push(error.into());
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut context = None;
    let mut session = None;
    let mut resources = Resources {
        peer: None,
        object: None,
        closed: false,
    };
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        context = Some(module.select(&token)?);
        let context = context
            .as_ref()
            .ok_or(Failure::Input("authentication_context"))?;
        session = Some(context.open_session(case.writable())?);
        let session = session
            .as_ref()
            .ok_or(Failure::Input("authentication_session"))?;
        if let Some(role) = authentication_state_action::role(case.before) {
            session.login_as(
                role,
                SecretPin::new(if role == LoginRole::SecurityOfficer {
                    pins.officer.to_vec()
                } else {
                    pins.user.to_vec()
                }),
            )?;
        }
        if session.info()?.state != case.before {
            return Err(Failure::Oracle("authentication_state_before"));
        }
        if case.action == "login_so_with_ro_peer" {
            if case.before != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Input("officer_peer_initial_state"));
            }
            resources.peer = Some(context.open_session(false)?);
            if resources
                .peer
                .as_ref()
                .ok_or(Failure::Input("authentication_peer"))?
                .info()?
                .state
                != fe11_sys::CKS_RO_PUBLIC_SESSION as u64
            {
                return Err(Failure::Oracle("officer_peer_before"));
            }
        }
        if case.action == "close_with_peer" {
            resources.peer = Some(context.open_session(case.writable())?);
            if resources
                .peer
                .as_ref()
                .ok_or(Failure::Input("authentication_peer"))?
                .info()?
                .state
                != case.before
            {
                return Err(Failure::Oracle("authentication_peer_before"));
            }
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match (&session, &context) {
                (Some(session), Some(context)) => authentication_state_action::check(
                    session,
                    context,
                    &case,
                    pins,
                    &mut resources,
                    &mut report,
                ),
                _ => Err(Failure::Input("authentication_resources")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if !resources.closed {
        if let Some(session) = &session {
            close(session, resources.object.as_ref(), &mut cleanup);
        }
    }
    if let Some(peer) = &resources.peer {
        close(peer, None, &mut cleanup);
    }
    drop(resources);
    drop(session);
    drop(context);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
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
            "authentication_native_result_and_state",
            Producer::Native,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup_result.is_ok() {
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
