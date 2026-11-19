// SPDX-License-Identifier: Apache-2.0
//! Search scenarios isolate native object ownership from iterator lifetime.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    search_action,
    search_fixture::Case,
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut objects = Vec::new();
    let mut logged_in = false;
    let mut closed = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        let session = session.as_ref().ok_or(Failure::Input("search_session"))?;
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged_in = true;
        for index in 0..3 {
            objects.push(case.create(session, index)?);
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let mut cleanup = Vec::new();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match &session {
                Some(session) => {
                    let result = search_action::execute(
                        session,
                        &case,
                        &mut closed,
                        &mut logged_in,
                        &mut report,
                        &mut cleanup,
                    );
                    if result.is_ok() && closed {
                        verify_closed_scope(&module, config, &case, &mut cleanup)
                    } else {
                        result
                    }
                }
                None => Err(Failure::Input("search_session")),
            },
        ),
    };
    if !closed {
        if let Some(session) = &session {
            for object in &objects {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
            if logged_in {
                if let Err(error) = session.logout() {
                    cleanup.push(error.into());
                }
            }
            if let Err(error) = session.close() {
                cleanup.push(error.into());
            }
        }
    }
    // Session objects are natively destroyed by successful CloseSession. Their
    // old references are dropped without issuing DestroyObject on a closed handle.
    drop(objects);
    drop(session);
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
            "search_set_and_owner_transitions",
            Producer::Fe11Local,
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

fn verify_closed_scope(
    module: &Module,
    config: &Configuration,
    case: &Case,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let token = select_token(module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
    let session = module.select(&token)?.open_session(true)?;
    let result = (|| -> std::result::Result<(), Failure> {
        let template = case.template();
        let batch = std::num::NonZeroUsize::new(2).ok_or(Failure::Input("search_batch"))?;
        let mut iterator = session.iter_native_objects(&template, case.limits(), batch)?;
        let observed = match iterator.next() {
            None => Ok(()),
            Some(Err(error)) => Err(error.into()),
            Some(Ok(_)) => Err(Failure::Oracle("closed_session_objects_remain")),
        };
        if let Err(error) = iterator.finish() {
            cleanup.push(error.into());
        }
        observed
    })();
    if let Err(error) = session.close() {
        cleanup.push(error.into());
    }
    result
}
