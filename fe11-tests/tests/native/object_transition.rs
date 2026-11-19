// SPDX-License-Identifier: Apache-2.0
//! Bounded object lifecycle cases with separately reported setup and cleanup.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    object_lifetime, object_transition_action,
    object_transition_fixture::{Case, Fixture},
    outcome,
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::Module;
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
    let mut fixture = Fixture::empty(config.label.as_bytes());
    let setup = Case::read(path).and_then(|case| {
        fixture.prepare(&module, config, pins, &case)?;
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            if matches!(
                case.action.as_str(),
                "mutate_label" | "destroy_again" | "logout" | "close_last" | "shared_login"
            ) {
                object_lifetime::execute(&mut fixture, &module, config, &case, pins)
            } else {
                object_transition_action::execute(&mut fixture, &module, &case, pins, &mut report)
            },
        ),
    };
    let mut cleanup = fixture.cleanup(pins);
    if !fixture.module_closed {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    // Runtime-retirement cases intentionally retain the old owners through the
    // action. Isolated token-directory removal belongs to the supervisor.
    drop(fixture);
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
            "object_lifetime_and_exact_result",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup.is_ok() {
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
