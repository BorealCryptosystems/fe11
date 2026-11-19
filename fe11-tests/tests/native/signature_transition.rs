// SPDX-License-Identifier: Apache-2.0
//! Signature continuation cases keep setup, action and cleanup independent.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    outcome,
    report::{Observation, Phase, PhaseResult, Producer, Report},
    signature_transition_action,
    signature_transition_fixture::{Case, Fixture},
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
    let mut fixture = Fixture::empty();
    let setup = Case::read(path).and_then(|case| {
        fixture.prepare(&module, config, pins, &case)?;
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            signature_transition_action::execute(&mut fixture, &case, config, &mut report),
        ),
    };
    let mut cleanup = fixture.cleanup();
    if let Err(error) = fixture.verify_owned() {
        cleanup.push(error);
    }
    if let Err(error) = fixture.write_reference_output() {
        cleanup.push(error);
    }
    drop(fixture);
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
            "signature_transition_and_owned_output",
            Producer::PublishedVector,
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
