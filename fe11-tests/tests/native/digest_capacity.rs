// SPDX-License-Identifier: Apache-2.0
//! Capacity-retained digests preserve exact input and an explicitly selected output.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    digest_capacity_action,
    digest_capacity_fixture::{Case, Fixture},
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
    let mut fixture = Fixture::empty();
    let setup = Case::read(path).and_then(|case| {
        fixture.prepare(&module, config, pins, &case)?;
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup_result, body) = match &setup {
        Err(_) => (false, Ok(())),
        Ok(case) => (
            true,
            digest_capacity_action::execute(&mut fixture, &module, case, config, pins, &mut report),
        ),
    };
    let mut cleanup = fixture.cleanup();
    if let Ok(case) = &setup {
        if fixture.output.is_some() {
            if let Err(error) = fixture.verify(case) {
                cleanup.push(error);
            }
        }
    }
    drop(fixture);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
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
            "retained_digest_exact_input_and_output",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup_result {
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
