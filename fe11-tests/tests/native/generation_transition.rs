// SPDX-License-Identifier: Apache-2.0
//! Keep generation setup, action, independent observations and cleanup distinct.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    generation_transition_action,
    generation_transition_fixture::{Case, Fixture},
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
    let setup_generations = fixture.generation_returns.len();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => {
            if case.route == "typed_generate_montgomery_key" && case.state == "REFUSED_TERMINAL" {
                // Preparation already checked the cancelled admission and its
                // zero native-call delta. Keep that observation if the next
                // generation fails because its mechanism is unavailable.
                report.observation(
                    Phase::Body,
                    "cancelled_generation_local_refusal",
                    Producer::TestOracle,
                    Observation::Boolean(true),
                )?;
            }
            (
                Ok(()),
                generation_transition_action::execute(
                    &mut fixture,
                    &module,
                    &case,
                    config,
                    &mut report,
                ),
            )
        }
    };
    let mut cleanup = fixture.cleanup(&config.label);
    if fixture.observes_pair_return() {
        for (index, code) in fixture.generation_returns.iter().enumerate() {
            let phase = if index < setup_generations {
                Phase::Setup
            } else {
                Phase::Body
            };
            report.observation(
                phase,
                "keypair_native_return",
                Producer::Native,
                Observation::Number(*code),
            )?;
        }
        for (name, count) in [
            ("keypair_namespace_objects", fixture.inventory_count),
            ("keypair_namespace_remaining", fixture.remaining_count),
        ] {
            if let Some(count) = count {
                report.observation(
                    Phase::Cleanup,
                    name,
                    Producer::TestOracle,
                    Observation::Number(count as u64),
                )?;
            }
        }
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
            "generation_transition_and_native_ownership",
            Producer::TestOracle,
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
