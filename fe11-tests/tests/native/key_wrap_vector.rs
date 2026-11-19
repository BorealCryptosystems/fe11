// SPDX-License-Identifier: Apache-2.0
//! Isolated key-wrap cases with separate setup, body and cleanup verdicts.
use super::{
    configuration::Configuration,
    key_wrap_fixture::{self as fixture, Vector},
    key_wrap_operation,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
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
    controlled: bool,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut target = None;
    let mut body_cleanup = Vec::new();
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = Vector::read(path)?;
        if controlled && (!vector.unwrap || vector.valid) {
            return Err(Failure::Input("controlled_unwrap_requires_negative"));
        }
        owner = Some(Owner::open(&module, config, vector.advanced)?);
        let active = owner.as_ref().ok_or(Failure::Input("wrap_owner"))?;
        key = Some(active.import_secret(
            &vector.kek,
            fe11_sys::CKK_AES,
            [StandardAttribute::WRAP, StandardAttribute::UNWRAP],
        )?);
        if !vector.unwrap || controlled {
            target = Some(fixture::import_target_checked(
                active,
                if controlled {
                    &[0x5a; 16]
                } else {
                    &vector.plaintext
                },
                vector.check.as_deref(),
            )?);
        }
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => key_wrap_operation::check(
                    owner,
                    key,
                    target.as_ref(),
                    &vector,
                    controlled,
                    &mut report,
                    &mut body_cleanup,
                ),
                _ => Err(Failure::Input("cipher_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = body_cleanup;
    if let (Some(owner), Some(target)) = (&owner, &target) {
        if let Err(error) = fixture::destroy(owner, target) {
            cleanup.push(error.into());
        }
    }
    cleanup.extend(
        owner
            .as_ref()
            .map_or_else(Vec::new, |owner| owner.close(key.as_ref())),
    );
    drop(target);
    drop(key);
    drop(owner);
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
            "published_key_wrap_verdict",
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
