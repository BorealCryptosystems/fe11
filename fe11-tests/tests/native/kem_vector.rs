// SPDX-License-Identifier: Apache-2.0
//! Decapsulation retains created-key ownership through assertions and cleanup.
use super::{
    configuration::Configuration,
    kem_fixture::Vector,
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
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut derived = None;
    let mut observed_refusal = None;
    let mut length_negative = false;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = Vector::read(path)?;
        length_negative = vector.length_negative;
        owner = Some(Owner::open(&module, config, vector.advanced)?);
        let owner = owner.as_ref().ok_or(Failure::Input("single_key_owner"))?;
        key = Some(vector.import(owner)?);
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => {
                    vector.check(owner, key, &mut derived, &mut observed_refusal)
                }
                _ => Err(Failure::Input("single_key_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let (Some(owner), Some(objects)) = (&owner, &derived) {
        for object in objects.as_slice() {
            let result = match owner {
                Owner::Session(session) => session.destroy_native_object(object),
                Owner::Advanced(session) => session.destroy_native_object(object),
            };
            if let Err(error) = result {
                cleanup.push(error.into());
            }
        }
    }
    drop(derived);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(key.as_ref()));
    }
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
    if let Some(error) = observed_refusal {
        outcome::record(&mut report, Phase::Body, &Failure::Product(error))?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            if length_negative {
                "kem_ciphertext_length_refusal"
            } else {
                "published_kem_shared_secret"
            },
            if length_negative {
                Producer::TestOracle
            } else {
                Producer::PublishedVector
            },
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
