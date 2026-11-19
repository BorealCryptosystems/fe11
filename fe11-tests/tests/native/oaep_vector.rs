// SPDX-License-Identifier: Apache-2.0
//! Exact published OAEP decryptions, with native failures kept observable.
use super::{
    configuration::Configuration,
    oaep_fixture::Vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

#[path = "oaep_contract.rs"]
mod contract;

fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    if vector.contract.is_some() {
        return contract::check(owner, key, vector, report, cleanup);
    }
    match vector.decrypt(owner, key) {
        Ok(result) if vector.valid => {
            if result.as_bytes() != vector.plaintext {
                return Err(Failure::Oracle("oaep_plaintext_bytes"));
            }
            Ok(())
        }
        Ok(_) => Err(Failure::Oracle("invalid_oaep_accepted")),
        Err(
            error @ Error::Native {
                function: "C_Decrypt",
                code,
                ..
            },
        ) if !vector.valid
            && (code == fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64
                || code == fe11_sys::CKR_ENCRYPTED_DATA_LEN_RANGE as u64) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = Vector::read(path)?;
        owner = Some(Owner::open(&module, config, vector.advanced)?);
        key = Some(vector.import(owner.as_ref().ok_or(Failure::Input("cipher_owner"))?)?);
        Ok(vector)
    })();
    let constructed = setup.as_ref().is_ok_and(|vector| vector.contract.is_some());
    let started = setup.is_ok();
    let mut control_cleanup = Vec::new();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => {
                    check(owner, key, &vector, &mut report, &mut control_cleanup)
                }
                _ => Err(Failure::Input("cipher_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |owner| owner.close(key.as_ref()));
    cleanup.append(&mut control_cleanup);
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
            "published_oaep_decryption_verdict",
            if constructed {
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
