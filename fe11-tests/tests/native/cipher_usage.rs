// SPDX-License-Identifier: Apache-2.0
//! One disabled usage, with all key bytes and cipher parameters kept valid.
use super::{
    cipher_vector,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
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
    let setup = (|| -> std::result::Result<_, Failure> {
        let vector = cipher_vector::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let session = owner.as_ref().ok_or(Failure::Input("cipher_owner"))?;
        key = Some(session.import_secret_usages(
            &vector.key,
            vector.key_type,
            [
                (StandardAttribute::ENCRYPT, !vector.encrypt),
                (StandardAttribute::DECRYPT, vector.encrypt),
            ],
        )?);
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            (|| -> std::result::Result<(), Failure> {
                let owner = owner.as_ref().ok_or(Failure::Input("cipher_owner"))?;
                let key = key.as_ref().ok_or(Failure::Input("cipher_key"))?;
                let input = [vector.input.as_slice()];
                let limits = InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: vector.input.len(),
                };
                let (result, function) = if vector.encrypt {
                    (
                        owner
                            .encrypt(key, vector.parameters, MessageRoute::Single, &input, limits)
                            .map(|_| ()),
                        "C_EncryptInit",
                    )
                } else {
                    (
                        owner
                            .decrypt(key, vector.parameters, MessageRoute::Single, &input, limits)
                            .map(|_| ()),
                        "C_DecryptInit",
                    )
                };
                match result {
                    Err(error @ Error::Native { .. }) if matches!(&error, Error::Native { function: actual, code, .. } if *actual == function && *code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64) => {
                        outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))
                    }
                    Err(error) => Err(error.into()),
                    Ok(()) => Err(Failure::Oracle("disabled_cipher_usage_accepted")),
                }
            })(),
        ),
    };
    let mut cleanup = owner
        .as_ref()
        .map(|o| o.close(key.as_ref()))
        .unwrap_or_default();
    drop(key);
    drop(owner);
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
