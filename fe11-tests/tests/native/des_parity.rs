// SPDX-License-Identifier: Apache-2.0
//! Preserve invalid DES parity bits and the module's actual import result.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut created = None;
    let setup = (|| -> std::result::Result<Vec<u8>, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(18)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() != 17 || data[16] != b'\n' {
            return Err(Failure::Input("parity_fixture_size"));
        }
        let text =
            std::str::from_utf8(&data[..16]).map_err(|_| Failure::Input("fixture_encoding"))?;
        let key = hex(text, 8).map_err(Failure::Input)?;
        if key.len() != 8 || key.iter().all(|byte| byte.count_ones() % 2 == 1) {
            return Err(Failure::Input("parity_fixture_not_invalid"));
        }
        owner = Some(Owner::open(&module, config, false)?);
        Ok(key)
    })();
    let started = setup.is_ok();
    let (setup, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(key) => (
            Ok(()),
            (|| -> std::result::Result<(), Failure> {
                let session = owner.as_ref().ok_or(Failure::Input("parity_owner"))?;
                match session.import_secret(
                    &key,
                    fe11_sys::CKK_DES,
                    [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
                ) {
                    Err(error @ Error::Native { .. }) if matches!(&error,Error::Native{function:"C_CreateObject",code,..} if [fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID,fe11_sys::CKR_TEMPLATE_INCONSISTENT,fe11_sys::CKR_FUNCTION_FAILED,fe11_sys::CKR_GENERAL_ERROR].iter().any(|allowed| *allowed as u64==*code)) => {
                        outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))
                    }
                    Err(error) => Err(error.into()),
                    Ok(object) => {
                        // A surprising success still returns an owner that must be
                        // destroyed. Never repair parity to obtain a passing import.
                        created = Some(object);
                        Err(Failure::Oracle("invalid_des_parity_accepted"))
                    }
                }
            })(),
        ),
    };
    let mut cleanup = owner
        .as_ref()
        .map(|o| o.close(created.as_ref()))
        .unwrap_or_default();
    drop(created);
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
