// SPDX-License-Identifier: Apache-2.0
//! OAEP encryption of public fixtures; the supervisor independently decodes RSA.
use super::{
    configuration::Configuration,
    oaep_fixture::Vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

fn check(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: vector.plaintext.len(),
    };
    let result = match owner {
        Owner::Session(session) => session.encrypt_native_rsa(
            key,
            vector.parameters(),
            &vector.plaintext,
            vector.key[0].len(),
            limits,
        ),
        Owner::Advanced(session) => session.encrypt_native_rsa(
            key,
            vector.parameters(),
            &vector.plaintext,
            vector.key[0].len(),
            limits,
        ),
    }?;
    if result.as_bytes().len() != vector.key[0].len() || result.as_bytes().len() > 2048 {
        return Err(Failure::Oracle("rsa_ciphertext_width"));
    }
    // Only ciphertext from public known test keys/messages goes to this bounded
    // sidecar. Credentials and arbitrary buffers never enter the report stream.
    // The supervisor supplies a fresh private working directory for every case.
    // create_new also refuses an existing file or symlink at the fixed name.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open("public-rsa-ciphertext.bin")
        .map_err(|_| Failure::Input("reference_output_create"))?;
    file.write_all(result.as_bytes())
        .map_err(|_| Failure::Input("reference_output_write"))?;
    file.flush()
        .map_err(|_| Failure::Input("reference_output_flush"))?;
    Ok(())
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
        if !vector.valid {
            return Err(Failure::Input("encryption_requires_valid_fixture"));
        }
        key = Some(
            owner
                .as_ref()
                .ok_or(Failure::Input("cipher_owner"))?
                .import_rsa_public_usage(
                    &vector.key[0],
                    &vector.key[1],
                    StandardAttribute::ENCRYPT,
                )?,
        );
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => check(owner, key, &vector),
                _ => Err(Failure::Input("cipher_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |owner| owner.close(key.as_ref()));
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
            "oaep_ciphertext_ready_for_independent_reference",
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
