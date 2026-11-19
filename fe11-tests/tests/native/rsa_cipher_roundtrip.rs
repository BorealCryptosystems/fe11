// SPDX-License-Identifier: Apache-2.0
//! Feed the actual randomized RSA ciphertext into native decryption.
use super::super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

const PREFIX: &[u8] = b"rsa-roundtrip\n";

pub(super) fn selected(path: &Path) -> bool {
    let mut bytes = [0; PREFIX.len()];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_ok()
        && bytes.as_slice() == PREFIX
}

struct Case {
    advanced: bool,
    key: Vec<Vec<u8>>,
    plaintext: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("rsa_roundtrip_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("rsa_roundtrip_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("rsa_roundtrip_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("rsa_roundtrip_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 11
            || fields[0] != "rsa-roundtrip"
            || !matches!(fields[1], "session" | "advanced")
        {
            return Err(Failure::Input("rsa_roundtrip_fields"));
        }
        let key = fields[2..10]
            .iter()
            .map(|v| hex(v, 256).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let plaintext = hex(fields[10], 245).map_err(Failure::Input)?;
        if key.iter().any(Vec::is_empty)
            || key[0].len() != 256
            || !matches!(plaintext.len(), 0 | 1 | 245)
        {
            return Err(Failure::Input("rsa_roundtrip_dimensions"));
        }
        Ok(Self {
            advanced: fields[1] == "advanced",
            key,
            plaintext,
        })
    }
}

fn check(owner: &Owner, keys: &[NativeObjectRef], case: &Case) -> std::result::Result<(), Failure> {
    if keys.len() != 2 {
        return Err(Failure::Input("rsa_roundtrip_owners"));
    }
    let input = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: case.plaintext.len(),
    };
    let ciphertext = match owner {
        Owner::Session(session) => session.encrypt_native_rsa(
            &keys[0],
            NativeRsaCipherParameters::Pkcs1v15,
            &case.plaintext,
            256,
            input,
        ),
        Owner::Advanced(session) => session.encrypt_native_rsa(
            &keys[0],
            NativeRsaCipherParameters::Pkcs1v15,
            &case.plaintext,
            256,
            input,
        ),
    }?;
    if ciphertext.as_bytes().len() != 256 {
        return Err(Failure::Oracle("rsa_roundtrip_ciphertext_width"));
    }
    let input = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 256,
    };
    let plaintext = match owner {
        Owner::Session(session) => session.decrypt_native_rsa(
            &keys[1],
            NativeRsaCipherParameters::Pkcs1v15,
            ciphertext.as_bytes(),
            256,
            input,
            None,
        ),
        Owner::Advanced(session) => session.decrypt_native_rsa(
            &keys[1],
            NativeRsaCipherParameters::Pkcs1v15,
            ciphertext.as_bytes(),
            256,
            input,
            None,
        ),
    }?;
    if plaintext.as_bytes() != case.plaintext.as_slice() {
        return Err(Failure::Oracle("rsa_roundtrip_plaintext"));
    }
    Ok(())
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut keys = Vec::new();
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, case.advanced)?);
        let selected = owner
            .as_ref()
            .ok_or(Failure::Input("rsa_roundtrip_owner"))?;
        // Retain each object immediately, including when the second import fails.
        keys.push(selected.import_rsa_public_usage(
            &case.key[0],
            &case.key[1],
            StandardAttribute::ENCRYPT,
        )?);
        keys.push(selected.import_rsa_private(&case.key, StandardAttribute::DECRYPT)?);
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match owner.as_ref() {
                Some(owner) => check(owner, &keys, &case),
                None => Err(Failure::Input("rsa_roundtrip_missing_owner")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(owner) = &owner {
        for key in &keys {
            let result = match owner {
                Owner::Session(session) => session.destroy_native_object(key),
                Owner::Advanced(session) => session.destroy_native_object(key),
            };
            if let Err(error) = result {
                cleanup.push(Failure::from(error));
            }
        }
        cleanup.extend(owner.close(None));
    }
    drop(keys);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    // Reporting follows cleanup so a broken output stream cannot skip ownership release.
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
            "rsa_actual_ciphertext_roundtrip",
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
