// SPDX-License-Identifier: Apache-2.0
//! RSA hash/MGF domains, with native producers and independent output verification.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use super::rsa_parameters::{hash, Hash};

struct Vector {
    pss: bool,
    hash: Hash,
    mgf: Hash,
    salt: u64,
    valid: bool,
    key: Vec<Vec<u8>>,
    message: Vec<u8>,
    prehash: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Vector, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("vector_open"))?
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("vector_read"))?;
    if bytes.len() > 32768 {
        return Err(Failure::Input("vector_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 15
        || !matches!(fields[0], "pss" | "oaep")
        || !matches!(fields[4], "valid" | "oversize")
    {
        return Err(Failure::Input("rsa_domain_fields"));
    }
    let key = fields[5..13]
        .iter()
        .map(|v| hex(v, 1024).map_err(Failure::Input))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if key.iter().any(Vec::is_empty) || key[0].len() != 256 {
        return Err(Failure::Input("rsa_domain_key"));
    }
    let mgf = hash(fields[2])?;
    let hash = hash(fields[1])?;
    let prehash = hex(fields[14], 64).map_err(Failure::Input)?;
    if prehash.len() != hash.bytes {
        return Err(Failure::Input("rsa_domain_digest"));
    }
    Ok(Vector {
        pss: fields[0] == "pss",
        hash,
        mgf,
        salt: fields[3]
            .parse()
            .map_err(|_| Failure::Input("rsa_domain_salt"))?,
        valid: fields[4] == "valid",
        key,
        message: hex(fields[13], 256).map_err(Failure::Input)?,
        prehash,
    })
}

fn check_result<W: Write>(
    result: Result<Vec<u8>>,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<Option<Vec<u8>>, Failure> {
    match result {
        Ok(bytes) if vector.valid && bytes.len() == 256 => Ok(Some(bytes)),
        Ok(_) => Err(Failure::Oracle("rsa_domain_unexpected_output")),
        Err(error @ Error::Native { function, code, .. }) if !vector.valid => {
            let accepted = if vector.pss {
                matches!(function, "C_SignInit" | "C_Sign" | "C_SignFinal")
                    && [
                        fe11_sys::CKR_MECHANISM_PARAM_INVALID,
                        fe11_sys::CKR_DATA_LEN_RANGE,
                        fe11_sys::CKR_FUNCTION_FAILED,
                        // A generic native refusal is permitted too. Preserve
                        // its code and effect flag; it proves no signature was
                        // returned, not why the module rejected the request.
                        fe11_sys::CKR_GENERAL_ERROR,
                    ]
                    .iter()
                    .any(|v| *v as u64 == code)
            } else {
                function == "C_Encrypt" && code == fe11_sys::CKR_DATA_LEN_RANGE as u64
            };
            if !accepted {
                return Err(error.into());
            }
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn body<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut outputs = Vec::new();
    if vector.pss {
        for (algorithm, input) in [
            (NativePssAlgorithm::RSA_PKCS_PSS, vector.prehash.as_slice()),
            (vector.hash.combined, vector.message.as_slice()),
        ] {
            let parameters = NativeSignatureParameters::RsaPss {
                algorithm,
                hash: vector.hash.number,
                mgf: vector.mgf.mgf,
                salt_bytes: vector.salt,
            };
            let limits = InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: input.len(),
            };
            let result = match owner {
                Owner::Session(s) => s.sign_native(
                    key,
                    parameters,
                    MessageRoute::Single,
                    &[input],
                    limits,
                    256,
                    None,
                ),
                Owner::Advanced(s) => s.sign_native(
                    key,
                    parameters,
                    MessageRoute::Single,
                    &[input],
                    limits,
                    256,
                    None,
                ),
            }
            .map(|v| v.as_bytes().to_vec());
            if let Some(bytes) = check_result(result, vector, report)? {
                outputs.extend(bytes);
            }
        }
    } else {
        let parameters = NativeRsaCipherParameters::Oaep(NativeOaepParameters {
            hash: vector.hash.number,
            mgf: vector.mgf.mgf,
            source: fe11_sys::CKZ_DATA_SPECIFIED as u64,
            data: None,
        });
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: vector.message.len(),
        };
        let result = match owner {
            Owner::Session(s) => {
                s.encrypt_native_rsa(key, parameters, &vector.message, 256, limits)
            }
            Owner::Advanced(s) => {
                s.encrypt_native_rsa(key, parameters, &vector.message, 256, limits)
            }
        }
        .map(|v| v.as_bytes().to_vec());
        if let Some(bytes) = check_result(result, vector, report)? {
            outputs.extend(bytes);
        }
    }
    if vector.valid {
        if outputs.len() != if vector.pss { 512 } else { 256 } {
            return Err(Failure::Oracle("rsa_domain_output_count"));
        }
        // Only signatures/ciphertext from the public test key cross this boundary.
        // The supervisor verifies each output independently before case PASS.
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open("public-rsa-domain.bin")
            .map_err(|_| Failure::Input("reference_output_create"))?;
        file.write_all(&outputs)
            .map_err(|_| Failure::Input("reference_output_write"))?;
        file.flush()
            .map_err(|_| Failure::Input("reference_output_flush"))?;
    }
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
        let vector = read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let active = owner.as_ref().ok_or(Failure::Input("rsa_domain_owner"))?;
        key = Some(if vector.pss {
            active.import_rsa_private(&vector.key, StandardAttribute::SIGN)?
        } else {
            active.import_rsa_public_usage(
                &vector.key[0],
                &vector.key[1],
                StandardAttribute::ENCRYPT,
            )?
        });
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, result) = match setup {
        Err(e) => (Err(e), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(o), Some(k)) => body(o, k, &vector, &mut report),
                _ => Err(Failure::Input("rsa_domain_owner")),
            },
        ),
    };
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |o| o.close(key.as_ref()));
    drop(key);
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    if let Err(e) = &setup_result {
        outcome::record(&mut report, Phase::Setup, e)?;
    }
    if let Err(e) = &result {
        outcome::record(&mut report, Phase::Body, e)?;
    }
    for e in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, e)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "rsa_domain_native_result",
            Producer::Fe11Local,
            Observation::Boolean(result.is_ok()),
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
        } else if result.is_ok() {
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
