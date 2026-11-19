// SPDX-License-Identifier: Apache-2.0
//! Published RSA signatures with explicit padding, prehash and PSS parameters.
use super::{
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

enum Algorithm {
    Parameterless(NativeSignatureAlgorithm),
    Pss {
        algorithm: NativePssAlgorithm,
        hash: u64,
        mgf: u64,
        salt_bytes: u64,
    },
}

impl Algorithm {
    fn parameters(&self) -> NativeSignatureParameters<'_> {
        match *self {
            Self::Parameterless(algorithm) => NativeSignatureParameters::Parameterless(algorithm),
            Self::Pss {
                algorithm,
                hash,
                mgf,
                salt_bytes,
            } => NativeSignatureParameters::RsaPss {
                algorithm,
                hash,
                mgf,
                salt_bytes,
            },
        }
    }
}

struct Vector {
    algorithm: Algorithm,
    multipart: bool,
    advanced: bool,
    valid: bool,
    lengths: Vec<usize>,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
    input: Vec<u8>,
    signature: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Vector, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("vector_open"))?
        .take(1048577)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("vector_read"))?;
    if bytes.len() > 1048576 {
        return Err(Failure::Input("vector_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 11 {
        return Err(Failure::Input("vector_fields"));
    }
    let pss = fields[0].ends_with("_PSS");
    let algorithm = if pss {
        let algorithm = match fields[0] {
            "CKM_RSA_PKCS_PSS" => NativePssAlgorithm::RSA_PKCS_PSS,
            "CKM_SHA256_RSA_PKCS_PSS" => NativePssAlgorithm::SHA256_RSA_PKCS_PSS,
            "CKM_SHA3_256_RSA_PKCS_PSS" => NativePssAlgorithm::SHA3_256_RSA_PKCS_PSS,
            _ => return Err(Failure::Input("rsa_pss_algorithm")),
        };
        let (hash, mgf) = match (fields[8], fields[9]) {
            ("SHA2-256", "mgf1") => (fe11_sys::CKM_SHA256, fe11_sys::CKG_MGF1_SHA256),
            ("SHA3-256", "mgf1") => (fe11_sys::CKM_SHA3_256, fe11_sys::CKG_MGF1_SHA3_256),
            _ => return Err(Failure::Input("rsa_pss_hash_mask")),
        };
        let salt_bytes = fields[10]
            .parse()
            .map_err(|_| Failure::Input("pss_salt_length"))?;
        Algorithm::Pss {
            algorithm,
            hash: hash as u64,
            mgf: mgf as u64,
            salt_bytes,
        }
    } else {
        if fields[8..] != ["-", "-", "0"] {
            return Err(Failure::Input("unexpected_rsa_parameters"));
        }
        Algorithm::Parameterless(match fields[0] {
            "CKM_RSA_PKCS" => NativeSignatureAlgorithm::RSA_PKCS,
            "CKM_SHA256_RSA_PKCS" => NativeSignatureAlgorithm::SHA256_RSA_PKCS,
            "CKM_SHA3_512_RSA_PKCS" => NativeSignatureAlgorithm::SHA3_512_RSA_PKCS,
            _ => return Err(Failure::Input("rsa_algorithm")),
        })
    };
    let advanced = match fields[1] {
        "session" => false,
        "advanced" => true,
        _ => return Err(Failure::Input("signature_owner")),
    };
    let valid = match fields[2] {
        "valid" => true,
        "invalid" => false,
        _ => return Err(Failure::Input("signature_oracle")),
    };
    let lengths: Vec<usize> = fields[3]
        .split(',')
        .map(|p| p.parse().map_err(|_| Failure::Input("part_length")))
        .collect::<std::result::Result<_, _>>()?;
    let input = hex(fields[6], 262144).map_err(Failure::Input)?;
    let total = lengths
        .iter()
        .try_fold(0usize, |sum, n| sum.checked_add(*n));
    if lengths.is_empty() || lengths.len() > 1024 || total != Some(input.len()) {
        return Err(Failure::Input("part_dimensions"));
    }
    let signature = hex(fields[7], 65536).map_err(Failure::Input)?;
    if valid && signature.is_empty() {
        return Err(Failure::Input("signature_width"));
    }
    Ok(Vector {
        algorithm,
        multipart: !matches!(fields[0], "CKM_RSA_PKCS" | "CKM_RSA_PKCS_PSS"),
        advanced,
        valid,
        lengths,
        modulus: hex(fields[4], 65536).map_err(Failure::Input)?,
        exponent: hex(fields[5], 65536).map_err(Failure::Input)?,
        input,
        signature,
    })
}

fn invalid<W: Write>(
    result: Result<()>,
    function: &'static str,
    length_refusal_allowed: bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function
            && (code == fe11_sys::CKR_SIGNATURE_INVALID as u64
                || (length_refusal_allowed
                    && code == fe11_sys::CKR_SIGNATURE_LEN_RANGE as u64)) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("invalid_signature_accepted")),
    }
}

fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut offset = 0;
    let parts: Vec<_> = vector
        .lengths
        .iter()
        .map(|n| {
            let p = &vector.input[offset..offset + n];
            offset += n;
            p
        })
        .collect();
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: vector.input.len(),
    };
    let routes =
        &[MessageRoute::Single, MessageRoute::Multipart][..if vector.multipart { 2 } else { 1 }];
    for &route in routes {
        let function = if route == MessageRoute::Single {
            "C_Verify"
        } else {
            "C_VerifyFinal"
        };
        let result = owner.verify_parameters(
            key,
            vector.algorithm.parameters(),
            route,
            &parts,
            &vector.signature,
            limits,
        );
        if vector.valid {
            result?;
            let mut changed = vector.signature.clone();
            let last = changed
                .last_mut()
                .ok_or(Failure::Input("signature_width"))?;
            *last ^= 1;
            invalid(
                owner.verify_parameters(
                    key,
                    vector.algorithm.parameters(),
                    route,
                    &parts,
                    &changed,
                    limits,
                ),
                function,
                false,
                report,
            )?;
        } else {
            invalid(result, function, true, report)?;
        }
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
        owner = Some(Owner::open(&module, config, vector.advanced)?);
        key = Some(
            owner
                .as_ref()
                .ok_or(Failure::Input("signature_owner"))?
                .import_rsa_public(&vector.modulus, &vector.exponent)?,
        );
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => check(owner, key, &vector, &mut report),
                _ => Err(Failure::Input("signature_fixture_incomplete")),
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
            "published_rsa_verdict",
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
