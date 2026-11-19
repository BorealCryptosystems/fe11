// SPDX-License-Identifier: Apache-2.0
//! Published DSA signatures with explicit subprime widths and prehashed inputs.
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

struct Vector {
    algorithm: NativeSignatureAlgorithm,
    multipart: bool,
    advanced: bool,
    valid: bool,
    length_refusal_allowed: bool,
    lengths: Vec<usize>,
    prime: Vec<u8>,
    subprime: Vec<u8>,
    base: Vec<u8>,
    value: Vec<u8>,
    input: Vec<u8>,
    signature: Vec<u8>,
    mutation: Option<SignatureMutation>,
}

enum SignatureMutation {
    ZeroR,
    Short,
    Long,
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
    if fields.len() != 10 {
        return Err(Failure::Input("vector_fields"));
    }
    let algorithm = match fields[0] {
        "CKM_DSA" => NativeSignatureAlgorithm::DSA,
        "CKM_DSA_SHA1" => NativeSignatureAlgorithm::DSA_SHA1,
        "CKM_DSA_SHA224" => NativeSignatureAlgorithm::DSA_SHA224,
        "CKM_DSA_SHA256" => NativeSignatureAlgorithm::DSA_SHA256,
        "CKM_DSA_SHA384" => NativeSignatureAlgorithm::DSA_SHA384,
        "CKM_DSA_SHA512" => NativeSignatureAlgorithm::DSA_SHA512,
        _ => return Err(Failure::Input("dsa_algorithm")),
    };
    let advanced = match fields[1] {
        "session" => false,
        "advanced" => true,
        _ => return Err(Failure::Input("signature_owner")),
    };
    let valid = match fields[2] {
        "valid" | "zero-r" | "short-signature" | "long-signature" => true,
        "invalid" | "invalid-exact" => false,
        _ => return Err(Failure::Input("signature_oracle")),
    };
    let lengths: Vec<usize> = fields[3]
        .split(',')
        .map(|p| p.parse().map_err(|_| Failure::Input("part_length")))
        .collect::<std::result::Result<_, _>>()?;
    let input = hex(fields[8], 262144).map_err(Failure::Input)?;
    let total = lengths
        .iter()
        .try_fold(0usize, |sum, n| sum.checked_add(*n));
    if lengths.is_empty() || lengths.len() > 1024 || total != Some(input.len()) {
        return Err(Failure::Input("part_dimensions"));
    }
    let signature = hex(fields[9], 64).map_err(Failure::Input)?;
    let subprime = hex(fields[5], 32).map_err(Failure::Input)?;
    if !matches!(subprime.len(), 20 | 28 | 32) || signature.len() != 2 * subprime.len() {
        return Err(Failure::Input("signature_width"));
    }
    let mutation = match fields[2] {
        "zero-r" => Some(SignatureMutation::ZeroR),
        "short-signature" => Some(SignatureMutation::Short),
        "long-signature" => Some(SignatureMutation::Long),
        _ => None,
    };
    if mutation.is_some() && fields[0] != "CKM_DSA" {
        return Err(Failure::Input("raw_dsa_mutation_mechanism"));
    }
    Ok(Vector {
        algorithm,
        multipart: fields[0] != "CKM_DSA",
        advanced,
        valid,
        length_refusal_allowed: fields[2] == "invalid",
        lengths,
        prime: hex(fields[4], 384).map_err(Failure::Input)?,
        subprime,
        base: hex(fields[6], 384).map_err(Failure::Input)?,
        value: hex(fields[7], 384).map_err(Failure::Input)?,
        input,
        signature,
        mutation,
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
        // Single consumes one contiguous message; Multipart preserves every
        // caller-declared partition, including empty Update boundaries.
        let contiguous = [vector.input.as_slice()];
        let route_parts = if route == MessageRoute::Single {
            contiguous.as_slice()
        } else {
            parts.as_slice()
        };
        let function = if route == MessageRoute::Single {
            "C_Verify"
        } else {
            "C_VerifyFinal"
        };
        let result = owner.verify_signature(
            key,
            vector.algorithm,
            route,
            route_parts,
            &vector.signature,
            limits,
        );
        if vector.valid {
            result?;
            let mut changed = vector.signature.clone();
            if let Some(mutation) = &vector.mutation {
                let expected = match mutation {
                    SignatureMutation::ZeroR => {
                        changed[..vector.subprime.len()].fill(0);
                        fe11_sys::CKR_SIGNATURE_INVALID
                    }
                    SignatureMutation::Short => {
                        changed.pop();
                        fe11_sys::CKR_SIGNATURE_LEN_RANGE
                    }
                    SignatureMutation::Long => {
                        changed.push(0);
                        fe11_sys::CKR_SIGNATURE_LEN_RANGE
                    }
                };
                // The unchanged valid signature must already have verified on
                // this exact key/digest. Only the signature is now changed.
                match owner.verify_signature(
                    key,
                    vector.algorithm,
                    route,
                    route_parts,
                    &changed,
                    limits,
                ) {
                    Err(
                        error @ Error::Native {
                            function: actual,
                            code,
                            ..
                        },
                    ) if actual == function && code == expected as u64 => {
                        outcome::record(report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))?;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(()) => return Err(Failure::Oracle("dsa_signature_mutation_accepted")),
                }
                continue;
            }
            let last = changed
                .last_mut()
                .ok_or(Failure::Input("signature_width"))?;
            *last ^= 1;
            invalid(
                owner.verify_signature(key, vector.algorithm, route, route_parts, &changed, limits),
                function,
                false,
                report,
            )?;
        } else {
            invalid(result, function, vector.length_refusal_allowed, report)?;
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
                .import_dsa_public(&vector.prime, &vector.subprime, &vector.base, &vector.value)?,
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
            "published_dsa_verdict",
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
