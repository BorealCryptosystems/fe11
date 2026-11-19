// SPDX-License-Identifier: Apache-2.0
//! Exact published ECDSA signatures, with raw digests distinguished from messages.
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
    lengths: Vec<usize>,
    parameters: Vec<u8>,
    point: Vec<u8>,
    input: Vec<u8>,
    signature: Vec<u8>,
    other_curve_point: Option<Vec<u8>>,
    exact_invalid_point: bool,
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
    if !matches!(fields.len(), 8 | 9 | 10) {
        return Err(Failure::Input("vector_fields"));
    }
    let algorithm = match fields[0] {
        "CKM_ECDSA" => NativeSignatureAlgorithm::ECDSA,
        "CKM_ECDSA_SHA224" => NativeSignatureAlgorithm::ECDSA_SHA224,
        "CKM_ECDSA_SHA256" => NativeSignatureAlgorithm::ECDSA_SHA256,
        "CKM_ECDSA_SHA384" => NativeSignatureAlgorithm::ECDSA_SHA384,
        "CKM_ECDSA_SHA512" => NativeSignatureAlgorithm::ECDSA_SHA512,
        "CKM_ECDSA_SHA3_224" => NativeSignatureAlgorithm::ECDSA_SHA3_224,
        "CKM_ECDSA_SHA3_256" => NativeSignatureAlgorithm::ECDSA_SHA3_256,
        "CKM_ECDSA_SHA3_384" => NativeSignatureAlgorithm::ECDSA_SHA3_384,
        "CKM_ECDSA_SHA3_512" => NativeSignatureAlgorithm::ECDSA_SHA3_512,
        _ => return Err(Failure::Input("ecdsa_algorithm")),
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
    let signature = hex(fields[7], 144).map_err(Failure::Input)?;
    if signature.is_empty() || signature.len() % 2 != 0 {
        return Err(Failure::Input("signature_width"));
    }
    let other_curve_point = if fields.len() >= 9 {
        if fields[0] != "CKM_ECDSA" || !valid {
            return Err(Failure::Input("wrong_curve_requires_raw_positive_control"));
        }
        Some(hex(fields[8], 160).map_err(Failure::Input)?)
    } else {
        None
    };
    let exact_invalid_point = fields.len() == 10;
    if exact_invalid_point && fields[9] != "verify-signature-invalid" {
        return Err(Failure::Input("invalid_point_oracle"));
    }
    Ok(Vector {
        algorithm,
        multipart: fields[0] != "CKM_ECDSA",
        advanced,
        valid,
        lengths,
        // ECParameters may be a named OID or a complete explicit domain.
        // Keep a bounded fixture size without assuming the short OID encoding.
        parameters: hex(fields[4], 4096).map_err(Failure::Input)?,
        point: hex(fields[5], 160).map_err(Failure::Input)?,
        input,
        signature,
        other_curve_point,
        exact_invalid_point,
    })
}

fn wrong_curve<W: Write>(
    owner: &Owner,
    vector: &Vector,
    retained: &mut Option<NativeObjectRef>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let Some(point) = &vector.other_curve_point else {
        return Ok(());
    };
    // The valid key and signature have already been checked. Only the public
    // point is replaced. Its outer DER OCTET STRING remains well formed;
    // the enclosed SEC1 point may deliberately be invalid.
    let result = match owner.import_ec_public(&vector.parameters, point) {
        Ok(key) => {
            *retained = Some(key);
            owner.verify_signature(
                retained
                    .as_ref()
                    .ok_or(Failure::Input("wrong_curve_owner"))?,
                vector.algorithm,
                MessageRoute::Single,
                &[&vector.input],
                &vector.signature,
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: vector.input.len(),
                },
            )
        }
        Err(error) => Err(error),
    };
    fn rejection(error: &Error) -> Option<u64> {
        match error {
            Error::ObjectsMayRemain(cause) => rejection(cause),
            Error::Native {
                function: "C_CreateObject",
                code,
                ..
            } if *code == fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID as u64 => Some(1),
            Error::Native {
                function: "C_VerifyInit",
                code,
                ..
            } if *code == fe11_sys::CKR_KEY_TYPE_INCONSISTENT as u64 => Some(2),
            Error::Native {
                function: "C_Verify",
                code,
                ..
            } if *code == fe11_sys::CKR_SIGNATURE_INVALID as u64 => Some(3),
            _ => None,
        }
    }
    match result {
        Err(error)
            if rejection(&error).is_some()
                && (!vector.exact_invalid_point || rejection(&error) == Some(3)) =>
        {
            report
                .observation(
                    Phase::Body,
                    "wrong_curve_rejection_stage",
                    Producer::Native,
                    Observation::Number(
                        rejection(&error).ok_or(Failure::Input("wrong_curve_stage"))?,
                    ),
                )
                .map_err(|_| Failure::Input("wrong_curve_report"))?;
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("wrong_curve_report"))
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("other_curve_point_signature_accepted")),
    }
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
    let mut other_curve_key = None;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = read(path)?;
        owner = Some(Owner::open(&module, config, vector.advanced)?);
        key = Some(
            owner
                .as_ref()
                .ok_or(Failure::Input("signature_owner"))?
                .import_ec_public(&vector.parameters, &vector.point)?,
        );
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => check(owner, key, &vector, &mut report)
                    .and_then(|()| wrong_curve(owner, &vector, &mut other_curve_key, &mut report)),
                _ => Err(Failure::Input("signature_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let (Some(owner), Some(key)) = (&owner, &other_curve_key) {
        let result = match owner {
            Owner::Session(s) => s.destroy_native_object(key),
            Owner::Advanced(s) => s.destroy_native_object(key),
        };
        if let Err(error) = result {
            cleanup.push(error.into());
        }
    }
    cleanup.extend(
        owner
            .as_ref()
            .map_or_else(Vec::new, |owner| owner.close(key.as_ref())),
    );
    drop(other_curve_key);
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
            "published_ecdsa_verdict",
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
