// SPDX-License-Identifier: Apache-2.0
//! Canonical scalar encodings through real DSA and P-256 public references.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_fixture::{self, Fixture},
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
    kind: String,
    input: Vec<u8>,
    der: Vec<u8>,
    raw: Vec<u8>,
    dsa_spki: Option<Vec<u8>>,
}

impl Vector {
    fn encode(&self, key: &VerificationKey, raw: &[u8]) -> fe11::Result<Vec<u8>> {
        if self.dsa_spki.is_some() {
            key.dsa_signature_to_der(raw)
        } else {
            key.ecdsa_signature_to_der(raw)
        }
    }

    fn decode(&self, key: &VerificationKey, der: &[u8]) -> fe11::Result<Vec<u8>> {
        if self.dsa_spki.is_some() {
            key.dsa_signature_from_der(der)
        } else {
            key.ecdsa_signature_from_der(der)
        }
    }
}

fn read(path: &Path) -> std::result::Result<Vector, Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("vector_open"))?
        .take(8193)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("vector_read"))?;
    if data.len() > 8192 {
        return Err(Failure::Input("vector_size"));
    }
    let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("vector_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    let (fields, dsa_spki) = if fields.len() == 6 && fields[0] == "dsa-encoding" {
        (
            &fields[1..5],
            Some(hex(fields[5], 2048).map_err(Failure::Input)?),
        )
    } else {
        (fields.as_slice(), None)
    };
    if dsa_spki.is_none() && data.len() > 2048 {
        return Err(Failure::Input("vector_size"));
    }
    if fields.len() != 4 {
        return Err(Failure::Input("vector_fields"));
    }
    if !matches!(
        fields[0],
        "encode" | "raw-width" | "der-invalid" | "der-size" | "scalar-width"
    ) {
        return Err(Failure::Input("encoding_case"));
    }
    let raw = hex(fields[3], 64).map_err(Failure::Input)?;
    if dsa_spki.is_some() && !matches!(raw.len(), 40 | 56 | 64) {
        return Err(Failure::Input("dsa_encoding_fixture_width"));
    }
    Ok(Vector {
        kind: fields[0].to_owned(),
        input: hex(fields[1], 128).map_err(Failure::Input)?,
        der: hex(fields[2], 128).map_err(Failure::Input)?,
        raw,
        dsa_spki,
    })
}

fn check(key: &VerificationKey, vector: &Vector) -> std::result::Result<(), Failure> {
    let actual = if vector.kind == "encode" {
        let der = vector.encode(key, &vector.input)?;
        if der != vector.der || vector.decode(key, &der)? != vector.raw {
            return Err(Failure::Oracle("canonical_scalar_encoding"));
        }
        return Ok(());
    } else if vector.kind == "raw-width" {
        vector.encode(key, &vector.input)
    } else {
        vector.decode(key, &vector.input)
    };
    let expected = if vector.dsa_spki.is_some() {
        match vector.kind.as_str() {
            "raw-width" => ClassicalSignaturesRejection::DsaSignatureWidth,
            "der-invalid" => ClassicalSignaturesRejection::DsaSignatureDer,
            "scalar-width" => ClassicalSignaturesRejection::DsaScalarWidth,
            _ => return Err(Failure::Input("dsa_encoding_case")),
        }
    } else {
        match vector.kind.as_str() {
            "raw-width" => ClassicalSignaturesRejection::EcdsaSignatureWidth,
            "der-invalid" => ClassicalSignaturesRejection::EcdsaDer,
            "der-size" => ClassicalSignaturesRejection::EcdsaDerSize,
            "scalar-width" => ClassicalSignaturesRejection::EcdsaScalarWidth,
            _ => return Err(Failure::Input("encoding_case")),
        }
    };
    match actual {
        Err(Error::Rejected(RejectionReason::ClassicalSignatures(cause))) if cause == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("expected_encoding_refusal")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = None;
    let setup = (|| -> std::result::Result<(VerificationKey, Vector), Failure> {
        let vector = read(path)?;
        fixture = Some(Fixture::open(&module, config)?);
        let owner = fixture.as_mut().ok_or(Failure::Input("fixture_owner"))?;
        let spki = if let Some(spki) = &vector.dsa_spki {
            spki.clone()
        } else {
            hex(
                include_str!("../vectors/encoding/p256-spki.hex").trim(),
                256,
            )
            .map_err(Failure::Input)?
        };
        let profile = if vector.dsa_spki.is_some() {
            VerificationProfile::Historical(HistoricalProfile::Dsa(DsaVerificationHash::Sha256))
        } else {
            VerificationProfile::Ecdsa(HashAlgorithm::Sha256)
        };
        let created = owner.session.create_verification_key(
            &spki,
            &[profile],
            MechanismObservationPlan::NotRequested,
            object_fixture::public_key_options(config.label.as_bytes()),
        )?;
        Ok((owner.retain_public_key(created)?, vector))
    })();
    let mut setup_failures = Vec::new();
    let mut body_failures = Vec::new();
    let mut counts_unchanged = None;
    let body_started = setup.is_ok();
    match setup {
        Err(error) => setup_failures.push(error),
        Ok((key, vector)) => {
            let result = (|| -> std::result::Result<(), Failure> {
                let before = module.call_counts()?;
                // This control represents integer encoding, not a valid signature.
                // DSA requires the exact q width; ECDSA also accepts equal short
                // halves. The same scalar values exercise both representations.
                let control_raw = if vector.dsa_spki.is_some() {
                    let mut raw = vec![0; vector.raw.len()];
                    raw[vector.raw.len() / 2 - 1] = 1;
                    raw[vector.raw.len() - 1] = 2;
                    raw
                } else {
                    vec![1, 2]
                };
                let control = vector.encode(&key, &control_raw)?;
                if control != [0x30, 6, 2, 1, 1, 2, 1, 2] {
                    return Err(Failure::Oracle("encoding_control"));
                }
                let conversion = check(&key, &vector);
                let control_after = vector.encode(&key, &control_raw);
                let after = module.call_counts()?;
                counts_unchanged = Some(before == after);
                if before != after {
                    return Err(Failure::Oracle("reported_native_call_delta"));
                }
                conversion?;
                if control_after? != control {
                    return Err(Failure::Oracle("encoding_control_after"));
                }
                Ok(())
            })();
            if let Err(error) = result {
                body_failures.push(error);
            }
            drop(key);
        }
    }
    let mut cleanup = fixture.as_mut().map_or_else(Vec::new, Fixture::close);
    drop(fixture);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    for error in &setup_failures {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    for error in &body_failures {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if let Some(unchanged) = counts_unchanged {
        report.observation(
            Phase::Body,
            "fe11_reported_calls_unchanged",
            Producer::Fe11Local,
            Observation::Boolean(unchanged),
        )?;
    }
    report.finish(
        if setup_failures.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !body_started {
            PhaseResult::NotExecuted
        } else if body_failures.is_empty() {
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
