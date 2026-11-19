// SPDX-License-Identifier: Apache-2.0
//! Published digest answers through four explicit synchronous/advanced API routes.
use super::{arguments::hex, configuration::Configuration, digest_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

enum Route {
    SessionSingle,
    SessionMultipart,
    AdvancedSingle,
    AdvancedMultipart,
}

struct Vector {
    algorithm: NativeDigestAlgorithm,
    route: Route,
    input: Vec<u8>,
    expected: Vec<u8>,
    lengths: Vec<usize>,
}

fn read(path: &Path) -> std::result::Result<Vector, Failure> {
    // Five UTF-8 lines: mechanism number, route, fragment lengths, input hex,
    // expected digest hex. Only public vectors use this file format.
    const MAXIMUM_FILE: u64 = 32 * 1024 * 1024 + 65536;
    let file = File::open(path).map_err(|_| Failure::Input("vector_open"))?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("vector_read"))?;
    if bytes.len() as u64 > MAXIMUM_FILE {
        return Err(Failure::Input("vector_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 5 {
        return Err(Failure::Input("vector_fields"));
    }
    let mechanism: u64 = fields[0]
        .parse()
        .map_err(|_| Failure::Input("mechanism_number"))?;
    let algorithm = NativeDigestAlgorithm::from_mechanism(mechanism)
        .ok_or(Failure::Input("parameterless_digest_selector"))?;
    let route = match fields[1] {
        "session-single" => Route::SessionSingle,
        "session-multipart" => Route::SessionMultipart,
        "advanced-single" => Route::AdvancedSingle,
        "advanced-multipart" => Route::AdvancedMultipart,
        _ => return Err(Failure::Input("digest_route")),
    };
    let input = hex(fields[3], 16 * 1024 * 1024).map_err(Failure::Input)?;
    let expected = hex(fields[4], 64).map_err(Failure::Input)?;
    if fields[2].split(',').count() > 131072 {
        return Err(Failure::Input("part_count"));
    }
    let lengths: Vec<usize> = fields[2]
        .split(',')
        .map(|part| part.parse().map_err(|_| Failure::Input("part_length")))
        .collect::<std::result::Result<_, _>>()?;
    let total = lengths
        .iter()
        .try_fold(0usize, |sum, value| sum.checked_add(*value))
        .ok_or(Failure::Input("part_length_overflow"))?;
    if lengths.len() > 131072 || total != input.len() || expected.is_empty() {
        return Err(Failure::Input("vector_dimensions"));
    }
    if matches!(route, Route::SessionSingle | Route::AdvancedSingle) && lengths != [input.len()] {
        return Err(Failure::Input("single_part_count"));
    }
    Ok(Vector {
        algorithm,
        route,
        input,
        expected,
        lengths,
    })
}

pub struct Outcome {
    pub body: std::result::Result<(), Failure>,
    pub cleanup: Vec<Failure>,
}

pub fn run(module: &Module, config: &Configuration, path: &Path) -> Outcome {
    let mut owner = None;
    let body = (|| -> std::result::Result<(), Failure> {
        let vector = read(path)?;
        owner = Some(Owner::open(
            module,
            config,
            matches!(
                vector.route,
                Route::AdvancedSingle | Route::AdvancedMultipart
            ),
        )?);
        let mut offset = 0;
        let parts: Vec<_> = vector
            .lengths
            .iter()
            .map(|length| {
                let part = &vector.input[offset..offset + length];
                offset += length;
                part
            })
            .collect();
        let limits = InputLimits {
            maximum_parts: parts.len(),
            maximum_total_bytes: vector.input.len(),
        };
        let actual = match owner.as_ref().expect("digest owner was assigned") {
            Owner::Session(session) => match vector.route {
                Route::SessionSingle => {
                    session.digest_native_single(vector.algorithm, &vector.input, limits)?
                }
                _ => session.digest_native(vector.algorithm, &parts, limits)?,
            },
            Owner::Advanced(session) => {
                let mut ticket = match vector.route {
                    Route::AdvancedSingle => {
                        session.digest_native_single(vector.algorithm, &vector.input, limits)?
                    }
                    _ => session.digest_native(vector.algorithm, &parts, limits)?,
                };
                match session.poll(&mut ticket)? {
                    OperationProgress::NativeDigest(digest) => digest,
                    _ => return Err(Failure::Oracle("expected_completed_native_digest")),
                }
            }
        };
        if actual.algorithm() != vector.algorithm {
            return Err(Failure::Oracle("digest_algorithm"));
        }
        if actual.as_bytes() != vector.expected {
            return Err(Failure::Oracle("published_digest_bytes_and_length"));
        }
        // Drop the credited result before explicit session closure.
        drop(actual);
        Ok(())
    })();
    let cleanup = owner.as_ref().map_or_else(Vec::new, Owner::close);
    Outcome { body, cleanup }
}

/// Report a finite or streamed digest after independent native cleanup.
pub fn finish<W: std::io::Write>(
    module: Module,
    mut result: Outcome,
    mut report: super::report::Report<W>,
) -> std::io::Result<bool> {
    use super::{
        outcome,
        report::{Observation, Phase, PhaseResult, Producer},
    };
    if let Err(error) = module.close() {
        result.cleanup.push(error.into());
    }
    if let Err(error) = &result.body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &result.cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    report.observation(
        Phase::Body,
        "published_digest_bytes_and_length",
        Producer::PublishedVector,
        Observation::Boolean(result.body.is_ok()),
    )?;
    report.finish(
        PhaseResult::Passed,
        if result.body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if result.cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
