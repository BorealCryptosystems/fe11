// SPDX-License-Identifier: Apache-2.0
//! HMAC/CMAC known answers, prefix witnesses and exact native refusals.
use super::{
    arguments::hex,
    configuration::Configuration,
    mac_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "mac_binding.rs"]
mod binding;
#[path = "mac_key_type.rs"]
mod key_type;

struct Vector {
    algorithm: NativeMacAlgorithm,
    advanced: bool,
    sign: bool,
    oracle: String,
    lengths: Vec<usize>,
    key: Vec<u8>,
    message: Vec<u8>,
    tag: Vec<u8>,
    width: usize,
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
    if fields.len() != 9 {
        return Err(Failure::Input("vector_fields"));
    }
    let mechanism: u64 = fields[0]
        .parse()
        .map_err(|_| Failure::Input("mechanism_number"))?;
    let algorithm = NativeMacAlgorithm::ALL
        .iter()
        .find(|value| value.mechanism_number() == mechanism)
        .copied()
        .ok_or(Failure::Input("mac_algorithm"))?;
    let advanced = match fields[1] {
        "session" => false,
        "advanced" => true,
        _ => return Err(Failure::Input("mac_owner")),
    };
    let sign = match fields[2] {
        "sign" => true,
        "verify" => false,
        _ => return Err(Failure::Input("mac_operation")),
    };
    if !matches!(
        fields[3],
        "full"
            | "prefix"
            | "short-key"
            | "negative"
            | "usage"
            | "binding"
            | "general-absent"
            | "dedicated"
    ) || (sign && fields[3] == "negative")
    {
        return Err(Failure::Input("mac_oracle"));
    }
    let lengths: Vec<usize> = fields[4]
        .split(',')
        .map(|part| part.parse().map_err(|_| Failure::Input("part_length")))
        .collect::<std::result::Result<_, _>>()?;
    let message = hex(fields[6], 262144).map_err(Failure::Input)?;
    let total = lengths
        .iter()
        .try_fold(0usize, |sum, size| sum.checked_add(*size));
    if lengths.is_empty() || lengths.len() > 1024 || total != Some(message.len()) {
        return Err(Failure::Input("part_dimensions"));
    }
    let width: usize = fields[8].parse().map_err(|_| Failure::Input("mac_width"))?;
    let tag = hex(fields[7], 1024).map_err(Failure::Input)?;
    let minimum_width = if fields[3] == "general-absent" { 1 } else { 8 };
    if !(minimum_width..=64).contains(&width)
        || (matches!(fields[3], "full" | "usage" | "binding" | "dedicated") && tag.len() != width)
    {
        return Err(Failure::Input("mac_tag_width"));
    }
    if fields[3] == "prefix" && (tag.is_empty() || tag.len() >= width) {
        return Err(Failure::Input("mac_prefix_width"));
    }
    if fields[3] == "general-absent" && tag.len() < width {
        return Err(Failure::Input("mac_general_answer_width"));
    }
    Ok(Vector {
        algorithm,
        advanced,
        sign,
        oracle: fields[3].to_owned(),
        lengths,
        key: hex(fields[5], 65536).map_err(Failure::Input)?,
        message,
        tag,
        width,
    })
}

fn refusal<W: Write>(
    result: Result<()>,
    function: &'static str,
    codes: &[u64],
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function && codes.contains(&code) => {
            // Preserve the actual native producer, code and effect classification,
            // even when this bounded refusal is the expected successful assertion.
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("expected_native_refusal")),
    }
}

fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if vector.oracle == "dedicated" {
        key_type::check(owner, key, vector.algorithm, &vector.key)?;
        // The object type is the variable under test. One published answer
        // witnesses its imported bytes and both of its requested usages.
        let input = [vector.message.as_slice()];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: vector.message.len(),
        };
        let tag = owner.compute(
            key,
            vector.algorithm,
            MessageRoute::Single,
            &input,
            limits,
            vector.width,
        )?;
        if tag.as_bytes() != vector.tag
            || tag.mechanism_number() != vector.algorithm.mechanism_number()
        {
            return Err(Failure::Oracle("dedicated_hmac_known_answer"));
        }
        owner.verify(
            key,
            vector.algorithm,
            MessageRoute::Single,
            &input,
            &vector.tag,
            limits,
        )?;
        return Ok(());
    }
    let mut parts = Vec::with_capacity(vector.lengths.len());
    let mut offset = 0;
    for length in &vector.lengths {
        parts.push(&vector.message[offset..offset + length]);
        offset += length;
    }
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: vector.message.len(),
    };
    let single = [vector.message.as_slice()];
    for route in [MessageRoute::Single, MessageRoute::Multipart] {
        // Single consumes the whole message once; only Multipart receives its
        // partition, including explicit zero-length fragments.
        let input = if route == MessageRoute::Single {
            single.as_slice()
        } else {
            parts.as_slice()
        };
        if vector.oracle == "usage" {
            let result = if vector.sign {
                owner
                    .compute(key, vector.algorithm, route, input, limits, vector.width)
                    .map(|_| ())
            } else {
                owner.verify(key, vector.algorithm, route, input, &vector.tag, limits)
            };
            refusal(
                result,
                if vector.sign {
                    "C_SignInit"
                } else {
                    "C_VerifyInit"
                },
                &[fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64],
                report,
            )?;
            continue;
        }
        let verify_final = if route == MessageRoute::Single {
            "C_Verify"
        } else {
            "C_VerifyFinal"
        };
        if vector.oracle == "short-key" {
            let result = if vector.sign {
                owner
                    .compute(key, vector.algorithm, route, input, limits, vector.width)
                    .map(|_| ())
            } else {
                owner.verify(key, vector.algorithm, route, input, &vector.tag, limits)
            };
            refusal(
                result,
                if vector.sign {
                    "C_SignInit"
                } else {
                    "C_VerifyInit"
                },
                &[fe11_sys::CKR_KEY_SIZE_RANGE as u64],
                report,
            )?;
            continue;
        }
        if vector.oracle == "negative" {
            refusal(
                owner.verify(key, vector.algorithm, route, input, &vector.tag, limits),
                verify_final,
                &[
                    fe11_sys::CKR_SIGNATURE_INVALID as u64,
                    fe11_sys::CKR_SIGNATURE_LEN_RANGE as u64,
                ],
                report,
            )?;
            continue;
        }
        if vector.oracle == "prefix" {
            let mac = owner.compute(key, vector.algorithm, route, input, limits, vector.width)?;
            if mac.mechanism_number() != vector.algorithm.mechanism_number()
                || mac.as_bytes().len() != vector.width
                || !mac.as_bytes().starts_with(&vector.tag)
            {
                return Err(Failure::Oracle("published_mac_prefix_and_full_length"));
            }
            if !vector.sign {
                // The native verifier consumes the generated full tag. Only its
                // prefix has an independent answer: this is not a full-tag KAT.
                owner.verify(key, vector.algorithm, route, input, mac.as_bytes(), limits)?;
            }
            report
                .observation(
                    Phase::Body,
                    "published_prefix_only",
                    Producer::PublishedVector,
                    Observation::Boolean(true),
                )
                .map_err(|_| Failure::Input("report_write"))?;
            continue;
        }
        if vector.sign {
            let mac = owner.compute(key, vector.algorithm, route, input, limits, vector.width)?;
            if mac.mechanism_number() != vector.algorithm.mechanism_number()
                || mac.as_bytes() != vector.tag
                || mac.as_bytes().len() != vector.width
            {
                return Err(Failure::Oracle("published_full_mac"));
            }
        } else {
            owner.verify(key, vector.algorithm, route, input, &vector.tag, limits)?;
        }
        let mut changed = vector.tag.clone();
        changed[0] ^= 1;
        refusal(
            owner.verify(key, vector.algorithm, route, input, &changed, limits),
            verify_final,
            &[fe11_sys::CKR_SIGNATURE_INVALID as u64],
            report,
        )?;
        refusal(
            owner.verify(
                key,
                vector.algorithm,
                route,
                input,
                &vector.tag[..vector.width - 1],
                limits,
            ),
            verify_final,
            &[fe11_sys::CKR_SIGNATURE_LEN_RANGE as u64],
            report,
        )?;
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
    let mut other_key = None;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = read(path)?;
        if vector.oracle == "general-absent" {
            let token = super::configuration::select_token(&module, &config.label)
                .ok_or(Failure::Input("token_not_unique"))?;
            let mechanism = NativeMacParameters::General {
                algorithm: vector.algorithm,
                output_bytes: vector.width as u64,
            }
            .mechanism_number()?;
            if module.mechanism_ids(token.slot)?.contains(&mechanism) {
                return Err(Failure::Input("general_mac_absence_prerequisite"));
            }
        }
        owner = Some(Owner::open(&module, config, vector.advanced)?);
        let active = owner.as_ref().ok_or(Failure::Input("mac_owner"))?;
        key = Some(if vector.oracle == "dedicated" {
            active.import_secret_usages(
                &vector.key,
                key_type::for_algorithm(vector.algorithm)?,
                [
                    (StandardAttribute::SIGN, true),
                    (StandardAttribute::VERIFY, true),
                ],
            )?
        } else if vector.oracle == "usage" {
            // Change only the required permission; key type, bytes and the
            // opposite permission remain those of the successful fixture.
            active.import_mac_usages(&vector.key, vector.algorithm, !vector.sign, vector.sign)?
        } else {
            active.import_mac(&vector.key, vector.algorithm)?
        });
        if vector.oracle == "binding" {
            // Change one bit of public fixture material while retaining the
            // algorithm, key type, length and permissions of the control key.
            let mut changed = vector.key.clone();
            let first = changed.first_mut().ok_or(Failure::Input("empty_mac_key"))?;
            *first ^= 1;
            other_key = Some(active.import_mac(&changed, vector.algorithm)?);
        }
        Ok(vector)
    })();
    let started = setup.is_ok();
    let dedicated = matches!(&setup, Ok(vector) if vector.oracle == "dedicated");
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) if vector.oracle == "general-absent" => (
            Ok(()),
            binding::general(
                owner.as_ref().expect("owner established"),
                key.as_ref().expect("key established"),
                &vector,
                &mut report,
            ),
        ),
        Ok(vector) if vector.oracle == "binding" => (
            Ok(()),
            binding::check(
                owner.as_ref().expect("owner established"),
                key.as_ref().expect("key established"),
                other_key.as_ref().expect("second key established"),
                &vector,
                &mut report,
            ),
        ),
        Ok(vector) => (
            Ok(()),
            check(
                owner.as_ref().expect("owner established"),
                key.as_ref().expect("key established"),
                &vector,
                &mut report,
            ),
        ),
    };
    let mut cleanup = Vec::new();
    if let (Some(owner), Some(other)) = (&owner, &other_key) {
        let result = match owner {
            Owner::Session(session) => session.destroy_native_object(other),
            Owner::Advanced(session) => session.destroy_native_object(other),
        };
        if let Err(error) = result {
            cleanup.push(error.into());
        }
    }
    drop(other_key);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(key.as_ref()));
    }
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
            if dedicated {
                "dedicated_hmac_identity_and_single_route"
            } else {
                "mac_oracle_and_both_message_routes"
            },
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
