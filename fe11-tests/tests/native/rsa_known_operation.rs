// SPDX-License-Identifier: Apache-2.0
//! Known RSA results and independent verification of randomized outputs.
use super::{
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    rsa_known_fixture::Vector,
};
use fe11::*;
use std::{fs::OpenOptions, io::Write};

#[path = "rsa_signature_lengths.rs"]
mod signature_lengths;

fn invalid_signature<W: Write>(
    result: Result<()>,
    function: &'static str,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function && code == fe11_sys::CKR_SIGNATURE_INVALID as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("invalid_signature_accepted")),
    }
}

pub fn check<W: Write>(
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
            let part = &vector.input[offset..offset + n];
            offset += n;
            part
        })
        .collect();
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: vector.input.len(),
    };
    if let Some(expected_code) = vector.cipher_refusal {
        let result = match owner {
            Owner::Session(s) => {
                s.encrypt_native_rsa(key, vector.cipher()?, &vector.input, 256, limits)
            }
            Owner::Advanced(s) => {
                s.encrypt_native_rsa(key, vector.cipher()?, &vector.input, 256, limits)
            }
        };
        return match result {
            Err(
                error @ Error::Native {
                    function: "C_Encrypt",
                    code,
                    ..
                },
            ) if code == expected_code => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("rsa_cipher_boundary_accepted")),
        };
    }
    let mut outputs = Vec::new();
    let routes =
        &[MessageRoute::Single, MessageRoute::Multipart][..if vector.multipart { 2 } else { 1 }];
    for &route in routes {
        // Single consumes one contiguous message; Multipart preserves every
        // declared fragment, including empty fragments at the boundaries.
        let single = [vector.input.as_slice()];
        let parts = if route == MessageRoute::Single {
            single.as_slice()
        } else {
            parts.as_slice()
        };
        let bytes = match vector.action.as_str() {
            "verify" => {
                if vector.length_boundaries {
                    signature_lengths::check(owner, key, vector, route, parts, limits, report)?;
                    continue;
                }
                owner.verify_parameters(
                    key,
                    vector.signature()?,
                    route,
                    &parts,
                    &vector.expected,
                    limits,
                )?;
                let mut altered = vector.expected.clone();
                *altered
                    .last_mut()
                    .ok_or(Failure::Input("rsa_signature_width"))? ^= 1;
                invalid_signature(
                    owner.verify_parameters(
                        key,
                        vector.signature()?,
                        route,
                        &parts,
                        &altered,
                        limits,
                    ),
                    if route == MessageRoute::Single {
                        "C_Verify"
                    } else {
                        "C_VerifyFinal"
                    },
                    report,
                )?;
                continue;
            }
            "sign" => match owner {
                Owner::Session(s) => {
                    s.sign_native(key, vector.signature()?, route, &parts, limits, 256, None)
                }
                Owner::Advanced(s) => {
                    s.sign_native(key, vector.signature()?, route, &parts, limits, 256, None)
                }
            }?
            .as_bytes()
            .to_vec(),
            "encrypt" => match owner {
                Owner::Session(s) => {
                    s.encrypt_native_rsa(key, vector.cipher()?, &vector.input, 256, limits)
                }
                Owner::Advanced(s) => {
                    s.encrypt_native_rsa(key, vector.cipher()?, &vector.input, 256, limits)
                }
            }?
            .as_bytes()
            .to_vec(),
            "decrypt" => match owner {
                Owner::Session(s) => {
                    s.decrypt_native_rsa(key, vector.cipher()?, &vector.input, 256, limits, None)
                }
                Owner::Advanced(s) => {
                    s.decrypt_native_rsa(key, vector.cipher()?, &vector.input, 256, limits, None)
                }
            }?
            .as_bytes()
            .to_vec(),
            _ => return Err(Failure::Input("rsa_known_action")),
        };
        if vector.randomized {
            if bytes.len() != 256 {
                return Err(Failure::Oracle("rsa_output_width"));
            }
            outputs.extend(bytes);
        } else if bytes != vector.expected {
            return Err(Failure::Oracle("rsa_known_answer"));
        }
    }
    if vector.randomized {
        if outputs.len() != 256 * routes.len() {
            return Err(Failure::Oracle("rsa_output_count"));
        }
        // Public test signatures/ciphertext only. The supervisor supplies a fresh
        // private directory and verifies these outputs before awarding a PASS.
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open("public-rsa-known.bin")
            .map_err(|_| Failure::Input("reference_output_create"))?;
        file.write_all(&outputs)
            .map_err(|_| Failure::Input("reference_output_write"))?;
        file.flush()
            .map_err(|_| Failure::Input("reference_output_flush"))?;
    }
    Ok(())
}
