// SPDX-License-Identifier: Apache-2.0
//! Published classic-cipher answers on both single and multipart public routes.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
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
#[path = "cipher_block_boundary.rs"]
mod block;

pub(super) struct Vector {
    pub(super) parameters: CipherParameters<'static>,
    pub(super) key_type: fe11_sys::CK_KEY_TYPE,
    pub(super) advanced: bool,
    pub(super) encrypt: bool,
    lengths: Vec<usize>,
    pub(super) key: Vec<u8>,
    pub(super) input: Vec<u8>,
    pub(super) expected: Vec<u8>,
    boundary: Option<Boundary>,
    block_boundary: Option<block::Case>,
}

#[derive(Clone, Copy)]
enum Boundary {
    Exact,
    CounterWidth,
    CounterOverflow,
}

pub(super) fn read(path: &Path) -> std::result::Result<Vector, Failure> {
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
    if !matches!(fields.len(), 8 | 9 | 10 | 12 | 13) {
        return Err(Failure::Input("vector_fields"));
    }
    let (counter_bits, boundary) = if fields.len() == 10 {
        if fields[0] != "CKM_AES_CTR" || fields[2] != "encrypt" {
            return Err(Failure::Input("counter_boundary_parameters"));
        }
        let bits: u64 = fields[8]
            .parse()
            .map_err(|_| Failure::Input("counter_width"))?;
        let boundary = match fields[9] {
            "exact" if (1..=128).contains(&bits) => Boundary::Exact,
            "width" if bits == 0 || bits == 129 => Boundary::CounterWidth,
            "overflow" if (1..=128).contains(&bits) => Boundary::CounterOverflow,
            _ => return Err(Failure::Input("counter_boundary_oracle")),
        };
        (bits, Some(boundary))
    } else {
        (128, None)
    };
    let iv = hex(fields[7], 16).map_err(Failure::Input)?;
    let iv8 = || <[u8; 8]>::try_from(iv.as_slice()).map_err(|_| Failure::Input("iv_width"));
    let iv16 = || <[u8; 16]>::try_from(iv.as_slice()).map_err(|_| Failure::Input("iv_width"));
    let (parameters, key_type) = match fields[0] {
        "CKM_AES_ECB" if iv.is_empty() => (
            CipherParameters::Aes(AesCipherParameters::Ecb),
            fe11_sys::CKK_AES,
        ),
        "CKM_AES_CBC" => (
            CipherParameters::Aes(AesCipherParameters::Cbc { iv: iv16()? }),
            fe11_sys::CKK_AES,
        ),
        "CKM_AES_CBC_PAD" => (
            CipherParameters::Aes(AesCipherParameters::CbcPad { iv: iv16()? }),
            fe11_sys::CKK_AES,
        ),
        "CKM_AES_CTR" => (
            CipherParameters::Aes(AesCipherParameters::Ctr {
                counter_bits,
                counter_block: iv16()?,
            }),
            fe11_sys::CKK_AES,
        ),
        "CKM_DES_ECB" if iv.is_empty() => (CipherParameters::DesEcb, fe11_sys::CKK_DES),
        "CKM_DES_CBC" => (CipherParameters::DesCbc { iv: iv8()? }, fe11_sys::CKK_DES),
        "CKM_DES_CBC_PAD" => (
            CipherParameters::DesCbcPad { iv: iv8()? },
            fe11_sys::CKK_DES,
        ),
        "CKM_DES3_ECB" if iv.is_empty() => (CipherParameters::Des3Ecb, fe11_sys::CKK_DES3),
        "CKM_DES3_CBC" => (CipherParameters::Des3Cbc { iv: iv8()? }, fe11_sys::CKK_DES3),
        "CKM_DES3_CBC_PAD" => (
            CipherParameters::Des3CbcPad { iv: iv8()? },
            fe11_sys::CKK_DES3,
        ),
        _ => return Err(Failure::Input("cipher_parameters")),
    };
    let key = hex(fields[4], 32).map_err(Failure::Input)?;
    // An explicit key-class suffix distinguishes two-key TDEA from the
    // default triple-length fixture grammar without silently rewriting it.
    let key_type = if matches!(fields.len(), 9 | 13) {
        if fields.last() != Some(&"CKK_DES2")
            || !matches!(
                fields[0],
                "CKM_DES3_ECB" | "CKM_DES3_CBC" | "CKM_DES3_CBC_PAD"
            )
            || key.len() != 16
        {
            return Err(Failure::Input("cipher_explicit_key_type"));
        }
        fe11_sys::CKK_DES2
    } else {
        key_type
    };
    let advanced = match fields[1] {
        "session" => false,
        "advanced" => true,
        _ => return Err(Failure::Input("cipher_owner")),
    };
    let encrypt = match fields[2] {
        "encrypt" => true,
        "decrypt" => false,
        _ => return Err(Failure::Input("cipher_direction")),
    };
    let lengths: Vec<usize> = fields[3]
        .split(',')
        .map(|part| part.parse().map_err(|_| Failure::Input("part_length")))
        .collect::<std::result::Result<_, _>>()?;
    let input = hex(fields[5], 262144).map_err(Failure::Input)?;
    let total = lengths
        .iter()
        .try_fold(0usize, |sum, size| sum.checked_add(*size));
    if lengths.is_empty() || lengths.len() > 1024 || total != Some(input.len()) {
        return Err(Failure::Input("part_dimensions"));
    }
    Ok(Vector {
        parameters,
        key_type,
        advanced,
        encrypt,
        lengths,
        key,
        input,
        expected: hex(fields[6], 262144).map_err(Failure::Input)?,
        boundary,
        block_boundary: if matches!(fields.len(), 12 | 13) {
            Some(block::Case::read(&fields)?)
        } else {
            None
        },
    })
}

/// A boundary fixture selects a synchronous single call or an incremental
/// Advanced stream. Explicit Update/Final calls expose the failing producer.
fn boundary_encrypt(
    owner: &Owner,
    key: &NativeObjectRef,
    parameters: CipherParameters<'_>,
    parts: &[&[u8]],
) -> std::result::Result<Vec<u8>, Failure> {
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: parts.iter().map(|p| p.len()).sum(),
    };
    match owner {
        Owner::Session(_) => Ok(owner
            .encrypt(key, parameters, MessageRoute::Single, parts, limits)?
            .as_bytes()
            .to_vec()),
        Owner::Advanced(session) => {
            // CTR emits at most one output byte per input byte. A full block
            // also accommodates the final call without a capacity retry.
            let mut ticket = session.begin_encrypt_stream(
                CipherKeyReference::Secret(key),
                parameters,
                CipherOutputPlan::Buffer {
                    capacity: limits.maximum_total_bytes.max(16),
                },
            )?;
            for part in parts {
                if !matches!(
                    session.cipher_update(&mut ticket, part, limits)?,
                    OperationProgress::Ready
                ) {
                    return Err(Failure::Oracle("counter_update_boundary"));
                }
            }
            match session.finish_cipher_stream(&mut ticket)? {
                OperationProgress::CipherEncrypted(value) => Ok(value.as_bytes().to_vec()),
                _ => Err(Failure::Oracle("counter_completed_output")),
            }
        }
    }
}

fn check_boundary<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    boundary: Boundary,
    parts: &[&[u8]],
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let result = boundary_encrypt(owner, key, vector.parameters, parts);
    let error = match (boundary, result) {
        (Boundary::Exact, Ok(value)) if value == vector.expected => None,
        (
            Boundary::CounterWidth,
            Err(Failure::Product(
                error @ Error::Rejected(RejectionReason::SymmetricParameters(
                    SymmetricParametersRejection::AesCtrCounterWidth,
                )),
            )),
        ) => Some(error),
        (
            Boundary::CounterOverflow,
            Err(Failure::Product(error @ Error::Native { function, code, .. })),
        ) if code == fe11_sys::CKR_DATA_LEN_RANGE as u64
            && function
                == if vector.advanced {
                    "C_EncryptUpdate"
                } else {
                    "C_Encrypt"
                } =>
        {
            Some(error)
        }
        (_, Err(error)) => return Err(error),
        _ => return Err(Failure::Oracle("counter_boundary_result")),
    };
    if let Some(error) = error {
        outcome::record(report, Phase::Body, &Failure::Product(error))
            .map_err(|_| Failure::Input("report_write"))?;
    }
    if !matches!(boundary, Boundary::CounterWidth) {
        // A terminal error must release the native operation. The control uses
        // the SAME session/key and counter, with a fresh Init and only one block.
        // Its expected bytes are supplied independently, not copied from output.
        let control = vector
            .input
            .get(..16)
            .ok_or(Failure::Input("counter_control_input"))?;
        let expected = vector
            .expected
            .get(..16)
            .ok_or(Failure::Input("counter_control_output"))?;
        if boundary_encrypt(owner, key, vector.parameters, &[control])? != expected {
            return Err(Failure::Oracle("counter_same_session_reinitialization"));
        }
    }
    Ok(())
}

fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut parts = Vec::with_capacity(vector.lengths.len());
    let mut offset = 0;
    for length in &vector.lengths {
        parts.push(&vector.input[offset..offset + length]);
        offset += length;
    }
    if let Some(boundary) = vector.boundary {
        return check_boundary(owner, key, vector, boundary, &parts, report);
    }
    if let Some(case) = &vector.block_boundary {
        return block::check(owner, key, vector, case, &parts, report);
    }
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: vector.input.len(),
    };
    for route in [MessageRoute::Single, MessageRoute::Multipart] {
        // The same bytes are contiguous for Single and partitioned for
        // Multipart. Zero-length parts remain explicit Update calls.
        let contiguous = [vector.input.as_slice()];
        let route_parts = if route == MessageRoute::Single {
            contiguous.as_slice()
        } else {
            parts.as_slice()
        };
        // Compare each direction with independent published bytes, never with
        // a round trip through another operation of the library under test.
        if vector.encrypt {
            let result = owner.encrypt(key, vector.parameters, route, route_parts, limits)?;
            if result.as_bytes() != vector.expected {
                return Err(Failure::Oracle("ciphertext_bytes"));
            }
        } else {
            let result = owner.decrypt(key, vector.parameters, route, route_parts, limits)?;
            if result.as_bytes() != vector.expected {
                return Err(Failure::Oracle("plaintext_bytes"));
            }
        }
    }
    Ok(())
}

pub fn run<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut boundary_case = false;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = read(path)?;
        boundary_case = vector.boundary.is_some() || vector.block_boundary.is_some();
        if boundary_case {
            let token =
                select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
            let session = module.select(&token)?.open_session(true)?;
            owner = Some(Owner::Session(session));
            if let Some(Owner::Session(session)) = &owner {
                session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            }
            if vector.advanced {
                if let Some(Owner::Session(session)) = owner.take() {
                    owner = Some(Owner::Advanced(session.into_advanced()?));
                }
            }
        } else {
            owner = Some(Owner::open(&module, config, vector.advanced)?);
        }
        key = Some(
            owner
                .as_ref()
                .ok_or(Failure::Input("cipher_owner"))?
                .import_secret(
                    &vector.key,
                    vector.key_type,
                    [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
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
                (Some(owner), Some(key)) => check(owner, key, &vector, &mut report),
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
            if boundary_case {
                "cipher_boundary_and_same_session_control"
            } else {
                "cipher_known_answer_and_both_routes"
            },
            if boundary_case {
                Producer::IndependentReference
            } else {
                Producer::PublishedVector
            },
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
