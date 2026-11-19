// SPDX-License-Identifier: Apache-2.0
//! Algorithm-role refusals and result bytes on real generated symmetric keys.
use super::{
    arguments::hex,
    configuration::Configuration,
    generation_transition_spec,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::Arc,
};

struct Case {
    action: String,
    input: Vec<u8>,
    mac: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(1025)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 1024 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_utf8"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !matches!(
                fields[0],
                "empty_encrypt"
                    | "empty_decrypt"
                    | "aes_mac"
                    | "hmac_ccm"
                    | "dual_aes"
                    | "dual_mac_length"
                    | "dual_hmac"
                    | "dual_algorithm"
                    | "managed_mac_bytes"
                    | "message_sign"
                    | "message_verify"
                    | "hmac_aes"
            )
        {
            return Err(Failure::Input("symmetric_guard_fields"));
        }
        Ok(Self {
            action: fields[0].into(),
            input: hex(fields[1], 64).map_err(Failure::Input)?,
            mac: hex(fields[2], 64).map_err(Failure::Input)?,
        })
    }
    fn advanced(&self) -> bool {
        !matches!(self.action.as_str(), "managed_mac_bytes" | "aes_mac" | "hmac_ccm" | "hmac_aes")
    }
}

fn generate(
    session: &Session,
    label: &str,
    algorithm: SymmetricAlgorithm,
    created: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<SymmetricKey, Failure> {
    let mut spec = generation_transition_spec::key(label);
    spec.algorithm = algorithm;
    spec.persistent = false;
    if !matches!(algorithm, SymmetricAlgorithm::Aes128) {
        spec.hmac_key_type = Some(HmacKeyType::Generic);
        spec.usages = KeyUsageRequest {
            sign: Some(true),
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        };
        spec.admission.observation.encrypt = false;
        spec.admission.observation.decrypt = false;
        spec.admission.observation.sign = true;
        spec.admission.observation.verify = true;
    }
    let result = session.generate_symmetric_key(spec)?;
    created.push(result.objects);
    if result.remainder.is_some() {
        return Err(Failure::Oracle("symmetric_generation_auxiliary_output"));
    }
    result.observation.map_err(Failure::from)
}

fn control(owner: &Owner) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    let digest = match owner {
        Owner::Session(session) => {
            session.digest_multipart(HashAlgorithm::Sha256, &[b"abc"], limits)?
        }
        Owner::Advanced(session) => {
            let mut ticket = session.begin_digest(HashAlgorithm::Sha256)?;
            session.digest_update(&mut ticket, b"abc", limits)?;
            match session.finish_digest(&mut ticket)? {
                OperationProgress::Digest(value) => value,
                _ => return Err(Failure::Oracle("guard_idle_digest_result")),
            }
        }
    };
    let expected = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected {
        return Err(Failure::Oracle("guard_idle_digest_bytes"));
    }
    Ok(())
}

fn check(
    module: &Module,
    owner: &Owner,
    case: &Case,
    key: &SymmetricKey,
    mac: Option<&SymmetricKey>,
) -> std::result::Result<(), Failure> {
    if case.action == "managed_mac_bytes" {
        let Owner::Session(session) = owner else {
            return Err(Failure::Input("managed_mac_session"));
        };
        let limits = InputLimits { maximum_parts: 1, maximum_total_bytes: case.input.len() };
        let mac = session.compute_mac(key, &case.input, limits)?;
        let before = module.call_counts()?;
        let bytes = mac.as_bytes();
        if bytes.len() != 32 || module.call_counts()? != before {
            return Err(Failure::Oracle("managed_mac_byte_view"));
        }
        if session.verify_mac(key, &case.input, bytes, limits)? != Verification::Valid {
            return Err(Failure::Oracle("managed_mac_bytes_did_not_verify"));
        }
        let mut altered = bytes.to_vec();
        altered[0] ^= 1;
        if session.verify_mac(key, &case.input, &altered, limits)? != Verification::Invalid {
            return Err(Failure::Oracle("managed_mac_mutation_accepted"));
        }
        return Ok(());
    }
    let before = module.call_counts()?;
    // This guard occurs after the dual context budget check. Account for the
    // exact IV and full SHA-256 MAC as well as the ciphertext; otherwise an
    // unrelated resource refusal would mask the algorithm mismatch.
    let context_bytes = if case.action == "dual_algorithm" {
        12 + 32
    } else {
        0
    };
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: case
            .input
            .len()
            .checked_add(context_bytes)
            .ok_or(Failure::Input("guard_context_size"))?,
    };
    let parts = [case.input.as_slice()];
    let gcm = || DualCipher::Gcm {
        nonce: AeadNonce::Provided([0; 12]),
        aad: &[],
    };
    let (result, reason) = match owner {
        Owner::Session(session) => match case.action.as_str() {
            "aes_mac" => (
                session.compute_mac(key, &case.input, limits).map(|_| ()),
                RejectionReason::SymmetricParameters(
                    SymmetricParametersRejection::AeadKeyUsedForMac,
                ),
            ),
            "hmac_ccm" => (
                session
                    .encrypt_ccm(
                        key,
                        CcmParameters {
                            nonce: CcmNonce {
                                bytes: Arc::from([0u8; 12]),
                                generator: 0,
                                fixed_bits: 0,
                            },
                            aad: &[],
                            mac_length: 16,
                        },
                        &case.input,
                        limits,
                    )
                    .map(|_| ()),
                RejectionReason::SymmetricParameters(
                    SymmetricParametersRejection::CcmRequiresAnAesKey,
                ),
            ),
            "hmac_aes" => (
                session
                    .begin_encrypt_aes(
                        key,
                        AesCipherParameters::Ecb,
                        MessageRoute::Single,
                        &parts,
                        limits,
                    )
                    .map(|_| ()),
                RejectionReason::CipherContinuation(
                    CipherContinuationRejection::AesOperationRequiresAnAesKey,
                ),
            ),
            _ => return Err(Failure::Input("synchronous_guard_action")),
        },
        Owner::Advanced(session) => match case.action.as_str() {
            "empty_encrypt" => (
                session
                    .encrypt_stream_aead_messages(
                        key.managed(),
                        &[],
                        MessageRoute::Single,
                        InputLimits {
                            maximum_parts: 0,
                            maximum_total_bytes: 0,
                        },
                    )
                    .map(|_| ()),
                RejectionReason::AeadMessages(AeadMessagesRejection::EmptyStreamAeadSequence),
            ),
            "empty_decrypt" => (
                session
                    .decrypt_stream_aead_messages(
                        key.managed(),
                        &[],
                        MessageRoute::Single,
                        InputLimits {
                            maximum_parts: 0,
                            maximum_total_bytes: 0,
                        },
                    )
                    .map(|_| ()),
                RejectionReason::AeadMessages(AeadMessagesRejection::EmptyStreamAeadSequence),
            ),
            "dual_aes" => (
                session
                    .decrypt_digest_with_hash(key, HashAlgorithm::Sha256, gcm(), &parts, limits)
                    .map(|_| ()),
                RejectionReason::CombinedOperations(
                    CombinedOperationsRejection::DualAesKeyRequired,
                ),
            ),
            "dual_mac_length" => (
                session
                    .decrypt_verify_with_mac(
                        key,
                        mac.ok_or(Failure::Input("mac_key"))?,
                        gcm(),
                        &parts,
                        &case.mac,
                        limits,
                    )
                    .map(|_| ()),
                RejectionReason::CombinedOperations(CombinedOperationsRejection::DualFullMacLength),
            ),
            "dual_hmac" => (
                session
                    .decrypt_verify_with_mac(key, key, gcm(), &parts, &case.mac, limits)
                    .map(|_| ()),
                RejectionReason::CombinedOperations(
                    CombinedOperationsRejection::DualHmacKeyRequired,
                ),
            ),
            "dual_algorithm" => {
                let expected: &[u8; 32] = case
                    .mac
                    .as_slice()
                    .try_into()
                    .map_err(|_| Failure::Input("mac32_width"))?;
                (
                    session
                        .decrypt_verify(
                            key,
                            mac.ok_or(Failure::Input("mac_key"))?,
                            gcm(),
                            &parts,
                            expected,
                            limits,
                        )
                        .map(|_| ()),
                    RejectionReason::CombinedOperations(
                        CombinedOperationsRejection::DualMacKeyAlgorithm,
                    ),
                )
            }
            "message_sign" => (
                session
                    .begin_mac_sign_message_stream(key, MessageRoute::Single)
                    .map(|_| ()),
                RejectionReason::SignatureMessages(
                    SignatureMessagesRejection::MessageHmacKeyRequired,
                ),
            ),
            "message_verify" => (
                session
                    .begin_mac_verify_message_stream(key, MessageRoute::Single)
                    .map(|_| ()),
                RejectionReason::SignatureMessages(
                    SignatureMessagesRejection::MessageHmacKeyRequired,
                ),
            ),
            _ => return Err(Failure::Input("advanced_guard_action")),
        },
    };
    match result {
        Err(Error::Rejected(actual)) if actual == reason => (),
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("symmetric_guard_missing_refusal")),
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("symmetric_guard_dispatched"));
    }
    control(owner)
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut created = Vec::new();
    let setup = (|| -> std::result::Result<(Case, SymmetricKey, Option<SymmetricKey>), Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let session = match &owner {
            Some(Owner::Session(value)) => value,
            _ => return Err(Failure::Input("guard_owner")),
        };
        let algorithm = if matches!(case.action.as_str(), "managed_mac_bytes" | "hmac_ccm" | "hmac_aes" | "dual_aes") {
            SymmetricAlgorithm::HmacSha256 { key_length: 32 }
        } else {
            SymmetricAlgorithm::Aes128
        };
        let key = generate(
            session,
            &format!("{}-key", config.label),
            algorithm,
            &mut created,
        )?;
        let mac = match case.action.as_str() {
            "dual_mac_length" => Some(generate(
                session,
                &format!("{}-mac", config.label),
                SymmetricAlgorithm::HmacSha256 { key_length: 32 },
                &mut created,
            )?),
            "dual_algorithm" => Some(generate(
                session,
                &format!("{}-mac", config.label),
                SymmetricAlgorithm::HmacSha384 { key_length: 48 },
                &mut created,
            )?),
            _ => None,
        };
        if case.advanced() {
            let session = match owner.take() {
                Some(Owner::Session(value)) => value,
                _ => return Err(Failure::Input("guard_owner")),
            };
            owner = Some(Owner::Advanced(session.into_advanced()?));
        }
        Ok((case, key, mac))
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Ok((case, key, mac)) => match &owner {
            Some(owner) => check(&module, owner, case, key, mac.as_ref()),
            None => Err(Failure::Input("guard_owner")),
        },
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(owner) = &owner {
        for objects in &created {
            for object in objects.as_slice() {
                let result = match owner {
                    Owner::Session(s) => s.destroy_native_object(object),
                    Owner::Advanced(s) => s.destroy_native_object(object),
                };
                if let Err(error) = result {
                    cleanup.push(error.into());
                }
            }
        }
        cleanup.extend(owner.close(None));
    }
    drop(created);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
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
        let (assertion, producer) = if matches!(&setup, Ok((case, _, _)) if case.action == "managed_mac_bytes") {
            ("managed_mac_byte_view_matches_native_verification", Producer::TestOracle)
        } else {
            ("typed_key_role_refused_without_dispatch_and_idle_digest_usable", Producer::Fe11Local)
        };
        report.observation(
            Phase::Body,
            assertion,
            producer,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
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
