// SPDX-License-Identifier: Apache-2.0
//! Structural input refusals are checked before native object or crypto work.
use super::{
    configuration::Configuration,
    credentials::Credentials,
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
};

struct Case {
    action: String,
    advanced: bool,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(129)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 128 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let action = text
            .strip_suffix('\n')
            .ok_or(Failure::Input("fixture_lines"))?;
        if !matches!(
            action,
            "deferred_template"
                | "template_count"
                | "template_value"
                | "template_depth"
                | "digest_count"
                | "digest_total"
                | "hmac_key_type"
                | "find_aes"
                | "generate_aes"
                | "kek_algorithm"
        ) {
            return Err(Failure::Input("input_guard_action"));
        }
        Ok(Self {
            action: action.into(),
            advanced: matches!(action, "find_aes" | "generate_aes"),
        })
    }
}

fn refusal<T>(result: Result<T>, expected: RejectionReason) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(reason)) if reason == expected => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("input_guard_expected_refusal")),
    }
}
fn hmac_spec(label: &str, key_type: Option<HmacKeyType>) -> SymmetricKeySpec {
    let mut key = generation_transition_spec::key(label);
    key.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 32 };
    key.hmac_key_type = key_type;
    key.persistent = false;
    key.usages = KeyUsageRequest {
        sign: Some(true),
        verify: Some(true),
        ..KeyUsageRequest::omitted()
    };
    key.admission.observation.encrypt = false;
    key.admission.observation.decrypt = false;
    key.admission.observation.sign = true;
    key.admission.observation.verify = true;
    key
}
fn check(
    module: &Module,
    owner: &Owner,
    case: &Case,
    label: &str,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    match case.action.as_str() {
        "deferred_template" => {
            // SAFETY: both identifiers designate template attributes in the
            // headers. The supplied layout is exactly Template; no native call
            // uses an accepted declaration. Each deferred identifier is checked.
            for id in [
                fe11_sys::CKA_ENCAPSULATE_TEMPLATE,
                fe11_sys::CKA_DECAPSULATE_TEMPLATE,
            ] {
                refusal(
                    unsafe {
                        module.declare_attribute_extension(id as u64, AttributeLayout::Template)
                    },
                    RejectionReason::AttributeValues(
                        AttributeValuesRejection::AttributeTemplateSpecificationDeferred,
                    ),
                )?;
            }
        }
        "find_aes" | "generate_aes" => {
            let Owner::Advanced(session) = owner else {
                return Err(Failure::Input("advanced_owner"));
            };
            let spec = hmac_spec(label, Some(HmacKeyType::Generic));
            let result = if case.action == "find_aes" {
                session.find_aes_key(spec)
            } else {
                session.generate_aes_key(spec)
            };
            refusal(
                result,
                RejectionReason::KeyAdmission(KeyAdmissionRejection::AesKeyRequired),
            )?;
        }
        action => {
            let Owner::Session(session) = owner else {
                return Err(Failure::Input("ordinary_owner"));
            };
            match action {
                "template_count" | "template_value" | "template_depth" => {
                    let leaf = [AttributeInput {
                        attribute: StandardAttribute::LABEL.into(),
                        value: AttributeInputValue::Bytes(b"abc"),
                    }];
                    let nested = [AttributeInput {
                        attribute: StandardAttribute::WRAP_TEMPLATE.into(),
                        value: AttributeInputValue::Template(&leaf),
                    }];
                    let (template, limits, reason) = match action {
                        "template_count" => (
                            &leaf[..],
                            AttributeTemplateLimits {
                                maximum_depth: 0,
                                maximum_attributes: 0,
                                maximum_value_bytes: 3,
                            },
                            AttributeValuesRejection::AttributeTemplateCountCeiling,
                        ),
                        "template_value" => (
                            &leaf[..],
                            AttributeTemplateLimits {
                                maximum_depth: 0,
                                maximum_attributes: 1,
                                maximum_value_bytes: 2,
                            },
                            AttributeValuesRejection::AttributeTemplateValueCeiling,
                        ),
                        _ => (
                            &nested[..],
                            AttributeTemplateLimits {
                                maximum_depth: 0,
                                maximum_attributes: 2,
                                maximum_value_bytes: 3,
                            },
                            AttributeValuesRejection::AttributeTemplateDepthCeiling,
                        ),
                    };
                    refusal(
                        session.create_native_object(template, limits),
                        RejectionReason::AttributeValues(reason),
                    )?;
                }
                "digest_count" | "digest_total" => {
                    let count = action == "digest_count";
                    let limits = InputLimits {
                        maximum_parts: if count { 0 } else { 1 },
                        maximum_total_bytes: if count { 3 } else { 2 },
                    };
                    refusal(
                        session.digest_multipart(HashAlgorithm::Sha256, &[b"abc"], limits),
                        RejectionReason::ClassicalSignatures(if count {
                            ClassicalSignaturesRejection::CryptoInputCeilings
                        } else {
                            ClassicalSignaturesRejection::CryptoTotalCeiling
                        }),
                    )?;
                }
                "hmac_key_type" => {
                    refusal(
                        session.generate_symmetric_key(hmac_spec(label, None)),
                        RejectionReason::SymmetricParameters(
                            SymmetricParametersRejection::HmacKeyTypeRequired,
                        ),
                    )?;
                }
                "kek_algorithm" => {
                    let key = hmac_spec(label, Some(HmacKeyType::Generic));
                    let spec = AesKeyEncryptionSpec {
                        native_protection: key.protection_request,
                        history_observation: key.history,
                        key,
                        usage: KeyTransportUsage::WrapAndUnwrap,
                    };
                    refusal(
                        session.import_aes_key_encryption_key(spec, SecretBytes::new(32)?),
                        RejectionReason::KeyTransport(KeyTransportRejection::AesKekAlgorithm),
                    )?;
                }
                _ => return Err(Failure::Input("input_guard_action")),
            }
        }
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("input_guard_dispatched"));
    }
    // An exact independent SHA-256 result demonstrates that no refused operation
    // was installed. This positive control is part of this case, not a replay of
    // another case's success.
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    let digest = match owner {
        Owner::Session(s) => s.digest_multipart(HashAlgorithm::Sha256, &[b"abc"], limits)?,
        Owner::Advanced(s) => {
            let mut ticket = s.begin_digest(HashAlgorithm::Sha256)?;
            s.digest_update(&mut ticket, b"abc", limits)?;
            match s.finish_digest(&mut ticket)? {
                OperationProgress::Digest(digest) => digest,
                _ => return Err(Failure::Oracle("guard_idle_digest_result")),
            }
        }
    };
    let expected = super::arguments::hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected {
        return Err(Failure::Oracle("guard_idle_digest_bytes"));
    }
    Ok(())
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut logged = false;
    let setup = Case::read(path).and_then(|case| {
        owner = Some(Owner::open(&module, config, case.advanced)?);
        if case.action == "hmac_key_type" {
            let Some(Owner::Session(session)) = &owner else {
                return Err(Failure::Input("ordinary_owner"));
            };
            session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            logged = true;
        }
        Ok(case)
    });
    let started = setup.is_ok();
    let body = match (&setup, &owner) {
        (Ok(case), Some(owner)) => check(&module, owner, case, &config.label),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    if logged {
        if let Some(Owner::Session(s)) = &owner {
            if let Err(e) = s.logout() {
                cleanup.push(e.into());
            }
        }
    }
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    if let Err(e) = &setup {
        outcome::record(&mut report, Phase::Setup, e)?;
    }
    if let Err(e) = &body {
        outcome::record(&mut report, Phase::Body, e)?;
    }
    for e in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, e)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "input_refusal_and_idle_owner",
            Producer::Fe11Local,
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
