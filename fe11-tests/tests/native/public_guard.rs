// SPDX-License-Identifier: Apache-2.0
//! Public metadata and input guards exercised against an actual module context.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    generation_transition_spec as generation,
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
    expected_digest: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(257)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 256 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 2
            || !matches!(
                fields[0],
                "boolean"
                    | "unsigned_array"
                    | "scalar_width"
                    | "representation"
                    | "unavailable_array"
                    | "missing_mechanism"
                    | "missing_token"
                    | "async"
                    | "async_notify"
                    | "validation"
                    | "validation-native"
                    | "kek_length"
                    | "secret_length"
                    | "digest_owner"
                    | "metadata_counts"
                    | "metadata_objects"
                    | "metadata_resources"
                    | "metadata_sessions"
                    | "metadata_policy"
                    | "standard_attribute_declaration"
                    | "digest_key_declaration"
            )
        {
            return Err(Failure::Input("guard_fields"));
        }
        let expected_digest = hex(fields[1], 32).map_err(Failure::Input)?;
        if expected_digest.len() != 32 {
            return Err(Failure::Input("guard_digest_width"));
        }
        Ok(Self {
            action: fields[0].into(),
            expected_digest,
        })
    }
}
fn refused(result: Result<()>, reason: RejectionReason) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(actual)) if actual == reason => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("public_guard_expected_refusal")),
    }
}
fn check(
    module: &Module,
    session: &Session,
    token: &TokenContext,
    case: &Case,
    label: &str,
    observation: Option<&FlatAttributeObservation>,
    ticket: &mut Option<OperationTicket>,
) -> std::result::Result<(), Failure> {
    if case.action.starts_with("metadata_")
        || matches!(
            case.action.as_str(),
            "standard_attribute_declaration" | "digest_key_declaration"
        )
    {
        return super::metadata_access::check(module, &case.action);
    }
    let before = module.call_counts()?;
    if case.action == "validation-native" {
        match session.validation_flags(0) {
            Err(Error::Native {
                function: "C_GetSessionValidationFlags",
                code,
                may_have_effect: false,
            }) if code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("validation_unexpected_native_value")),
        }
        let mut expected = before;
        *expected.entry("C_GetSessionValidationFlags").or_default() += 1;
        return if module.call_counts()? == expected {
            Ok(())
        } else {
            Err(Failure::Oracle("validation_native_call_count"))
        };
    }
    let (result, reason) = match case.action.as_str() {
        "boolean" => (
            observation
                .ok_or(Failure::Input("guard_observation"))?
                .boolean()
                .map(|_| ()),
            RejectionReason::AttributeValues(
                AttributeValuesRejection::AttributeBooleanRepresentation,
            ),
        ),
        "unsigned_array" => (
            observation
                .ok_or(Failure::Input("guard_observation"))?
                .unsigned_values()
                .map(|_| ()),
            RejectionReason::AttributeValues(AttributeValuesRejection::AttributeUnsignedArrayWidth),
        ),
        "scalar_width" => (
            observation
                .ok_or(Failure::Input("guard_observation"))?
                .unsigned()
                .map(|_| ()),
            RejectionReason::AttributeValues(AttributeValuesRejection::AttributeNativeScalarWidth),
        ),
        "representation" => {
            // Caller-owned metadata exercises conversion order. It does not
            // represent an observed native read or contribute a native verdict.
            let value = FlatAttributeObservation {
                attribute: StandardAttribute::LABEL.into(),
                calls: AttributeReadCalls::Size { code: 0 },
                value: FlatAttributeValue::SizeKnown { required: 0 },
            };
            (
                value.unsigned().map(|_| ()),
                RejectionReason::AttributeValues(
                    AttributeValuesRejection::AttributeRepresentationDoesNotMatchConversion,
                ),
            )
        }
        "unavailable_array" => {
            let value = FlatAttributeObservation {
                attribute: StandardAttribute::ALLOWED_MECHANISMS.into(),
                calls: AttributeReadCalls::Direct {
                    code: fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID as u64,
                },
                value: FlatAttributeValue::Unavailable(AttributeUnavailableCause::Unsupported),
            };
            (
                value.unsigned_values().map(|_| ()),
                RejectionReason::AttributeValues(
                    AttributeValuesRejection::AttributeValueUnavailable,
                ),
            )
        }
        "missing_mechanism" => {
            let catalog = &token.capabilities().mechanisms;
            let mechanism = fe11_sys::CKM_HKDF_DERIVE as u64;
            if catalog.discovery() != &MechanismDiscovery::Complete
                || catalog.observation(&mechanism).is_some()
            {
                return Err(Failure::Oracle("guard_mechanism_prerequisite"));
            }
            (
                catalog.properties(&mechanism).map(|_| ()),
                RejectionReason::Mechanisms(MechanismsRejection::MechanismNotAnnounced),
            )
        }
        "missing_token" => {
            let mut identity = token.capabilities().identity.clone();
            // A finite discovered set cannot contain every serial below. The
            // altered identity is explicit caller input, never a native token.
            let snapshots = module.tokens();
            let mut found = false;
            for index in 0..=snapshots.len() {
                let serial = format!("{index:016x}");
                if serial.len() != 16 {
                    return Err(Failure::Input("guard_serial_width"));
                }
                identity.serial.copy_from_slice(serial.as_bytes());
                if snapshots.iter().all(|item| item.identity != identity) {
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(Failure::Input("guard_missing_identity"));
            }
            (
                module.select(&identity).map(|_| ()),
                RejectionReason::ModuleLifecycle(ModuleLifecycleRejection::TokenSelectorNotUnique),
            )
        }
        "async" => (
            token
                .open_advanced_session(true, AdvancedSessionMode::Asynchronous)
                .map(|_| ()),
            RejectionReason::OperationOwnership(
                OperationOwnershipRejection::NativeAsynchronousExecutionUnavailable,
            ),
        ),
        "async_notify" => (
            token
                .open_advanced_session_with_notify(
                    true,
                    AdvancedSessionMode::Asynchronous,
                    NotifyHandler::new(|_| NotifyDecision::Continue),
                )
                .map(|_| ()),
            RejectionReason::OperationOwnership(
                OperationOwnershipRejection::NativeAsynchronousExecutionUnavailable,
            ),
        ),
        "validation" => (
            session.validation_flags(0).map(|_| ()),
            RejectionReason::SessionLifecycle(
                SessionLifecycleRejection::CGetSessionValidationFlagsUnavailable,
            ),
        ),
        "kek_length" => {
            let key = generation::key(label);
            (
                session
                    .import_aes_key_encryption_key(
                        AesKeyEncryptionSpec {
                            native_protection: key.protection_request,
                            history_observation: generation::history(),
                            key,
                            usage: KeyTransportUsage::WrapAndUnwrap,
                        },
                        SecretBytes::new(15)?,
                    )
                    .map(|_| ()),
                RejectionReason::KeyTransport(KeyTransportRejection::AesKekMaterialLength),
            )
        }
        "secret_length" => {
            let key = generation::key(label);
            (
                session
                    .import_symmetric_key(
                        SymmetricIntroductionSpec {
                            native_protection: key.protection_request,
                            history_observation: generation::history(),
                            key,
                        },
                        SecretBytes::new(15)?,
                    )
                    .map(|_| ()),
                RejectionReason::KeyTransport(KeyTransportRejection::TransportSecretLength),
            )
        }
        "digest_owner" => (
            session.take_digest_ticket().map(|_| ()),
            RejectionReason::DigestContinuation(
                DigestContinuationRejection::DigestContinuationTicketUnavailable,
            ),
        ),
        _ => return Err(Failure::Input("guard_action")),
    };
    refused(result, reason)?;
    if module.call_counts()? != before {
        return Err(Failure::Oracle("public_guard_native_dispatch"));
    }
    if let Some(observation) = observation {
        let expected = if case.action == "boolean" { 2 } else { 1 };
        match &observation.value {
            FlatAttributeValue::Available(bytes) if bytes.as_bytes() == [expected] => (),
            _ => return Err(Failure::Oracle("guard_retained_attribute")),
        }
    }
    if case.action == "digest_owner" {
        let ticket = ticket
            .as_mut()
            .ok_or(Failure::Input("guard_digest_ticket"))?;
        session.digest_update(
            ticket,
            b"abc",
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        let digest = session.finish_native_digest(ticket)?;
        if digest.as_bytes() != case.expected_digest {
            return Err(Failure::Oracle("guard_original_digest"));
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
    let mut session = None;
    let mut object = None;
    let mut observation = None;
    let mut ticket = None;
    let setup = (|| -> std::result::Result<(Case, TokenContext), Failure> {
        let case = Case::read(path)?;
        let identity =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let token = module.select(&identity)?;
        session = Some(token.open_session(true)?);
        let owner = session.as_ref().ok_or(Failure::Input("guard_session"))?;
        if matches!(
            case.action.as_str(),
            "boolean" | "unsigned_array" | "scalar_width"
        ) {
            let value = if case.action == "boolean" { 2 } else { 1 };
            let label = [value];
            let template = [
                AttributeInput {
                    attribute: StandardAttribute::CLASS.into(),
                    value: AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
                },
                AttributeInput {
                    attribute: StandardAttribute::TOKEN.into(),
                    value: AttributeInputValue::Boolean(false),
                },
                AttributeInput {
                    attribute: StandardAttribute::PRIVATE.into(),
                    value: AttributeInputValue::Boolean(false),
                },
                AttributeInput {
                    attribute: StandardAttribute::LABEL.into(),
                    value: AttributeInputValue::Bytes(&label),
                },
            ];
            object = Some(owner.create_native_object(
                &template,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: 4,
                    maximum_value_bytes: std::mem::size_of::<fe11_sys::CK_ULONG>() + 3,
                },
            )?);
            let mut read = owner.read_flat_attribute(
                object.as_ref().ok_or(Failure::Input("guard_data_object"))?,
                StandardAttribute::LABEL,
                FlatAttributeReadPlan::Buffer { capacity: 1 },
            )?;
            if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
                return Err(Failure::Oracle("guard_native_label"));
            }
            // FlatAttributeObservation is public caller-owned metadata. These
            // bytes came from LABEL; do not claim a malformed native boolean.
            read.attribute = if case.action == "boolean" {
                StandardAttribute::TOKEN
            } else if case.action == "scalar_width" {
                StandardAttribute::CLASS
            } else {
                StandardAttribute::ALLOWED_MECHANISMS
            }
            .into();
            observation = Some(read);
        }
        if case.action == "digest_owner" {
            ticket = Some(owner.begin_native_digest(NativeDigestAlgorithm::Sha256)?);
        }
        Ok((case, token))
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Ok((case, token)) => check(
            &module,
            session.as_ref().unwrap(),
            token,
            case,
            &config.label,
            observation.as_ref(),
            &mut ticket,
        ),
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if let Some(object) = &object {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(ticket);
    drop(observation);
    drop(object);
    drop(session);
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
        report.observation(
            Phase::Body,
            "exact_public_guard_and_preserved_owner",
            Producer::TestOracle,
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
