// SPDX-License-Identifier: Apache-2.0
//! Native permission/template refusals preserve exact valid envelopes and effects.
use super::{
    configuration::Configuration,
    key_wrap_fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
    transport_negative_fixture::Case,
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut denied = None;
    let mut target = None;
    let mut created = None;
    let mut control_created = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let o = owner.as_ref().ok_or(Failure::Input("transport_owner"))?;
        key = Some(o.import_secret_usages(
            &case.key,
            case.key_type,
            [
                (StandardAttribute::WRAP, true),
                (StandardAttribute::UNWRAP, true),
            ],
        )?);
        if case.usage {
            denied = Some(o.import_secret_usages(
                &case.key,
                case.key_type,
                [
                    (StandardAttribute::WRAP, !case.wrap),
                    (StandardAttribute::UNWRAP, case.wrap),
                ],
            )?);
        }
        if case.wrap {
            target = Some(key_wrap_fixture::import_target(o, &case.plaintext)?);
        }
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = &owner else {
                return Err(Failure::Input("transport_owner"));
            };
            let key = key.as_ref().ok_or(Failure::Input("transport_key"))?;
            // Establish that this exact envelope and complete key/template work
            // through the selected native wrapping route before its one mutation.
            if case.wrap {
                let target = target.as_ref().ok_or(Failure::Input("transport_target"))?;
                let output = session.wrap_native_key(
                    key,
                    target,
                    case.parameters(),
                    case.ciphertext.len(),
                )?;
                if output.as_bytes() != case.ciphertext {
                    return Err(Failure::Oracle("transport_control_ciphertext"));
                }
            } else {
                let attributes = key_wrap_fixture::template();
                let template = GenerationTemplate {
                    attributes: &attributes,
                    limits: key_wrap_fixture::limits(attributes.len(), 0),
                    observation: None,
                    destination: DestinationPlan {
                        search: DestinationSearchPlan::NotRequested,
                        user: DestinationUserObservation::NotRequested,
                    },
                };
                let result = session.unwrap_native_key(
                    key,
                    &case.ciphertext,
                    case.parameters(),
                    ManagedClass::SecretKey,
                    template,
                )?;
                control_created = Some(result.objects);
                result.observation?;
                let objects = control_created
                    .as_ref()
                    .ok_or(Failure::Input("transport_control_ownership"))?
                    .as_slice();
                if objects.len() != 1 || result.remainder.is_some() {
                    return Err(Failure::Oracle("transport_control_count"));
                }
                let value = session.read_flat_attribute(
                    &objects[0],
                    StandardAttribute::VALUE,
                    FlatAttributeReadPlan::Buffer {
                        capacity: case.plaintext.len(),
                    },
                )?;
                if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
                    return Err(Failure::Oracle("transport_control_value_code"));
                }
                match value.value {
                    FlatAttributeValue::Available(bytes) if bytes.as_bytes() == case.plaintext => {
                        ()
                    }
                    _ => return Err(Failure::Oracle("transport_control_plaintext")),
                }
            }
            let key = if case.usage {
                denied
                    .as_ref()
                    .ok_or(Failure::Input("denied_transport_key"))?
            } else {
                key
            };
            let result = if case.wrap {
                let target = target.as_ref().ok_or(Failure::Input("transport_target"))?;
                session
                    .wrap_native_key(key, target, case.parameters(), case.ciphertext.len())
                    .map(|_| ())
            } else {
                let mut attributes = Vec::from(key_wrap_fixture::template());
                if !case.usage {
                    match case.template_mutation.as_str() {
                        "template" => {
                            attributes.retain(|a| a.attribute != StandardAttribute::CLASS)
                        }
                        "missing-type" => {
                            attributes.retain(|a| a.attribute != StandardAttribute::KEY_TYPE)
                        }
                        "conflicting-type" => {
                            let field = attributes
                                .iter_mut()
                                .find(|a| a.attribute == StandardAttribute::KEY_TYPE)
                                .ok_or(Failure::Input("transport_key_type_missing"))?;
                            field.value = AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64);
                        }
                        "read-only" => attributes.push(AttributeInput {
                            attribute: StandardAttribute::LOCAL.into(),
                            value: AttributeInputValue::Boolean(true),
                        }),
                        _ => return Err(Failure::Input("transport_template_mutation")),
                    }
                }
                let template = GenerationTemplate {
                    attributes: &attributes,
                    limits: key_wrap_fixture::limits(attributes.len(), 0),
                    observation: None,
                    destination: DestinationPlan {
                        search: DestinationSearchPlan::NotRequested,
                        user: DestinationUserObservation::NotRequested,
                    },
                };
                session
                    .unwrap_native_key(
                        key,
                        &case.ciphertext,
                        case.parameters(),
                        ManagedClass::SecretKey,
                        template,
                    )
                    .map(|result| {
                        // Capture even unexpected creations before reporting an oracle failure.
                        created = Some(result.objects);
                    })
            };
            let function = if case.wrap {
                "C_WrapKey"
            } else {
                "C_UnwrapKey"
            };
            let expected = if case.usage {
                fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED
            } else {
                match case.template_mutation.as_str() {
                    "template" | "missing-type" => fe11_sys::CKR_TEMPLATE_INCOMPLETE,
                    "conflicting-type" => fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID,
                    "read-only" => fe11_sys::CKR_ATTRIBUTE_READ_ONLY,
                    _ => return Err(Failure::Input("transport_template_mutation")),
                }
            };
            match result {
                Err(
                    error @ Error::Native {
                        function: actual,
                        code,
                        may_have_effect,
                        ..
                    },
                ) if actual == function
                    && code == expected as u64
                    && may_have_effect == !case.wrap =>
                {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
                Ok(()) => Err(Failure::Oracle("invalid_transport_request_accepted")),
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(owner) = &owner {
        for objects in control_created.iter().chain(created.iter()) {
            for object in objects.as_slice() {
                if let Err(e) = key_wrap_fixture::destroy(owner, object) {
                    cleanup.push(e.into());
                }
            }
        }
        if let Some(target) = &target {
            if let Err(e) = key_wrap_fixture::destroy(owner, target) {
                cleanup.push(e.into());
            }
        }
        if let Some(denied) = &denied {
            if let Err(e) = key_wrap_fixture::destroy(owner, denied) {
                cleanup.push(e.into());
            }
        }
        cleanup.extend(owner.close(key.as_ref()));
    }
    drop(created);
    drop(control_created);
    drop(target);
    drop(denied);
    drop(key);
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
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if setup.is_err() {
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
