// SPDX-License-Identifier: Apache-2.0
//! One wrapping-permission mutation after an exact native plaintext control.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    key_wrap_fixture, module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    rsa_unwrap_negative::Case,
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

#[path = "rsa_wrap_label.rs"]
mod label;

fn control(
    session: &Session,
    key: &NativeObjectRef,
    target: &NativeObjectRef,
    private: &NativeObjectRef,
    case: &Case,
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let envelope = session.wrap_native_key(key, target, case.parameters(), case.envelope.len())?;
    if envelope.as_bytes().len() != case.envelope.len() {
        return Err(Failure::Oracle("rsa_wrap_control_length"));
    }
    let attributes = key_wrap_fixture::template();
    let created = session.unwrap_native_key(
        private,
        envelope.as_bytes(),
        case.parameters(),
        ManagedClass::SecretKey,
        GenerationTemplate {
            attributes: &attributes,
            limits: key_wrap_fixture::limits(attributes.len(), 0),
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        },
    )?;
    *retained = Some(created.objects);
    created.observation?;
    if created.remainder.is_some() {
        return Err(Failure::Oracle("rsa_wrap_control_remainder"));
    }
    let objects = retained
        .as_ref()
        .ok_or(Failure::Input("rsa_wrap_control_owner"))?
        .as_slice();
    if objects.len() != 1 {
        return Err(Failure::Oracle("rsa_wrap_control_count"));
    }
    let value = session.read_flat_attribute(
        &objects[0],
        StandardAttribute::VALUE,
        FlatAttributeReadPlan::Buffer {
            capacity: case.plain.len(),
        },
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("rsa_wrap_control_read"));
    }
    match value.value {
        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == case.plain => Ok(()),
        _ => Err(Failure::Oracle("rsa_wrap_control_plaintext")),
    }
}

/// Verify the effective prerequisites independently of the wrapping result.
/// A trusted-only or non-extractable target would test a different refusal.
fn private_class_refusal<W: Write>(
    session: &Session,
    wrapping: &NativeObjectRef,
    target: &NativeObjectRef,
    case: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    use fe11_sys::{CKO_PRIVATE_KEY, CKR_KEY_NOT_WRAPPABLE};
    let class = CKO_PRIVATE_KEY.to_ne_bytes();
    for (key, attribute, expected) in [
        (target, StandardAttribute::CLASS, class.as_slice()),
        (target, StandardAttribute::EXTRACTABLE, &[1][..]),
        (target, StandardAttribute::WRAP_WITH_TRUSTED, &[0][..]),
        (wrapping, StandardAttribute::WRAP, &[1][..]),
    ] {
        let result = session.read_flat_attribute(
            key,
            attribute,
            FlatAttributeReadPlan::Buffer {
                capacity: expected.len(),
            },
        )?;
        if result.calls != (AttributeReadCalls::Direct { code: 0 })
            || !matches!(result.value, FlatAttributeValue::Available(v) if v.as_bytes()==expected)
        {
            return Err(Failure::Oracle("rsa_wrap_class_prerequisite"));
        }
    }
    match session.wrap_native_key(wrapping, target, case.parameters(), case.key[0].len()) {
        Err(
            error @ Error::Native {
                function: "C_WrapKey",
                code,
                ..
            },
        ) if code == CKR_KEY_NOT_WRAPPABLE as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("secret_only_mechanism_wrapped_private_key")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    match Case::read_wrapping(path) {
        Ok(case) if case.label_owner.is_some() => label::execute(module, config, case, report),
        parsed => execute_standard(module, config, parsed, pins, report),
    }
}

fn execute_standard<W: Write>(
    module: Module,
    config: &Configuration,
    parsed: std::result::Result<Case, Failure>,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    // Every native creation is retained immediately, including partial setup.
    let mut keys = Vec::new();
    let mut recovered = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = parsed?;
        owner = Some(Owner::open(&module, config, false)?);
        let o = owner.as_ref().ok_or(Failure::Input("rsa_wrap_owner"))?;
        if case.algorithm == "rsa_aes" {
            let Owner::Session(session) = o else {
                return Err(Failure::Input("rsa_wrap_owner"));
            };
            session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        }
        keys.push(o.import_rsa_public_usage_enabled(
            &case.key[0],
            &case.key[1],
            StandardAttribute::WRAP,
            true,
        )?);
        if let Some(target) = &case.private_target {
            keys.push(o.import_rsa_private(target, StandardAttribute::EXTRACTABLE)?);
            return Ok(case);
        }
        keys.push(o.import_rsa_public_usage_enabled(
            &case.key[0],
            &case.key[1],
            StandardAttribute::WRAP,
            false,
        )?);
        keys.push(o.import_rsa_private(&case.key, StandardAttribute::UNWRAP)?);
        keys.push(key_wrap_fixture::import_target(o, &case.plain)?);
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = &owner else {
                return Err(Failure::Input("rsa_wrap_owner"));
            };
            if case.private_target.is_some() {
                let [key, private] = keys.as_slice() else {
                    return Err(Failure::Input("rsa_wrap_class_objects"));
                };
                return private_class_refusal(session, key, private, case, &mut report);
            }
            let [key, denied, private, target] = keys.as_slice() else {
                return Err(Failure::Input("rsa_wrap_keys"));
            };
            control(session, key, target, private, case, &mut recovered)?;
            match session.wrap_native_key(denied, target, case.parameters(), case.envelope.len()) {
                Err(
                    error @ Error::Native {
                        function: "C_WrapKey",
                        code,
                        ..
                    },
                ) if code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
                Ok(_) => Err(Failure::Oracle("rsa_wrap_permission_ignored")),
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        if let Some(set) = &recovered {
            for object in set.as_slice() {
                if let Err(error) = key_wrap_fixture::destroy(o, object) {
                    cleanup.push(error.into());
                }
            }
        }
        for object in &keys {
            if let Err(error) = key_wrap_fixture::destroy(o, object) {
                cleanup.push(error.into());
            }
        }
    }
    drop(recovered);
    drop(keys);
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
