// SPDX-License-Identifier: Apache-2.0
//! Parameterless key generation through typed and explicitly declared interfaces.
use super::super::{
    arguments::Arguments,
    configuration::select_token,
    derived_value, key_wrap_fixture, module_controls, object_fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
};

#[derive(Clone, Copy)]
enum Action {
    Aes,
    ObservationFailure,
    Chacha,
    Poly1305,
    Salsa,
    SalsaExtension,
}
impl Action {
    fn aes(self) -> bool {
        matches!(self, Self::Aes | Self::ObservationFailure)
    }
    fn chacha(self) -> bool {
        matches!(self, Self::Chacha)
    }
    fn extension(self) -> bool {
        !matches!(self, Self::Chacha | Self::Salsa | Self::Poly1305)
    }
}

pub fn execute<W: Write>(
    module: Module,
    args: &Arguments,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut retained = None;
    let setup = (|| -> std::result::Result<Action, Failure> {
        let mut text = String::new();
        File::open(&args.vector)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(65)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if text.len() > 64 {
            return Err(Failure::Input("fixture_size"));
        }
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 2
            || !matches!(f[0], "session" | "advanced")
            || !matches!(
                f[1],
                "aes-extension"
                    | "aes-observation-failure"
                    | "chacha-typed"
                    | "poly1305-typed"
                    | "salsa-typed"
                    | "salsa-extension"
            )
        {
            return Err(Failure::Input("generation_extension_fields"));
        }
        let action = match f[1] {
            "aes-extension" => Action::Aes,
            "aes-observation-failure" => Action::ObservationFailure,
            "chacha-typed" => Action::Chacha,
            "poly1305-typed" => Action::Poly1305,
            "salsa-typed" => Action::Salsa,
            "salsa-extension" => Action::SalsaExtension,
            _ => return Err(Failure::Input("generation_extension_action")),
        };
        let aes = action.aes();
        let chacha = action.chacha();
        let selector = if aes {
            fe11_sys::CKM_AES_KEY_GEN
        } else if matches!(action, Action::Poly1305) {
            fe11_sys::CKM_POLY1305_KEY_GEN
        } else if chacha {
            fe11_sys::CKM_CHACHA20_KEY_GEN
        } else {
            fe11_sys::CKM_SALSA20_KEY_GEN
        };
        let token =
            select_token(&module, &args.config.label).ok_or(Failure::Input("generation_token"))?;
        if module
            .mechanism_ids(token.slot)?
            .contains(&(selector as u64))
            != aes
        {
            return Err(Failure::Oracle("generation_capability_catalogue"));
        }
        owner = Some(Owner::open(&module, &args.config, f[0] == "advanced")?);
        Ok(action)
    })();
    let body = match (&setup, &owner) {
        (Ok(action), Some(o)) => (|| -> std::result::Result<(), Failure> {
            let aes = action.aes();
            let chacha = action.chacha();
            let extension = action.extension();
            let mut attrs = Vec::from(derived_value::template_attributes(if aes {
                16
            } else {
                32
            }));
            attrs[1].value = AttributeInputValue::Unsigned(if aes {
                fe11_sys::CKK_AES
            } else if matches!(action, Action::Poly1305) {
                fe11_sys::CKK_POLY1305
            } else if chacha {
                fe11_sys::CKK_CHACHA20
            } else {
                fe11_sys::CKK_SALSA20
            } as u64);
            if aes {
                for attribute in [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT] {
                    attrs.push(AttributeInput {
                        attribute: attribute.into(),
                        value: AttributeInputValue::Boolean(true),
                    });
                }
            }
            let observation = if matches!(action, Action::ObservationFailure) {
                // Metadata succeeds; only the later content read has a short
                // caller budget. It cannot revoke the already created object.
                let mut admission = object_fixture::public_key_options(&[]).admission;
                admission.observation.verify = false;
                admission.observation.maximum_bytes = 2;
                Some(CreationObservation {
                    admission,
                    content: ContentObservation::Observe(ContentReadPlan::Value {
                        maximum_bytes: 1,
                    }),
                })
            } else {
                None
            };
            let template = GenerationTemplate {
                attributes: &attrs,
                limits: AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: attrs.len(),
                    maximum_value_bytes: 30,
                },
                observation,
                destination: DestinationPlan {
                    search: DestinationSearchPlan::NotRequested,
                    user: DestinationUserObservation::NotRequested,
                },
            };
            let contract;
            let generator = if extension {
                let selector = if aes {
                    fe11_sys::CKM_AES_KEY_GEN
                } else {
                    fe11_sys::CKM_SALSA20_KEY_GEN
                };
                // SAFETY: these standard generators have exactly NULL/0
                // parameters, no nested pointers and no auxiliary outputs.
                contract = unsafe {
                    module.declare_mechanism_extension(
                        selector as u64,
                        (3, 0),
                        ExtensionOperation::GenerateKey,
                        false,
                    )
                }?;
                // SAFETY: the request realizes the declared NULL/0 ABI; all
                // pointer, block and output arrays are empty.
                let request = unsafe {
                    ExtensionRequest::new(
                        &contract,
                        ExtensionParameters {
                            blocks: &[],
                            pointers: &[],
                            root: None,
                            outputs: &[],
                        },
                    )
                };
                NativeKeyGeneration::Extension {
                    request,
                    class: ManagedClass::SecretKey,
                }
            } else {
                NativeKeyGeneration::Simple(if matches!(action, Action::Poly1305) {
                    KeyGenerator::POLY1305_KEY_GEN
                } else if chacha {
                    KeyGenerator::CHACHA20_KEY_GEN
                } else {
                    KeyGenerator::SALSA20_KEY_GEN
                })
            };
            let result = match o {
                Owner::Session(s) => s.generate_native_key_with_parameters(generator, template),
                Owner::Advanced(s) => s.generate_native_key_with_parameters(generator, template),
            };
            let created = match result {
                Err(
                    error @ Error::Native {
                        function: "C_GenerateKey",
                        code,
                        ..
                    },
                ) if !aes && code == fe11_sys::CKR_MECHANISM_INVALID as u64 => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
                Ok(created) => created,
            };
            retained = Some(created.objects);
            if !aes {
                return Err(Failure::Oracle("absent_generator_accepted"));
            }
            if matches!(action, Action::ObservationFailure) {
                match created.observation {
                    Err(Error::OperationCompleted {
                        function: "C_GenerateKey",
                        cause,
                    }) => {
                        let expected = matches!(
                            &*cause,
                            Error::Rejected(RejectionReason::InputBounds(
                                InputBoundsRejection::LengthBound
                            ))
                        );
                        let error = Error::OperationCompleted {
                            function: "C_GenerateKey",
                            cause,
                        };
                        if !expected {
                            return Err(error.into());
                        }
                        outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))?;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("short_content_observation_accepted")),
                }
                let output = created
                    .remainder
                    .as_ref()
                    .and_then(CreationRemainder::generation_output)
                    .ok_or(Failure::Oracle("generation_remainder_missing"))?;
                match output {
                    Ok(output) => check_output(output)?,
                    Err(_) => return Err(Failure::Oracle("generation_remainder_invalid")),
                }
            } else {
                let observed = created.observation?;
                check_output(&observed.output)?;
                if created.remainder.is_some() {
                    return Err(Failure::Oracle("generator_auxiliary_output"));
                }
            }
            let objects = retained
                .as_ref()
                .ok_or(Failure::Input("generation_ownership"))?
                .as_slice();
            if objects.len() != 1 {
                return Err(Failure::Oracle("generation_object_count"));
            }
            for (attribute, expected) in [
                (StandardAttribute::CLASS, fe11_sys::CKO_SECRET_KEY as u64),
                (StandardAttribute::KEY_TYPE, fe11_sys::CKK_AES as u64),
                (StandardAttribute::VALUE_LEN, 16),
            ] {
                let plan = FlatAttributeReadPlan::Buffer {
                    capacity: std::mem::size_of::<fe11_sys::CK_ULONG>(),
                };
                let value = match o {
                    Owner::Session(s) => s.read_flat_attribute(&objects[0], attribute, plan),
                    Owner::Advanced(s) => s.read_flat_attribute(&objects[0], attribute, plan),
                }?;
                if value.calls != (AttributeReadCalls::Direct { code: 0 })
                    || value.unsigned()? != expected
                {
                    return Err(Failure::Oracle("generated_attribute_value"));
                }
            }
            // This is a usability witness for the newly generated capability,
            // not an independent AES known-answer claim.
            let parameters = CipherParameters::Aes(AesCipherParameters::Cbc { iv: [0x24; 16] });
            let limits = InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 16,
            };
            let encrypted = o.encrypt(
                &objects[0],
                parameters,
                MessageRoute::Single,
                &[&[0x42; 16]],
                limits,
            )?;
            if encrypted.as_bytes().len() != 16 {
                return Err(Failure::Oracle("generated_cipher_length"));
            }
            let plain = o.decrypt(
                &objects[0],
                parameters,
                MessageRoute::Single,
                &[encrypted.as_bytes()],
                limits,
            )?;
            if plain.as_bytes() != [0x42; 16] {
                return Err(Failure::Oracle("generated_cipher_recovery"));
            }
            Ok(())
        })(),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let (Some(o), Some(set)) = (&owner, &retained) {
        for object in set.as_slice() {
            if let Err(e) = key_wrap_fixture::destroy(o, object) {
                cleanup.push(e.into());
            }
        }
    }
    drop(retained);
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}

fn check_output(output: &NativeGenerationOutput) -> std::result::Result<(), Failure> {
    match output {
        NativeGenerationOutput::Extension(value)
            if value.provenance() == MechanismLayoutProvenance::CallerAssertedLayout
                && value.output(0).is_none() =>
        {
            Ok(())
        }
        _ => Err(Failure::Oracle("generation_output_provenance")),
    }
}
