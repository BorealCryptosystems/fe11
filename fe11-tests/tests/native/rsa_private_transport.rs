// SPDX-License-Identifier: Apache-2.0
//! Unwrap an independently encoded RSA private key, prove its identity with a
//! deterministic signature, and vary only the transport key's usage permission.
use crate::{
    arguments::Arguments,
    credentials::Credentials,
    key_wrap_fixture, module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    rsa_unwrap_negative::Case,
};
use fe11::*;
use std::io::{self, Write};

pub(super) fn private_template() -> [AttributeInput<'static>; 5] {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(false),
        ),
        attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
        attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(true),
        ),
    ]
}

fn unwrap(
    session: &Session,
    transport: &NativeObjectRef,
    case: &Case,
) -> fe11::Result<CreatedObjects<NativeUnwrappedObject>> {
    let attributes = private_template();
    session.unwrap_native_key(
        transport,
        &case.envelope,
        case.parameters(),
        ManagedClass::PrivateKey,
        GenerationTemplate {
            attributes: &attributes,
            limits: key_wrap_fixture::limits(attributes.len(), 16),
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        },
    )
}

pub(super) fn execute<W: Write>(
    module: Module,
    args: &Arguments,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut transport = Vec::new();
    let mut recovered = Vec::new();
    let wrapping = args.mode == "rsa-aes-private-wrap";
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read_private_transport(&args.vector)?;
        owner = Some(Owner::open(&module, &args.config, false)?);
        let Some(o @ Owner::Session(session)) = &owner else {
            return Err(Failure::Input("private_unwrap_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        transport.push(o.import_rsa_private_usage(&case.key, StandardAttribute::UNWRAP, true)?);
        if wrapping {
            for enabled in [true, false] {
                transport.push(o.import_rsa_public_usage_enabled(
                    &case.key[0],
                    &case.key[1],
                    StandardAttribute::WRAP,
                    enabled,
                )?);
            }
        } else {
            transport.push(o.import_rsa_private_usage(
                &case.key,
                StandardAttribute::UNWRAP,
                false,
            )?);
        }
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = &owner else {
                return Err(Failure::Input("private_unwrap_session"));
            };
            let enabled = transport
                .first()
                .ok_or(Failure::Input("private_unwrap_key"))?;
            let created = unwrap(session, enabled, case)?;
            recovered.push(created.objects);
            created.observation?;
            if created.remainder.is_some() {
                return Err(Failure::Oracle("unexpected_unwrap_remainder"));
            }
            let [key] = recovered[0].as_slice() else {
                return Err(Failure::Oracle("private_unwrap_count"));
            };
            let message = [b"abc".as_slice()];
            let signature = session.sign_native(
                key,
                NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
                MessageRoute::Single,
                &message,
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
                case.plain.len(),
                None,
            )?;
            if signature.as_bytes() != case.plain {
                return Err(Failure::Oracle("unwrapped_key_signature"));
            }
            if wrapping {
                let [_, wrap_key, denied] = transport.as_slice() else {
                    return Err(Failure::Input("private_wrap_keys"));
                };
                let wrapped = session.wrap_native_key(
                    wrap_key,
                    key,
                    case.parameters(),
                    case.envelope.len(),
                )?;
                if wrapped.as_bytes().len() != case.envelope.len() {
                    return Err(Failure::Oracle("private_wrap_envelope_length"));
                }
                // The independent reference decodes only this published test key.
                let mut options = std::fs::OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options
                    .open("public-wrap-ciphertext.bin")
                    .and_then(|mut f| f.write_all(wrapped.as_bytes()))
                    .map_err(|_| Failure::Input("private_wrap_reference_output"))?;
                return match session.wrap_native_key(
                    denied,
                    key,
                    case.parameters(),
                    case.envelope.len(),
                ) {
                    Err(
                        error @ Error::Native {
                            function: "C_WrapKey",
                            code,
                            ..
                        },
                    ) if code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 => {
                        outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("private_wrap_report"))
                    }
                    Err(other) => Err(other.into()),
                    Ok(_) => Err(Failure::Oracle("disabled_private_wrap_succeeded")),
                };
            }
            let [_, disabled] = transport.as_slice() else {
                return Err(Failure::Input("private_unwrap_keys"));
            };
            match unwrap(session, disabled, case) {
                Err(
                    error @ Error::Native {
                        function: "C_UnwrapKey",
                        code,
                        ..
                    },
                ) if code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("private_unwrap_report"))
                }
                Err(other) => Err(other.into()),
                Ok(unexpected) => {
                    recovered.push(unexpected.objects);
                    Err(Failure::Oracle("disabled_private_unwrap_succeeded"))
                }
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        for key in recovered
            .iter()
            .flat_map(|set| set.as_slice())
            .chain(&transport)
        {
            if let Err(error) = key_wrap_fixture::destroy(o, key) {
                cleanup.push(error.into());
            }
        }
        cleanup.extend(o.close(None));
    }
    drop(recovered);
    drop(transport);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
