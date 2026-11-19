// SPDX-License-Identifier: Apache-2.0
//! Edwards negatives use a successfully exercised, module-generated key pair.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    module_controls,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "edwards_generated_identity.rs"]
mod identity;
#[path = "edwards_multipart.rs"]
mod multipart;

fn boolean(attribute: StandardAttribute, value: bool) -> AttributeInput<'static> {
    AttributeInput {
        attribute: attribute.into(),
        value: AttributeInputValue::Boolean(value),
    }
}
fn template<'a>(attributes: &'a [AttributeInput<'a>], bytes: usize) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: bytes,
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}
fn limits() -> InputLimits {
    InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    }
}

fn generate_pair(
    owner: &Session,
    parameters: &[u8],
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<NativeKeyPair, Failure> {
    // The selected OID is submitted unchanged. Both native owners are retained
    // before interpreting the result; no private seed or public point is imported.
    let public = [
        boolean(StandardAttribute::TOKEN, false),
        boolean(StandardAttribute::PRIVATE, false),
        boolean(StandardAttribute::VERIFY, true),
        boolean(StandardAttribute::COPYABLE, true),
        AttributeInput {
            attribute: StandardAttribute::EC_PARAMS.into(),
            value: AttributeInputValue::Bytes(parameters),
        },
    ];
    let private = [
        boolean(StandardAttribute::TOKEN, false),
        boolean(StandardAttribute::PRIVATE, true),
        boolean(StandardAttribute::SIGN, true),
    ];
    let created = owner.generate_native_key_pair(
        KeyPairGenerator::EC_EDWARDS_KEY_PAIR_GEN,
        template(&public, 9),
        template(&private, 3),
    )?;
    // Preserve both cleanup rights before checking any observation.
    *retained = Some(created.objects);
    if created.remainder.is_some() || retained.as_ref().map_or(0, |x| x.as_slice().len()) != 2 {
        return Err(Failure::Oracle("edwards_negative_pair_count"));
    }
    Ok(created.observation?)
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut retained = None;
    let mut denied = None;
    let mut second_pair = None;
    let mut logged = false;
    let mut observe_identity = false;
    let mut multipart_sign = None;
    let setup =
        (|| -> std::result::Result<(NativeKeyPair, bool, bool, &'static [u8], usize), Failure> {
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(|_| Failure::Input("edwards_negative_open"))?
                .take(33)
                .read_to_end(&mut bytes)
                .map_err(|_| Failure::Input("edwards_negative_read"))?;
            observe_identity = matches!(bytes.as_slice(), b"identity-25519\n" | b"identity-448\n");
            multipart_sign = match bytes.as_slice() {
                b"multipart-sign\n" => Some(true),
                b"multipart-verify\n" => Some(false),
                _ => None,
            };
            let (usage, wrong_key, parameters, signature_width): (_, _, &[u8], _) =
                match bytes.as_slice() {
                    b"usage\n" => (true, false, &[6, 3, 43, 101, 112], 64),
                    b"changed\n" => (false, false, &[6, 3, 43, 101, 112], 64),
                    b"wrong-25519\n" => (false, true, &[6, 3, 43, 101, 112], 64),
                    b"wrong-448\n" => (false, true, &[6, 3, 43, 101, 113], 114),
                    b"identity-25519\n" => (false, false, &[6, 3, 43, 101, 112], 64),
                    b"identity-448\n" => (false, false, &[6, 3, 43, 101, 113], 114),
                    b"multipart-sign\n" | b"multipart-verify\n" => {
                        (false, false, &[6, 3, 43, 101, 112], 64)
                    }
                    _ => return Err(Failure::Input("edwards_negative_action")),
                };
            let token = select_token(&module, &config.label)
                .ok_or(Failure::Input("edwards_negative_token"))?;
            session = Some(module.select(&token)?.open_session(true)?);
            let owner = session
                .as_ref()
                .ok_or(Failure::Input("edwards_negative_session"))?;
            owner.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            logged = true;
            let pair = generate_pair(owner, parameters, &mut retained)?;
            Ok((pair, usage, wrong_key, parameters, signature_width))
        })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((pair, usage, wrong_key, parameters, signature_width)) = &setup else {
            return Ok(());
        };
        let owner = session
            .as_ref()
            .ok_or(Failure::Input("edwards_negative_session"))?;
        let mechanism = || NativeSignatureParameters::EdDsa(None);
        let parts: [&[u8]; 1] = [b"abc"];
        let signature = owner.sign_native(
            pair.private.native(),
            mechanism(),
            MessageRoute::Single,
            &parts,
            limits(),
            *signature_width,
            None,
        )?;
        if signature.as_bytes().len() != *signature_width {
            return Err(Failure::Oracle("edwards_negative_signature_width"));
        }
        // A successful control prevents an unrelated import or key failure from
        // making a rejection appear to validate the intended mutation.
        owner.verify_native(
            pair.public.native(),
            mechanism(),
            MessageRoute::Single,
            &parts,
            signature.as_bytes(),
            limits(),
            None,
        )?;
        if let Some(sign) = multipart_sign {
            return multipart::check(owner, pair, sign, signature.as_bytes());
        }
        let (result, function, code) = if *wrong_key {
            let other = generate_pair(owner, parameters, &mut second_pair)?;
            // Exercise the second key before using it as the negative. This
            // excludes a bad key or failed import as the reason for rejection.
            let control = owner.sign_native(
                other.private.native(),
                mechanism(),
                MessageRoute::Single,
                &parts,
                limits(),
                *signature_width,
                None,
            )?;
            if control.as_bytes().len() != *signature_width {
                return Err(Failure::Oracle("edwards_control_signature_width"));
            }
            owner.verify_native(
                other.public.native(),
                mechanism(),
                MessageRoute::Single,
                &parts,
                control.as_bytes(),
                limits(),
                None,
            )?;
            (
                owner.verify_native(
                    other.public.native(),
                    mechanism(),
                    MessageRoute::Single,
                    &parts,
                    signature.as_bytes(),
                    limits(),
                    None,
                ),
                "C_Verify",
                fe11_sys::CKR_SIGNATURE_INVALID,
            )
        } else if *usage {
            let changes = [boolean(StandardAttribute::VERIFY, false)];
            denied = Some(owner.copy_native_object(
                pair.public.native(),
                &changes,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: 1,
                    maximum_value_bytes: 1,
                },
            )?);
            let key = denied
                .as_ref()
                .ok_or(Failure::Input("edwards_negative_copy"))?;
            (
                owner.verify_native(
                    key,
                    mechanism(),
                    MessageRoute::Single,
                    &parts,
                    signature.as_bytes(),
                    limits(),
                    None,
                ),
                "C_VerifyInit",
                fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED,
            )
        } else {
            let mut changed = signature.as_bytes().to_vec();
            changed[63] ^= 1;
            (
                owner.verify_native(
                    pair.public.native(),
                    mechanism(),
                    MessageRoute::Single,
                    &parts,
                    &changed,
                    limits(),
                    None,
                ),
                "C_Verify",
                fe11_sys::CKR_SIGNATURE_INVALID,
            )
        };
        match result {
            Err(error @ Error::Native { .. }) if matches!(&error, Error::Native { function: actual, code: rv, .. } if *actual == function && *rv == code as u64) =>
            {
                outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("edwards_negative_accepted")),
        }
        // The unchanged public key and full signature must still verify after
        // either refusal, establishing that the negative is terminal.
        owner.verify_native(
            pair.public.native(),
            mechanism(),
            MessageRoute::Single,
            &parts,
            signature.as_bytes(),
            limits(),
            None,
        )?;
        if observe_identity {
            identity::check(owner, pair, parameters, *signature_width / 2, &mut report)?;
        }
        Ok(())
    })();
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let Some(owner) = &session {
        if let Some(key) = &denied {
            if let Err(error) = owner.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
        for objects in [&second_pair, &retained].into_iter().flatten() {
            for key in objects.as_slice() {
                if let Err(error) = owner.destroy_native_object(key) {
                    cleanup.push(error.into());
                }
            }
        }
        if logged {
            if let Err(error) = owner.logout() {
                cleanup.push(error.into());
            }
        }
    }
    if let Some(owner) = session {
        if let Err(error) = owner.close() {
            cleanup.push(error.into());
        }
    }
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
