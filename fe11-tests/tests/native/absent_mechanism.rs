// SPDX-License-Identifier: Apache-2.0
//! Require catalogue absence and the precise native refusal, without fallback.
use super::{
    absent_mechanism_fixture::{Case, CURVE_OID, DIGEST_OID},
    configuration::{select_token, Configuration},
    credentials::Credentials,
    generation_fixture::{request, Field, Value},
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

fn generate(session: &Session, label: &[u8], created: &mut Option<CreatedObjectSet>) -> Result<()> {
    let field = |attribute, value| Field { attribute, value };
    let mut public = vec![
        field(
            StandardAttribute::CLASS,
            Value::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
        ),
        field(
            StandardAttribute::KEY_TYPE,
            Value::Unsigned(fe11_sys::CKK_GOSTR3410 as u64),
        ),
        field(
            StandardAttribute::GOSTR3410_PARAMS,
            Value::Bytes(CURVE_OID.to_vec()),
        ),
        field(
            StandardAttribute::GOSTR3411_PARAMS,
            Value::Bytes(DIGEST_OID.to_vec()),
        ),
        field(StandardAttribute::VERIFY, Value::Boolean(true)),
    ];
    let mut private = vec![
        field(
            StandardAttribute::CLASS,
            Value::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
        ),
        field(
            StandardAttribute::KEY_TYPE,
            Value::Unsigned(fe11_sys::CKK_GOSTR3410 as u64),
        ),
        field(StandardAttribute::SIGN, Value::Boolean(true)),
        field(StandardAttribute::SENSITIVE, Value::Boolean(false)),
        field(StandardAttribute::EXTRACTABLE, Value::Boolean(true)),
    ];
    for (fields, private) in [(&mut public, false), (&mut private, true)] {
        fields.push(field(StandardAttribute::TOKEN, Value::Boolean(false)));
        fields.push(field(StandardAttribute::PRIVATE, Value::Boolean(private)));
        fields.push(field(
            StandardAttribute::LABEL,
            Value::Bytes(label.to_vec()),
        ));
    }
    let p: Vec<_> = public.iter().map(Field::input).collect();
    let q: Vec<_> = private.iter().map(Field::input).collect();
    // Retain every unexpected successful creation before reporting an oracle failure.
    *created = Some(
        session
            .generate_native_key_pair(
                KeyPairGenerator::GOSTR3410_KEY_PAIR_GEN,
                request(&p, &public),
                request(&q, &private),
            )?
            .objects,
    );
    Ok(())
}

fn invoke(
    session: &Session,
    case: &Case,
    key: Option<&NativeObjectRef>,
    label: &[u8],
    created: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(Result<()>, &'static str), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: case.input.len(),
    };
    let parts = [case.input.as_slice()];
    if case.family == "digest" {
        return Ok((
            session
                .digest_native_single(NativeDigestAlgorithm::GostR3411, &case.input, limits)
                .map(|_| ()),
            "C_DigestInit",
        ));
    }
    if case.family == "pair" {
        return Ok((generate(session, label, created), "C_GenerateKeyPair"));
    }
    let key = key.ok_or(Failure::Input("absent_mechanism_key"))?;
    let result = if case.family == "mac" {
        let parameters = NativeMacParameters::GostR3411 {
            oid: Some(DIGEST_OID),
        };
        if case.sign() {
            session
                .compute_native_mac(
                    key,
                    parameters,
                    MessageRoute::Single,
                    &parts,
                    limits,
                    32,
                    None,
                )
                .map(|_| ())
        } else {
            session.verify_native_mac(
                key,
                parameters,
                MessageRoute::Single,
                &parts,
                &case.signature,
                limits,
                None,
            )
        }
    } else if case.compatible {
        if case.sign() {
            session
                .begin_native_sign_single(
                    key,
                    case.parameters(),
                    SignatureOutputPlan::Buffer { capacity: 64 },
                    64,
                )
                .map(|_| ())
        } else {
            session
                .begin_native_verify_single(key, case.parameters())
                .map(|_| ())
        }
    } else if case.sign() {
        session
            .sign_native(
                key,
                case.parameters(),
                MessageRoute::Single,
                &parts,
                limits,
                256,
                None,
            )
            .map(|_| ())
    } else {
        session.verify_native(
            key,
            case.parameters(),
            MessageRoute::Single,
            &parts,
            &case.signature,
            limits,
            None,
        )
    };
    Ok((
        result,
        if case.sign() {
            "C_SignInit"
        } else {
            "C_VerifyInit"
        },
    ))
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut created = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        if module
            .mechanism_ids(token.slot)?
            .contains(&case.mechanism())
        {
            return Err(Failure::Oracle("mechanism_must_be_absent"));
        }
        owner = Some(Owner::Session(module.select(&token)?.open_session(true)?));
        let Some(Owner::Session(session)) = owner.as_ref() else {
            return Err(Failure::Input("session_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        key = case.import(owner.as_ref().ok_or(Failure::Input("session_owner"))?)?;
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = owner.as_ref() else {
                return Err(Failure::Input("session_owner"));
            };
            let (result, function) = invoke(
                session,
                case,
                key.as_ref(),
                config.label.as_bytes(),
                &mut created,
            )?;
            match result {
                Err(
                    error @ Error::Native {
                        function: actual,
                        code,
                        ..
                    },
                ) if actual == function
                    && (code == fe11_sys::CKR_MECHANISM_INVALID as u64
                        || (case.signature_key()
                            && !case.compatible
                            && code == fe11_sys::CKR_KEY_TYPE_INCONSISTENT as u64)) =>
                {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
                Ok(()) => Err(Failure::Oracle("absent_mechanism_native_refusal")),
            }
        })(),
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(Owner::Session(session)) = owner.as_ref() {
        if let Some(objects) = created.as_ref() {
            for object in objects.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        if let Some(key) = key.as_ref() {
            if let Err(error) = session.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(created);
    drop(key);
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
        report.observation(
            Phase::Body,
            "catalogue_absence_and_native_refusal",
            Producer::Native,
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
