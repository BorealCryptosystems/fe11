// SPDX-License-Identifier: Apache-2.0
//! A contradictory class or key type is the sole mutation of a valid request.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    generation_fixture::{self, Fixture, Generator, Value},
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    num::NonZeroUsize,
    path::Path,
};

fn check<W: Write>(
    session: &Session,
    fixture: &mut Fixture,
    key_type_mismatch: bool,
    objects: &mut Option<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let attribute = if key_type_mismatch {
        StandardAttribute::KEY_TYPE
    } else {
        StandardAttribute::CLASS
    };
    let field = fixture
        .public
        .iter_mut()
        .find(|field| field.attribute == attribute)
        .ok_or(Failure::Input("generation_control_attribute"))?;
    let original = match field.value {
        Value::Unsigned(value) => value,
        _ => return Err(Failure::Input("generation_control_attribute")),
    };
    let replacement = if key_type_mismatch {
        // Both replacements are standard key types. The original generator and
        // every other public/private attribute remain unchanged.
        if original == fe11_sys::CKK_AES as u64 {
            fe11_sys::CKK_GENERIC_SECRET as u64
        } else {
            fe11_sys::CKK_AES as u64
        }
    } else {
        if original == fe11_sys::CKO_DATA as u64 {
            return Err(Failure::Input("generation_control_class"));
        }
        fe11_sys::CKO_DATA as u64
    };
    field.value = Value::Unsigned(replacement);
    let public: Vec<_> = fixture.public.iter().map(|f| f.input()).collect();
    let private: Vec<_> = fixture.private.iter().map(|f| f.input()).collect();
    let public_request = generation_fixture::request(&public, &fixture.public);
    let (result, function) = match fixture.generator {
        Generator::Single(generator) => (
            session
                .generate_native_key(generator, public_request)
                .map(|created| created.map(|_| ())),
            "C_GenerateKey",
        ),
        Generator::Pair(generator) => (
            session
                .generate_native_key_pair(
                    generator,
                    public_request,
                    generation_fixture::request(&private, &fixture.private),
                )
                .map(|created| created.map(|_| ())),
            "C_GenerateKeyPair",
        ),
    };
    match result {
        Err(error @ Error::Native { .. }) if matches!(&error,Error::Native{function:actual,code,..}if *actual==function && *code==fe11_sys::CKR_TEMPLATE_INCONSISTENT as u64) => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(created) => {
            // Even an unexpected success keeps its cleanup owners. A descriptive
            // observation cannot turn a successful native creation into a refusal.
            *objects = Some(created.objects);
            Err(Failure::Oracle(if key_type_mismatch {
                "contradictory_generation_key_type_accepted"
            } else {
                "contradictory_generation_class_accepted"
            }))
        }
    }
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut objects = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<(Fixture, bool), Failure> {
        let fixture = Fixture::read_negative(path, config.label.as_bytes())?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("generation_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(fixture)
    })();
    let started = setup.is_ok();
    let (setup, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok((mut fixture, key_type_mismatch)) => (
            Ok(()),
            check(
                session.as_ref().unwrap(),
                &mut fixture,
                key_type_mismatch,
                &mut objects,
                &mut report,
            ),
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if let Some(objects) = &objects {
            for object in objects.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        // Search the exact namespace after refusal, independently of returned
        // output handles. Do not infer non-creation from an empty Rust result.
        let template = [AttributeInput {
            attribute: StandardAttribute::LABEL.into(),
            value: AttributeInputValue::Bytes(config.label.as_bytes()),
        }];
        let found = session.find_native_objects(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: 1,
                maximum_value_bytes: config.label.len(),
            },
            SearchPlan {
                maximum_objects: Some(2),
                batch_size: NonZeroUsize::new(2).unwrap(),
            },
        );
        match found {
            Ok(found) => {
                if !found.as_slice().is_empty() {
                    cleanup.push(Failure::Oracle("generation_refusal_left_objects"));
                }
                for object in found.as_slice() {
                    if let Err(error) = session.destroy_native_object(object) {
                        cleanup.push(error.into());
                    }
                }
            }
            Err(error) => cleanup.push(error.into()),
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
    drop(objects);
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
