// SPDX-License-Identifier: Apache-2.0
//! Context authentication on a real private key and a retained single-sign ticket.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    rsa_known_fixture::Vector,
};
use fe11::*;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

fn import(session: &Session, vector: &Vector) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let mut template = vec![
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
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(true),
        ),
        attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
        attr(
            StandardAttribute::ALWAYS_AUTHENTICATE,
            AttributeInputValue::Boolean(true),
        ),
    ];
    let attributes = [
        StandardAttribute::MODULUS,
        StandardAttribute::PUBLIC_EXPONENT,
        StandardAttribute::PRIVATE_EXPONENT,
        StandardAttribute::PRIME_1,
        StandardAttribute::PRIME_2,
        StandardAttribute::EXPONENT_1,
        StandardAttribute::EXPONENT_2,
        StandardAttribute::COEFFICIENT,
    ];
    for (attribute, value) in attributes.into_iter().zip(&vector.key) {
        template.push(attr(attribute, AttributeInputValue::Bytes(value)));
    }
    session.create_native_object(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: 20 + vector.key.iter().map(Vec::len).sum::<usize>(),
        },
    )
}

fn check<W: Write>(
    module: &Module,
    session: &Session,
    key: &NativeObjectRef,
    vector: &Vector,
    pins: &Credentials,
    wrong_first: bool,
    guards: bool,
    missing_first: bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if missing_first {
        let mut unauthenticated = session.begin_native_sign_single(
            key,
            vector.signature()?,
            SignatureOutputPlan::Buffer { capacity: 256 },
            256,
        )?;
        match session.finish_signature_single(
            &mut unauthenticated,
            &vector.input,
            None,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: vector.input.len(),
            },
        ) {
            Err(
                error @ Error::Native {
                    function: "C_Sign",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_USER_NOT_LOGGED_IN as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("signature_without_context_authentication")),
        }
        // No cleanup/reopen substitutes for the subsequent same-session control.
        drop(unauthenticated);
    }
    if guards {
        let before = module.call_counts()?;
        let result = session.login_as(
            LoginRole::VendorExtension(fe11_sys::CKU_CONTEXT_SPECIFIC as u64),
            SecretPin::new(pins.user.to_vec()),
        );
        if !matches!(
            result,
            Err(Error::Rejected(RejectionReason::ModuleLifecycle(
                ModuleLifecycleRejection::StandardLoginRoleRequiresDedicatedVariant
            )))
        ) || module.call_counts()? != before
        {
            return Err(Failure::Oracle("standard_role_requires_dedicated_variant"));
        }
        report
            .observation(
                Phase::Body,
                "standard_role_local_refusal",
                Producer::TestOracle,
                Observation::Boolean(true),
            )
            .map_err(|_| Failure::Input("report_write"))?;
    }
    let mut ticket = session.begin_native_sign_single(
        key,
        vector.signature()?,
        SignatureOutputPlan::Buffer { capacity: 256 },
        256,
    )?;
    if wrong_first {
        let mut wrong = pins.user.to_vec();
        let byte = wrong.first_mut().ok_or(Failure::Input("user_pin_empty"))?;
        *byte = if *byte == b'0' { b'1' } else { b'0' };
        match session
            .authenticate_context(&ticket, ContextAuthentication::login(SecretPin::new(wrong)))
        {
            Err(
                error @ Error::Native {
                    function: "C_Login",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_PIN_INCORRECT as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("incorrect_context_pin_accepted")),
        }
    }
    session.authenticate_context(
        &ticket,
        ContextAuthentication::login(SecretPin::new(pins.user.to_vec())),
    )?;
    if session.info()?.state != fe11_sys::CKS_RW_USER_FUNCTIONS as u64 {
        return Err(Failure::Oracle("context_login_changed_session_role"));
    }
    match session.finish_signature_single(
        &mut ticket,
        &vector.input,
        None,
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: vector.input.len(),
        },
    )? {
        OperationProgress::NativeSignature(signature) => {
            if vector.randomized {
                if signature.as_bytes().len() != 256 {
                    return Err(Failure::Oracle("context_signature_width"));
                }
                // Only a signature made with the public fixture key is written.
                // The driver independently verifies it before case admission.
                let mut options = OpenOptions::new();
                options.create_new(true).write(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options
                    .open("public-context-signature.bin")
                    .map_err(|_| Failure::Input("context_output_create"))?;
                file.write_all(signature.as_bytes())
                    .and_then(|()| file.flush())
                    .map_err(|_| Failure::Input("context_output_write"))?;
            } else if signature.as_bytes() != vector.expected {
                return Err(Failure::Oracle("context_signature_known_answer"));
            }
        }
        _ => return Err(Failure::Oracle("context_signature_not_completed")),
    }
    if session.info()?.state != fe11_sys::CKS_RW_USER_FUNCTIONS as u64 {
        return Err(Failure::Oracle("context_sign_changed_session_role"));
    }
    if guards {
        // Finishing consumed this real ticket; a new context login must not
        // reuse it, and no native authentication call may be issued.
        let before = module.call_counts()?;
        let result = session.authenticate_context(
            &ticket,
            ContextAuthentication::login(SecretPin::new(pins.user.to_vec())),
        );
        if !matches!(
            result,
            Err(Error::Rejected(RejectionReason::Authentication(
                AuthenticationRejection::ForeignOrConsumedOperationTicket
            )))
        ) || module.call_counts()? != before
        {
            return Err(Failure::Oracle("consumed_context_ticket_local_refusal"));
        }
        report
            .observation(
                Phase::Body,
                "consumed_context_ticket_local_refusal",
                Producer::TestOracle,
                Observation::Boolean(true),
            )
            .map_err(|_| Failure::Input("report_write"))?;
    }
    report
        .observation(
            Phase::Body,
            if vector.randomized {
                "context_signature_for_independent_verification"
            } else {
                "context_signature_known_answer"
            },
            Producer::Fe11Local,
            Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mode: &str,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut key = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let vector = Vector::read(path)?;
        let pss = mode == "context-pss-login";
        if vector.randomized != pss || vector.action != "sign" || vector.expected.len() != 256 {
            return Err(Failure::Input("context_signature_fixture"));
        }
        if pss
            && !matches!(
                vector.signature()?,
                NativeSignatureParameters::RsaPss {
                    algorithm: NativePssAlgorithm::SHA256_RSA_PKCS_PSS,
                    hash,
                    mgf,
                    salt_bytes: 32,
                } if hash == fe11_sys::CKM_SHA256 as u64 && mgf == fe11_sys::CKG_MGF1_SHA256 as u64
            )
        {
            return Err(Failure::Input("context_pss_parameters"));
        }
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        let session = session.as_ref().ok_or(Failure::Input("context_session"))?;
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        key = Some(import(session, &vector)?);
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&session, &key) {
                (Some(session), Some(key)) => check(
                    &module,
                    session,
                    key,
                    &vector,
                    pins,
                    mode == "context-wrong-pin",
                    mode == "context-local-guards",
                    matches!(mode, "context-missing-login" | "context-pss-login"),
                    &mut report,
                ),
                _ => Err(Failure::Input("context_setup")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if let Some(key) = &key {
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
    drop(key);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    report.finish(
        if setup_result.is_ok() {
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
