// SPDX-License-Identifier: Apache-2.0
//! Native Init refusal, absent owner, and explicit fresh-operation recovery.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    digest_fixture::{Fixture, State},
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
    expected: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("fixture_read"))?;
    if bytes.len() > 256 {
        return Err(Failure::Input("fixture_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 2
        || !matches!(
            fields[0],
            "init" | "take" | "cancel" | "login" | "logout" | "close"
        )
    {
        return Err(Failure::Input("digest_refused_fields"));
    }
    let expected = hex(fields[1], 32).map_err(Failure::Input)?;
    if expected.len() != 32 {
        return Err(Failure::Input("digest_width"));
    }
    Ok(Case {
        action: fields[0].into(),
        expected,
    })
}

fn native<T, W: Write>(
    result: Result<T>,
    function: &'static str,
    code: u64,
    phase: Phase,
    no_effect: bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code: actual_code,
                may_have_effect,
            },
        ) if actual == function && actual_code == code && (!no_effect || !may_have_effect) => {
            outcome::record(report, phase, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("digest_expected_native_refusal")),
    }
}

fn fresh(fixture: &mut Fixture, case: &Case) -> std::result::Result<(), Failure> {
    fixture.ticket = Some(
        fixture
            .subject()?
            .begin_native_digest(NativeDigestAlgorithm::Sha256)?,
    );
    fixture.update(
        b"abc",
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
    )?;
    fixture.finish()?;
    fixture.check_output(&case.expected)
}

fn action<W: Write>(
    fixture: &mut Fixture,
    case: &Case,
    config: &Configuration,
    pins: &Credentials,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match case.action.as_str() {
        "init" => (), // The explicit fresh Init below is this action.
        "take" => match fixture.subject()?.take_digest_ticket() {
            Err(Error::Rejected(RejectionReason::OperationOwnership(
                OperationOwnershipRejection::OperationAbsent,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("refused_digest_created_ticket")),
        },
        "cancel" => {
            let result = fixture.subject()?.cancel(CancellationFlags::DIGEST);
            if matches!(config.interface, InterfaceSelection::Legacy240) {
                match result {
                    Err(Error::Rejected(RejectionReason::Cancellation(
                        CancellationRejection::CSessionCancelUnavailable,
                    ))) => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("unavailable_cancel_accepted")),
                }
            } else {
                native(
                    result,
                    "C_SessionCancel",
                    fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64,
                    Phase::Body,
                    true,
                    report,
                )?;
            }
        }
        "login" => native(
            fixture
                .peer
                .as_ref()
                .ok_or(Failure::Input("digest_peer"))?
                .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec())),
            "C_Login",
            fe11_sys::CKR_USER_ALREADY_LOGGED_IN as u64,
            Phase::Body,
            false,
            report,
        )?,
        "logout" => {
            let peer = fixture.peer.as_ref().ok_or(Failure::Input("digest_peer"))?;
            peer.logout()?;
            fixture.logged_in = false;
            if peer.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("digest_logout_role"));
            }
        }
        "close" => fixture.close_subject()?,
        _ => return Err(Failure::Input("digest_refused_action")),
    }
    // A refused Init yielded no ticket. This explicitly new operation proves
    // usability; it never pretends to resume the rejected initialization.
    if !fixture.closed {
        fresh(fixture, case)?;
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
    let mut fixture = Fixture::empty();
    let setup: std::result::Result<Case, Failure> = (|| {
        let case = read(path)?;
        fixture.prepare(&module, config, pins, State::Absent)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        let available = module.mechanism_ids(token.slot)?;
        // Select once from discovered absence. Never retry another algorithm
        // after a native result and never infer absence from a provider name.
        let algorithm = NativeDigestAlgorithm::ALL
            .into_iter()
            .find(|algorithm| !available.contains(&algorithm.mechanism_number()))
            .ok_or(Failure::Input("absent_digest_mechanism_unavailable"))?;
        native(
            fixture.subject()?.begin_native_digest(algorithm),
            "C_DigestInit",
            fe11_sys::CKR_MECHANISM_INVALID as u64,
            Phase::Setup,
            false,
            &mut report,
        )?;
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Ok(case) => action(&mut fixture, case, config, pins, &mut report),
        Err(_) => Ok(()),
    };
    let mut cleanup = fixture.cleanup();
    if let Ok(case) = &setup {
        if fixture.published.is_some() {
            if let Err(error) = fixture.check_output(&case.expected) {
                cleanup.push(error);
            }
        }
    }
    drop(fixture);
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
            "digest_refusal_owner_and_fresh_operation",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup.is_ok() {
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
