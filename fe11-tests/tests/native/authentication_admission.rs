// SPDX-License-Identifier: Apache-2.0
//! Authentication between returned digest calls, with explicit session selection.
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
    time::{Duration, Instant},
};

struct Case {
    route: String,
    wait: bool,
    success: bool,
    expected: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("fixture_read"))?;
    if bytes.len() > 1024 {
        return Err(Failure::Input("fixture_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 4
        || !matches!(
            fields[0],
            "session"
                | "token"
                | "token-only"
                | "drain"
                | "named-session"
                | "named-token"
                | "named-drain"
        )
        || !matches!(fields[1], "immediate" | "wait")
        || !matches!(fields[2], "already" | "success")
    {
        return Err(Failure::Input("authentication_fixture"));
    }
    let expected = hex(fields[3], 32).map_err(Failure::Input)?;
    if expected.len() != 32 || (fields[0] == "token-only" && fields[2] == "success") {
        return Err(Failure::Input("authentication_dimensions"));
    }
    Ok(Case {
        route: fields[0].into(),
        wait: fields[1] == "wait",
        success: fields[2] == "success",
        expected,
    })
}

fn login(
    fixture: &Fixture,
    context: &TokenContext,
    case: &Case,
    pins: &Credentials,
) -> std::result::Result<(), Failure> {
    let pin = SecretPin::new(pins.user.to_vec());
    let name = || b"public-test-user".to_vec();
    let result = match case.route.as_str() {
        "session" => fixture
            .peer
            .as_ref()
            .ok_or(Failure::Input("login_peer"))?
            .login_as(LoginRole::User, pin),
        "named-session" => fixture
            .peer
            .as_ref()
            .ok_or(Failure::Input("login_peer"))?
            .login_user(LoginRole::User, pin, name()),
        "token" | "token-only" => context.login_as(LoginRole::User, pin),
        "named-token" => context.login_user(LoginRole::User, pin, name()),
        "drain" => context.begin_drain()?.login_as(LoginRole::User, pin),
        "named-drain" => context
            .begin_drain()?
            .login_user(LoginRole::User, pin, name()),
        _ => return Err(Failure::Input("authentication_route")),
    };
    result.map_err(Failure::from)
}

fn body<W: Write>(
    fixture: &mut Fixture,
    context: &TokenContext,
    case: &Case,
    config: &Configuration,
    pins: &Credentials,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if case.success {
        fixture
            .peer
            .as_ref()
            .ok_or(Failure::Input("login_peer"))?
            .logout()?;
        fixture.logged_in = false;
    }
    if case.route == "token-only" {
        fixture
            .peer
            .as_ref()
            .ok_or(Failure::Input("login_peer"))?
            .close()?;
        drop(fixture.peer.take());
        // The advanced session remains open, so this is not the last-session
        // close that logs the token out. Its ticket is still the original one.
    }
    let admission = if case.wait {
        ResourceAdmission::WaitUntil {
            deadline: Instant::now()
                .checked_add(Duration::from_secs(3600))
                .ok_or(Failure::Input("admission_deadline"))?,
            cancellation: AdmissionCancellation::new(),
        }
    } else {
        ResourceAdmission::Immediate
    };
    let result = with_resource_admission(admission, || login(fixture, context, case, pins));
    let named = case.route.starts_with("named-");
    let absent = named && matches!(config.interface, InterfaceSelection::Legacy240);
    if absent {
        match result {
            Err(Failure::Product(Error::Unsupported(UnsupportedReason::NativeFunction {
                function: "C_LoginUser",
            }))) => (),
            Err(error) => return Err(error),
            Ok(()) => return Err(Failure::Oracle("missing_login_user_accepted")),
        }
    } else if case.success {
        result?;
        fixture.logged_in = true;
    } else {
        let function = if named { "C_LoginUser" } else { "C_Login" };
        match result {
            Err(
                error @ Failure::Product(Error::Native {
                    function: actual,
                    code,
                    ..
                }),
            ) if actual == function && code == fe11_sys::CKR_USER_ALREADY_LOGGED_IN as u64 => {
                outcome::record(report, Phase::Body, &error)
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error),
            Ok(()) => return Err(Failure::Oracle("already_logged_in_was_success")),
        }
    }
    // PKCS11 permits successful Login or Logout to terminate existing operations.
    // The success recipe already logged out, even if LoginUser is unavailable.
    // An ordinary
    // refusal must not consume Fe11's ticket locally. Observe the native result
    // using that same ticket, without another Init or a replacement session.
    match fixture.finish() {
        Ok(()) => fixture.check_output(&case.expected)?,
        Err(
            error @ Failure::Product(Error::Native {
                function: "C_DigestFinal",
                code,
                ..
            }),
        ) if case.success && code == fe11_sys::CKR_OPERATION_NOT_INITIALIZED as u64 => {
            outcome::record(report, Phase::Body, &error)
                .map_err(|_| Failure::Input("report_write"))?;
        }
        Err(error) => return Err(error),
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
    let mut context = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        context = Some(module.select(&token)?);
        fixture.prepare(&module, config, pins, State::Initialized)?;
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body_result) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match &context {
                Some(context) => body(&mut fixture, context, &case, config, pins, &mut report),
                None => Err(Failure::Input("authentication_context")),
            },
        ),
    };
    let mut cleanup = fixture.cleanup();
    drop(fixture);
    drop(context);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body_result {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "authentication_between_digest_calls",
            Producer::Fe11Local,
            Observation::Boolean(body_result.is_ok()),
        )?;
    }
    report.finish(
        if setup_result.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body_result.is_ok() {
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
