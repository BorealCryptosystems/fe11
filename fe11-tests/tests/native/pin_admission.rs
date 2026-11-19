// SPDX-License-Identifier: Apache-2.0
//! PIN mutation and refusal through ordinary sessions and token-drain permits.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
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
use zeroize::Zeroizing;

struct Case {
    drain: bool,
    initialize: bool,
    wait: bool,
    outcome: String,
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
    if fields.len() != 4
        || !matches!(fields[0], "session" | "drain")
        || !matches!(fields[1], "initialize" | "change")
        || !matches!(fields[2], "immediate" | "wait")
        || !matches!(
            fields[3],
            "success" | "wrong-role" | "wrong-old" | "cancel" | "token-block" | "module-block"
        )
        || (fields[3] == "wrong-role" && fields[1] != "initialize")
        || (fields[3] == "wrong-old" && fields[1] != "change")
        || (fields[3] == "cancel" && fields[2] != "wait")
        || (fields[3] == "token-block" && fields[0] != "session")
    {
        return Err(Failure::Input("pin_fixture"));
    }
    Ok(Case {
        drain: fields[0] == "drain",
        initialize: fields[1] == "initialize",
        wait: fields[2] == "wait",
        outcome: fields[3].into(),
    })
}

fn call(
    session: &Session,
    drain: Option<&TokenDrain>,
    case: &Case,
    old: &[u8],
    new: &[u8],
) -> fe11::Result<()> {
    let new = SecretPin::new(new.to_vec());
    if case.initialize {
        match drain {
            Some(drain) => drain.initialize_user_pin(session, new),
            None => session.initialize_user_pin(new),
        }
    } else {
        let old = SecretPin::new(old.to_vec());
        match drain {
            Some(drain) => drain.change_pin(session, old, new),
            None => session.change_pin(old, new),
        }
    }
}

fn body<W: Write>(
    module: &Module,
    context: &TokenContext,
    session: &Session,
    case: &Case,
    pins: &Credentials,
    logged_in: &mut bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut new = Zeroizing::new(pins.user.to_vec());
    let mut old = Zeroizing::new(pins.user.to_vec());
    if new.is_empty() {
        return Err(Failure::Input("empty_fixture_pin"));
    }
    new[0] ^= 1;
    if case.outcome == "wrong-old" {
        old[0] ^= 2;
    }
    // The token and module permits remain independent even when both exist.
    // All permits are dropped before the login used to verify PIN state.
    let result = {
        let token_drain = if case.drain || case.outcome == "token-block" {
            Some(context.begin_drain()?)
        } else {
            None
        };
        let _module_drain = if case.outcome == "module-block" {
            Some(module.begin_drain()?)
        } else {
            None
        };
        let cancellation = AdmissionCancellation::new();
        if case.outcome == "cancel" {
            cancellation.cancel();
        }
        let admission = if case.wait {
            ResourceAdmission::WaitUntil {
                deadline: Instant::now()
                    .checked_add(Duration::from_secs(3600))
                    .ok_or(Failure::Input("admission_deadline"))?,
                cancellation,
            }
        } else {
            ResourceAdmission::Immediate
        };
        with_resource_admission(admission, || {
            call(
                session,
                if case.drain {
                    token_drain.as_ref()
                } else {
                    None
                },
                case,
                &old,
                &new,
            )
        })
    };
    match (&*case.outcome, result) {
        ("success", Ok(())) => (),
        (
            "wrong-role",
            Err(
                error @ Error::Native {
                    function: "C_InitPIN",
                    code,
                    ..
                },
            ),
        ) if code == fe11_sys::CKR_USER_NOT_LOGGED_IN as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
        }
        (
            "wrong-old",
            Err(
                error @ Error::Native {
                    function: "C_SetPIN",
                    code,
                    ..
                },
            ),
        ) if code == fe11_sys::CKR_PIN_INCORRECT as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
        }
        ("cancel", Err(Error::AdmissionCancelled)) => (),
        (
            "token-block",
            Err(Error::Busy(BusyReason::ModuleLifecycle(ModuleLifecycleBusy::TokenDraining))),
        ) => (),
        (
            "module-block",
            Err(Error::Busy(BusyReason::LocalAdmission(LocalAdmissionBusy::ModuleDraining))),
        ) => (),
        (_, Err(error)) => return Err(error.into()),
        (_, Ok(())) => return Err(Failure::Oracle("pin_refusal_was_success")),
    }
    session.logout()?;
    *logged_in = false;
    // A real login verifies the mutation, or that the old PIN remains valid
    // after a refusal. No cached authentication observation supplies this proof.
    let selected = if case.outcome == "success" {
        &*new
    } else {
        &*pins.user
    };
    session.login_as(LoginRole::User, SecretPin::new(selected.to_vec()))?;
    *logged_in = true;
    session.logout()?;
    *logged_in = false;
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut context = None;
    let mut session = None;
    let mut logged_in = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        context = Some(module.select(&token)?);
        session = Some(
            context
                .as_ref()
                .ok_or(Failure::Input("pin_context"))?
                .open_session(true)?,
        );
        let officer = case.initialize && case.outcome != "wrong-role";
        session
            .as_ref()
            .ok_or(Failure::Input("pin_session"))?
            .login_as(
                if officer {
                    LoginRole::SecurityOfficer
                } else {
                    LoginRole::User
                },
                SecretPin::new(if officer {
                    pins.officer.to_vec()
                } else {
                    pins.user.to_vec()
                }),
            )?;
        logged_in = true;
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body_result) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match (&context, &session) {
                (Some(context), Some(session)) => body(
                    &module,
                    context,
                    session,
                    &case,
                    pins,
                    &mut logged_in,
                    &mut report,
                ),
                _ => Err(Failure::Input("pin_owner")),
            },
        ),
    };
    let mut cleanup: Vec<Failure> = Vec::new();
    if let Some(session) = &session {
        if logged_in {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
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
            "pin_mutation_and_admission",
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
