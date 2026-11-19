// SPDX-License-Identifier: Apache-2.0
//! Direct Wrap, Unwrap and Derive lifecycle with independently retained outputs.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    direct_material_fixture::Case,
    direct_material_operation::Fixture,
    key_wrap_fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation as ReportObservation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

fn prepare<W: Write>(
    f: &mut Fixture,
    module: &Module,
    config: &Configuration,
    pins: &Credentials,
    c: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    f.owner = Some(Owner::open(module, config, false)?);
    f.session()?
        .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
    f.logged = true;
    let usages = if c.route == "derive" {
        [
            (StandardAttribute::DERIVE, true),
            (StandardAttribute::ENCRYPT, false),
        ]
    } else {
        [
            (StandardAttribute::WRAP, true),
            (StandardAttribute::UNWRAP, true),
        ]
    };
    f.key = Some(
        f.owner()?
            .import_secret_usages(&c.key, fe11_sys::CKK_AES, usages)?,
    );
    if c.route == "wrap" {
        f.target = Some(key_wrap_fixture::import_target(f.owner()?, &c.input)?);
        if c.state == "REFUSED_TERMINAL" {
            f.denied_key = Some(f.owner()?.import_secret_usages(
                &c.key,
                fe11_sys::CKK_AES,
                [
                    (StandardAttribute::WRAP, false),
                    (StandardAttribute::UNWRAP, true),
                ],
            )?);
        }
    }
    match c.state.as_str() {
        "CONSUMED" => f.invoke(c, false)?,
        "REFUSED_TERMINAL" => match f.invoke(c, true) {
            Err(
                error @ Failure::Product(Error::Native {
                    function,
                    code,
                    may_have_effect,
                    ..
                }),
            ) if function == c.function()
                && code == c.refusal_code()
                && may_have_effect == (c.route != "wrap") =>
            {
                // Keep the refusal and creation uncertainty visible independently.
                outcome::record(report, Phase::Setup, &error)
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error),
            Ok(()) => return Err(Failure::Oracle("material_negative_accepted")),
        },
        "RETIRED" => f.close()?,
        _ => (),
    }
    Ok(())
}
fn closed<T>(result: std::result::Result<T, Failure>) -> std::result::Result<(), Failure> {
    match result {
        Err(Failure::Product(Error::Rejected(RejectionReason::SessionLifecycle(
            SessionLifecycleRejection::SessionClosed,
        )))) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(Failure::Oracle("closed_material_session_accepted")),
    }
}
fn action(f: &mut Fixture, module: &Module, c: &Case) -> std::result::Result<(), Failure> {
    let metadata = f.snapshot();
    let values = f.values.clone();
    let wrapped: Vec<_> = f.wrapped.iter().map(|v| v.as_bytes().to_vec()).collect();
    let calls = module.call_counts()?;
    match c.action.as_str() {
        "init" => {
            let result = f.invoke(c, false);
            if f.closed {
                closed(result)?;
            } else {
                result?;
            }
        }
        "take" => {
            if values.len() != 1
                || values[0] != c.expected
                || (c.route == "wrap" && (wrapped.len() != 1 || wrapped[0] != c.expected))
                || (c.route != "wrap" && (metadata.len() != 1 || metadata[0].0 != Some(0)))
            {
                return Err(Failure::Oracle("direct_material_owned_result"));
            }
        }
        "logout" => {
            let result = f.session()?.logout().map_err(Failure::from);
            if f.closed {
                match result {
                    Err(Failure::Product(Error::Rejected(RejectionReason::Authentication(
                        AuthenticationRejection::LogoutRequiresLiveSession,
                    )))) => (),
                    Err(error) => return Err(error),
                    Ok(()) => return Err(Failure::Oracle("closed_logout_accepted")),
                }
            } else {
                result?;
                f.logged = false;
                if f.session()?.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                    return Err(Failure::Oracle("material_logout_role"));
                }
            }
        }
        "close" => {
            let result = f.close();
            if c.state == "RETIRED" {
                closed(result)?;
            } else {
                result?;
            }
        }
        _ => return Err(Failure::Input("direct_material_action")),
    }
    if (c.action == "take" || c.state == "RETIRED") && module.call_counts()? != calls {
        return Err(Failure::Oracle("material_local_action_dispatched"));
    }
    let added = usize::from(c.action == "init" && !f.closed);
    let after = f.snapshot();
    if f.values.len() != values.len() + added
        || f.values[..values.len()] != values
        || after.len() != metadata.len() + if c.route == "wrap" { 0 } else { added }
        || after[..metadata.len()] != metadata
        || f.wrapped.len() != wrapped.len() + if c.route == "wrap" { added } else { 0 }
        || f.wrapped
            .iter()
            .zip(&wrapped)
            .any(|(a, b)| a.as_bytes() != b)
    {
        return Err(Failure::Oracle("material_replaced_owned_result"));
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
    let mut fixture = Fixture {
        owner: None,
        key: None,
        denied_key: None,
        target: None,
        created: Vec::new(),
        values: Vec::new(),
        wrapped: Vec::new(),
        closed: false,
        logged: false,
    };
    let setup = Case::read(path).and_then(|case| {
        prepare(&mut fixture, &module, config, pins, &case, &mut report)?;
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (Ok(()), action(&mut fixture, &module, &case)),
    };
    let mut cleanup = fixture.cleanup();
    drop(fixture);
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
    if started {
        report.observation(
            Phase::Body,
            "direct_material_transition_and_owned_result",
            Producer::TestOracle,
            ReportObservation::Boolean(body.is_ok()),
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
