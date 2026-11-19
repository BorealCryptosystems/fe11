// SPDX-License-Identifier: Apache-2.0
//! Session state, explicit ownership and caller-selected cleanup policies.
use super::{
    configuration::{select_token, Budgets, Configuration},
    credentials::Credentials,
    module_controls,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn require(value: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("session_fixture_open"))?
        .take(65)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("session_fixture_read"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("session_fixture_fields"))?;
    if !matches!(
        action,
        "ro" | "rw"
            | "states"
            | "explicit_close"
            | "closed_reference"
            | "drop_close"
            | "drop_keep_open"
            | "reopen"
            | "capacity"
            | "close_all_owned"
    ) {
        return Err(Failure::Input("session_fixture_action"));
    }
    Ok(action.into())
}

fn info(
    session: &Session,
    slot: u64,
    state: CK_STATE,
    rw: bool,
) -> std::result::Result<(), Failure> {
    let info = session.info()?;
    require(
        info.slot == slot
            && info.state == state as u64
            && info.flags == (CKF_SERIAL_SESSION | if rw { CKF_RW_SESSION } else { 0 }) as u64,
        "session_information",
    )
}

fn usage(module: &Module, total: usize, rw: usize) -> std::result::Result<(), Failure> {
    let status = module.resource_status()?;
    let expected = SessionUsage {
        total,
        read_write: rw,
        open: total,
        ..SessionUsage::default()
    };
    require(status.usage == expected, "session_credit_state")?;
    if total == 0 {
        require(status.tokens.is_empty(), "released_token_credit")?;
    }
    Ok(())
}

fn close(session: &mut Option<Session>) -> std::result::Result<(), Failure> {
    if let Some(value) = session.as_ref() {
        value.close()?;
    }
    drop(session.take());
    Ok(())
}

fn closed<T>(result: fe11::Result<T>) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::SessionLifecycle(
            SessionLifecycleRejection::SessionClosed,
        ))) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("closed_session_accepted")),
    }
}

fn check(
    module: &Module,
    context: &TokenContext,
    slot: u64,
    action: &str,
    pins: &Credentials,
    first: &mut Option<Session>,
    second: &mut Option<Session>,
    abandoned: &mut bool,
) -> std::result::Result<(), Failure> {
    let rw = action != "ro";
    usage(module, 0, 0)?;
    *first = Some(context.open_session(rw)?);
    usage(module, 1, usize::from(rw))?;
    let session = first.as_ref().ok_or(Failure::Input("session_owner"))?;
    info(
        session,
        slot,
        if rw {
            CKS_RW_PUBLIC_SESSION
        } else {
            CKS_RO_PUBLIC_SESSION
        },
        rw,
    )?;
    match action {
        "ro" | "rw" => (),
        "states" => {
            session.login_as(
                LoginRole::SecurityOfficer,
                SecretPin::new(pins.officer.to_vec()),
            )?;
            info(session, slot, CKS_RW_SO_FUNCTIONS, true)?;
            session.logout()?;
            info(session, slot, CKS_RW_PUBLIC_SESSION, true)?;
            session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            info(session, slot, CKS_RW_USER_FUNCTIONS, true)?;
            session.logout()?;
            info(session, slot, CKS_RW_PUBLIC_SESSION, true)?;
            close(first)?;
            *first = Some(context.open_session(false)?);
            let session = first.as_ref().ok_or(Failure::Input("ro_session_owner"))?;
            info(session, slot, CKS_RO_PUBLIC_SESSION, false)?;
            session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            info(session, slot, CKS_RO_USER_FUNCTIONS, false)?;
            session.logout()?;
            info(session, slot, CKS_RO_PUBLIC_SESSION, false)?;
        }
        "explicit_close" | "closed_reference" => {
            session.close()?;
            let closed_owner = first.take().ok_or(Failure::Input("closed_session_owner"))?;
            if action == "closed_reference" {
                let before = module.call_counts()?;
                closed(closed_owner.info())?;
                closed(closed_owner.close())?;
                require(before == module.call_counts()?, "closed_session_dispatched")?;
            }
            drop(closed_owner);
            usage(module, 0, 0)?;
        }
        "drop_close" => {
            first
                .as_mut()
                .ok_or(Failure::Input("session_owner"))?
                .set_drop_behavior(SessionDropBehavior::Close);
            drop(first.take());
            usage(module, 0, 0)?;
        }
        "drop_keep_open" => {
            first
                .as_mut()
                .ok_or(Failure::Input("session_owner"))?
                .set_drop_behavior(SessionDropBehavior::KeepOpen);
            let before = module.call_counts()?;
            // KeepOpen transfers no deferred-close request. Recovery remains
            // explicit and is also retained as cleanup if an assertion fails.
            *abandoned = true;
            drop(first.take());
            require(before == module.call_counts()?, "keep_open_drop_dispatched")?;
            usage(module, 1, 1)?;
            require(module.reap_sessions(1)? == 0, "keep_open_was_deferred")?;
            require(before == module.call_counts()?, "keep_open_reap_dispatched")?;
            usage(module, 1, 1)?;
            context.begin_drain()?.recover_sessions()?;
            *abandoned = false;
            usage(module, 0, 0)?;
        }
        "reopen" | "capacity" => {
            if action == "capacity" {
                let before = module.call_counts()?;
                match context.open_session(true) {
                    Err(Error::Rejected(RejectionReason::SessionAccounting(
                        SessionAccountingRejection::SessionLimit,
                    ))) => (),
                    Err(error) => return Err(error.into()),
                    Ok(value) => {
                        *second = Some(value);
                        return Err(Failure::Oracle("session_capacity_not_applied"));
                    }
                }
                require(
                    before == module.call_counts()?,
                    "session_capacity_dispatched",
                )?;
                usage(module, 1, 1)?;
            }
            close(first)?;
            usage(module, 0, 0)?;
            *first = Some(context.open_session(true)?);
            let session = first.as_ref().ok_or(Failure::Input("reopened_session"))?;
            info(session, slot, CKS_RW_PUBLIC_SESSION, true)?;
            // No assertion is made about numeric native handle reuse.
            super::module_lifecycle::control(session)?;
        }
        "close_all_owned" => {
            *second = Some(context.open_session(false)?);
            usage(module, 2, 1)?;
            let drain = context.begin_drain()?;
            drain.close_session(session)?;
            drop(first.take());
            drain.close_session(second.as_ref().ok_or(Failure::Input("second_session"))?)?;
            drop(second.take());
            usage(module, 0, 0)?;
        }
        _ => return Err(Failure::Input("session_contract_action")),
    }
    Ok(())
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let setup = (|| -> std::result::Result<(String, TokenContext, u64), Failure> {
        let action = read(path)?;
        let mut budgets = Budgets::ordinary();
        if action == "capacity" {
            budgets.sessions = 1;
        }
        module = Some(config.open(&budgets)?);
        let m = module.as_ref().ok_or(Failure::Input("session_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("session_token"))?;
        Ok((action, m.select(&token)?, token.slot))
    })();
    let mut first = None;
    let mut second = None;
    let mut abandoned = false;
    let body = match (&setup, &module) {
        (Ok((action, context, slot)), Some(m)) => check(
            m,
            context,
            *slot,
            action,
            pins,
            &mut first,
            &mut second,
            &mut abandoned,
        ),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    for session in [&mut first, &mut second] {
        if let Err(error) = close(session) {
            cleanup.push(error);
        }
    }
    if abandoned {
        if let Ok((_, context, _)) = &setup {
            if let Err(error) = context
                .begin_drain()
                .and_then(|permit| permit.recover_sessions())
            {
                cleanup.push(error.into());
            }
        }
    }
    if let Some(m) = &module {
        if let Err(error) = usage(m, 0, 0) {
            cleanup.push(error);
        }
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
