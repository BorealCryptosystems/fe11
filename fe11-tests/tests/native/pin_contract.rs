// SPDX-License-Identifier: Apache-2.0
//! PIN boundaries and authentication flags on disposable, explicitly owned tokens.
use super::{
    configuration::{select_token, Budgets, Configuration},
    credentials::Credentials,
    module_controls,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use fe11_sys::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

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
        .map_err(|_| Failure::Input("pin_contract_open"))?
        .take(65)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("pin_contract_read"))?;
    let value = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("pin_contract_fields"))?;
    if !matches!(
        value,
        "init_standard"
            | "init_min_minus"
            | "init_min"
            | "init_max"
            | "init_max_plus"
            | "set_min_minus"
            | "set_min"
            | "set_max"
            | "set_max_plus"
            | "change_user"
            | "change_so"
            | "wrong_old"
            | "ro_init"
            | "ro_set"
            | "flags"
    ) {
        return Err(Failure::Input("pin_contract_action"));
    }
    Ok(value.into())
}

fn refused<W: Write>(
    result: fe11::Result<()>,
    function: &'static str,
    expected: CK_RV,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function && code == expected as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("pin_contract_report"))
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("pin_contract_refusal_missing")),
    }
}

fn fresh_context(
    module: &Module,
    config: &Configuration,
    pins: &Credentials,
) -> std::result::Result<TokenContext, Failure> {
    const LABEL: &str = "public-pin-boundary";
    require(config.label != LABEL, "pin_contract_namespace")?;
    let targets = module.administration_targets()?;
    let blank: Vec<_> = targets
        .iter()
        .filter(|t| t.capabilities().flags & CKF_TOKEN_INITIALIZED as u64 == 0)
        .collect();
    require(blank.len() == 1, "pin_contract_blank_token")?;
    // The supervisor owns this fresh token directory. Never reset an existing
    // token to obtain an uninitialized user PIN.
    module.initialize_token(blank[0], SecretPin::new(pins.officer.to_vec()), LABEL)?;
    module.refresh_tokens()?;
    let targets = module.administration_targets()?;
    let mut label = [b' '; 32];
    label[..LABEL.len()].copy_from_slice(LABEL.as_bytes());
    let initialized: Vec<_> = targets
        .iter()
        .filter(|t| {
            t.capabilities().label == label
                && t.capabilities().flags & CKF_TOKEN_INITIALIZED as u64 != 0
        })
        .collect();
    require(initialized.len() == 1, "pin_contract_new_identity")?;
    let caps = initialized[0].capabilities();
    require(
        caps.flags & CKF_USER_PIN_INITIALIZED as u64 == 0,
        "pin_contract_user_already_initialized",
    )?;
    Ok(module.select(&caps.identity)?)
}

fn modified(
    pin: &[u8],
    length: usize,
    mask: u8,
) -> std::result::Result<Zeroizing<Vec<u8>>, Failure> {
    require(
        !pin.is_empty() && length <= 4096,
        "pin_contract_input_bound",
    )?;
    // Derive disposable fixture bytes from the supervisor's generated PIN.
    // Neither these bytes nor the credential frames are written to reports.
    Ok(Zeroizing::new(
        (0..length).map(|i| pin[i % pin.len()] ^ mask).collect(),
    ))
}

fn slot_of(context: &TokenContext) -> u64 {
    context.capabilities().identity.slot
}

fn check<W: Write>(
    module: &Module,
    context: &TokenContext,
    action: &str,
    pins: &Credentials,
    session: &mut Option<Session>,
    logged_in: &mut bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let slot = slot_of(context);
    let initialize = action.starts_with("init_");
    let officer = initialize || action == "change_so";
    let role = if officer {
        LoginRole::SecurityOfficer
    } else {
        LoginRole::User
    };
    let current = if officer { &*pins.officer } else { &*pins.user };
    let active = session
        .as_ref()
        .ok_or(Failure::Input("pin_contract_session"))?;
    if action == "flags" {
        let bad = modified(&pins.user, pins.user.len(), 1)?;
        refused(
            active.login_as(LoginRole::User, SecretPin::new(bad.to_vec())),
            "C_Login",
            CKR_PIN_INCORRECT,
            report,
        )?;
        require(
            module.token_info(slot)?.flags & CKF_USER_PIN_COUNT_LOW as u64 != 0,
            "pin_count_low_not_set",
        )?;
        active.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        *logged_in = true;
        return require(
            module.token_info(slot)?.flags & CKF_USER_PIN_COUNT_LOW as u64 == 0,
            "pin_count_low_not_cleared",
        );
    }
    active.login_as(role, SecretPin::new(current.to_vec()))?;
    *logged_in = true;
    let info = module.token_info(slot)?;
    let min =
        usize::try_from(info.minimum_pin_length).map_err(|_| Failure::Input("pin_min_width"))?;
    let max =
        usize::try_from(info.maximum_pin_length).map_err(|_| Failure::Input("pin_max_width"))?;
    require(
        min > 0 && min <= max && max < 4096,
        "pin_contract_announced_bounds",
    )?;
    let length = if action.ends_with("min_minus") {
        min - 1
    } else if action.ends_with("max_plus") {
        max + 1
    } else if action.ends_with("min") {
        min
    } else if action.ends_with("max") {
        max
    } else {
        current.len()
    };
    let new = modified(if initialize { &pins.user } else { current }, length, 1)?;
    let old = modified(
        current,
        current.len(),
        if action == "wrong_old" { 2 } else { 0 },
    )?;
    let result = if initialize || action == "ro_init" {
        active.initialize_user_pin(SecretPin::new(new.to_vec()))
    } else {
        active.change_pin(SecretPin::new(old.to_vec()), SecretPin::new(new.to_vec()))
    };
    let outside = length < min || length > max;
    let rejected = outside || matches!(action, "wrong_old" | "ro_init" | "ro_set");
    if rejected {
        let expected = if outside {
            CKR_PIN_LEN_RANGE
        } else if action == "wrong_old" {
            CKR_PIN_INCORRECT
        } else if action == "ro_init" {
            CKR_USER_NOT_LOGGED_IN
        } else {
            CKR_SESSION_READ_ONLY
        };
        refused(
            result,
            if initialize || action == "ro_init" {
                "C_InitPIN"
            } else {
                "C_SetPIN"
            },
            expected,
            report,
        )?;
        require(
            module.token_info(slot)?.flags & CKF_USER_PIN_INITIALIZED as u64
                == info.flags & CKF_USER_PIN_INITIALIZED as u64,
            "pin_initialized_flag_changed_on_refusal",
        )?;
    } else {
        result?;
        require(
            module.token_info(slot)?.flags & CKF_USER_PIN_INITIALIZED as u64 != 0,
            "pin_initialized_flag_missing",
        )?;
    }
    active.logout()?;
    *logged_in = false;
    if initialize {
        if rejected {
            refused(
                active.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec())),
                "C_Login",
                CKR_USER_PIN_NOT_INITIALIZED,
                report,
            )?;
            active.login_as(
                LoginRole::SecurityOfficer,
                SecretPin::new(pins.officer.to_vec()),
            )?;
            *logged_in = true;
            active.initialize_user_pin(SecretPin::new(pins.user.to_vec()))?;
            active.logout()?;
            *logged_in = false;
        }
        let pin = if rejected { &*pins.user } else { &*new };
        active.login_as(LoginRole::User, SecretPin::new(pin.to_vec()))?;
        *logged_in = true;
    } else {
        // Reopen before validating credentials so cached login state cannot
        // satisfy the positive control after a mutation or a refusal.
        active.close()?;
        drop(session.take());
        *session = Some(context.open_session(true)?);
        let active = session
            .as_ref()
            .ok_or(Failure::Input("pin_contract_reopen"))?;
        if !rejected {
            refused(
                active.login_as(role, SecretPin::new(current.to_vec())),
                "C_Login",
                CKR_PIN_INCORRECT,
                report,
            )?;
        }
        active.login_as(
            role,
            SecretPin::new(if rejected {
                current.to_vec()
            } else {
                new.to_vec()
            }),
        )?;
        *logged_in = true;
        if action == "change_so" {
            active.logout()?;
            *logged_in = false;
            active.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            *logged_in = true;
        }
    }
    Ok(())
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut logged_in = false;
    let setup = (|| -> std::result::Result<(String, TokenContext), Failure> {
        let action = read(path)?;
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("pin_contract_module"))?;
        let context = if action.starts_with("init_") {
            fresh_context(m, config, pins)?
        } else {
            let token =
                select_token(m, &config.label).ok_or(Failure::Input("pin_contract_token"))?;
            m.select(&token)?
        };
        session = Some(context.open_session(!action.starts_with("ro_"))?);
        Ok((action, context))
    })();
    let body = match (&setup, &module) {
        (Ok((action, context)), Some(m)) => check(
            m,
            context,
            action,
            pins,
            &mut session,
            &mut logged_in,
            &mut report,
        ),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(active) = &session {
        if logged_in {
            if let Err(error) = active.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = active.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
