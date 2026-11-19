// SPDX-License-Identifier: Apache-2.0
//! InitToken SO-PIN boundaries use its distinct native error contract.
use super::{
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use fe11_sys::*;
use std::io::Write;
use zeroize::Zeroizing;

fn require(value: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

pub(super) fn check<W: Write>(
    module: &Module,
    target: &TokenAdministrationTarget,
    pins: &Credentials,
    action: &str,
    session: &mut Option<Session>,
    logged: &mut bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    const LABEL: &str = "Test Token";
    let caps = target.capabilities();
    let min = usize::try_from(caps.minimum_pin_length)
        .map_err(|_| Failure::Input("token_pin_min_width"))?;
    let max = usize::try_from(caps.maximum_pin_length)
        .map_err(|_| Failure::Input("token_pin_max_width"))?;
    require(
        min > 0 && min <= max && max < 4096 && !pins.officer.is_empty(),
        "token_pin_fixture_bound",
    )?;
    let length = match action {
        "pin_min_minus" => min - 1,
        "pin_min" => min,
        "pin_max" => max,
        "pin_max_plus" => max + 1,
        _ => return Err(Failure::Input("token_pin_action")),
    };
    let input = Zeroizing::new(
        (0..length)
            .map(|i| pins.officer[i % pins.officer.len()] ^ 1)
            .collect::<Vec<u8>>(),
    );
    let result = module.initialize_token(target, SecretPin::new(input.to_vec()), LABEL);
    let outside = length < min || length > max;
    if outside {
        match result {
            Err(
                error @ Error::Native {
                    function: "C_InitToken",
                    code,
                    ..
                },
            ) if code == CKR_PIN_INCORRECT as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("token_pin_report"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("invalid_token_pin_accepted")),
        }
        require(
            module.token_info(caps.identity.slot)?.flags & CKF_TOKEN_INITIALIZED as u64 == 0,
            "invalid_token_pin_initialized_token",
        )?;
        // Obtain a fresh observation for the separate valid-PIN control.
        // This boundary case does not prove reuse of the original target.
        module.refresh_tokens()?;
        let targets = module.administration_targets()?;
        let blank: Vec<_> = targets
            .iter()
            .filter(|t| t.capabilities().flags & CKF_TOKEN_INITIALIZED as u64 == 0)
            .collect();
        require(blank.len() == 1, "token_pin_blank_after_refusal")?;
        module.initialize_token(blank[0], SecretPin::new(pins.officer.to_vec()), LABEL)?;
    } else {
        result?;
    }
    module.refresh_tokens()?;
    let targets = module.administration_targets()?;
    let mut label = [b' '; 32];
    label[..LABEL.len()].copy_from_slice(LABEL.as_bytes());
    let selected: Vec<_> = targets
        .iter()
        .filter(|t| {
            t.capabilities().label == label
                && t.capabilities().flags & CKF_TOKEN_INITIALIZED as u64 != 0
        })
        .collect();
    require(selected.len() == 1, "token_pin_initialized_identity")?;
    let caps = selected[0].capabilities();
    require(
        caps.flags & CKF_USER_PIN_INITIALIZED as u64 == 0,
        "token_pin_user_state_changed",
    )?;
    *session = Some(module.select(&caps.identity)?.open_session(true)?);
    session
        .as_ref()
        .ok_or(Failure::Input("token_pin_session"))?
        .login_as(
            LoginRole::SecurityOfficer,
            SecretPin::new(if outside {
                pins.officer.to_vec()
            } else {
                input.to_vec()
            }),
        )?;
    *logged = true;
    Ok(())
}
