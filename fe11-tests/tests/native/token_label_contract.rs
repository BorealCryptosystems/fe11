// SPDX-License-Identifier: Apache-2.0
//! Exact fixed-width label bytes and explicit string padding on a blank token.
use super::{
    configuration::{Budgets, Configuration},
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

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<String, Failure> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("token_label_open"))?
            .take(65)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("token_label_read"))?;
        let action = text
            .strip_suffix('\n')
            .ok_or(Failure::Input("token_label_fields"))?;
        if !matches!(
            action,
            "blank"
                | "blank_stale"
                | "string0"
                | "string1"
                | "string31"
                | "string32"
                | "string33"
                | "bytes_utf8"
                | "open_session"
                | "preserve_open_string"
                | "preserve_open_bytes"
                | "preserve_pin_string"
                | "preserve_pin_bytes"
                | "pin_min_minus"
                | "pin_min"
                | "pin_max"
                | "pin_max_plus"
        ) {
            return Err(Failure::Input("token_label_action"));
        }
        module = Some(config.open(&Budgets::ordinary())?);
        Ok(action.into())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(action), Some(module)) = (&setup, &module) else {
            return Ok(());
        };
        if action == "open_session" {
            return super::token_admin_open::check(module, config, pins, &mut session, &mut report);
        }
        if action.starts_with("preserve_") {
            return super::token_admin_open::check_preservation(
                module,
                config,
                pins,
                action,
                &mut session,
                &mut report,
            );
        }
        let targets = module.administration_targets()?;
        let blank: Vec<_> = targets
            .iter()
            .filter(|t| t.capabilities().flags & CKF_TOKEN_INITIALIZED as u64 == 0)
            .collect();
        require(blank.len() == 1, "token_label_blank_target")?;
        if action.starts_with("pin_") {
            require(
                config.label != "Test Token",
                "token_pin_namespace_collision",
            )?;
            return super::token_pin_boundary::check(
                module,
                blank[0],
                pins,
                action,
                &mut session,
                &mut logged,
                &mut report,
            );
        }
        let mut expected = [b' '; 32];
        let text = match action.as_str() {
            "blank" | "blank_stale" => "Test Token".to_owned(),
            "bytes_utf8" => String::new(),
            value => "x".repeat(
                value
                    .strip_prefix("string")
                    .ok_or(Failure::Input("token_label_prefix"))?
                    .parse::<usize>()
                    .map_err(|_| Failure::Input("token_label_length"))?,
            ),
        };
        if action == "string33" {
            let before = module.call_counts()?;
            match module.initialize_token(blank[0], SecretPin::new(pins.officer.to_vec()), &text) {
                Err(Error::Rejected(RejectionReason::TokenAdministration(
                    TokenAdministrationRejection::TokenLabel,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(Failure::Oracle("oversized_label_accepted")),
            }
            require(
                module.call_counts()? == before,
                "oversized_label_dispatched",
            )?;
            let info = module.token_info(blank[0].capabilities().identity.slot)?;
            return require(
                info.flags & CKF_TOKEN_INITIALIZED as u64 == 0,
                "oversized_label_initialized_token",
            );
        }
        if action == "bytes_utf8" {
            // Four UTF-8 bytes followed by exact blank padding. Character
            // counts cannot substitute for the native byte-width contract.
            expected[..4].copy_from_slice("éµ".as_bytes());
            module.initialize_token_bytes(
                blank[0],
                SecretPin::new(pins.officer.to_vec()),
                expected,
            )?;
        } else {
            require(config.label != text, "token_label_namespace_collision")?;
            expected[..text.len()].copy_from_slice(text.as_bytes());
            module.initialize_token(blank[0], SecretPin::new(pins.officer.to_vec()), &text)?;
        }
        if action == "blank_stale" {
            let before = module.call_counts()?;
            let result =
                module.initialize_token(blank[0], SecretPin::new(pins.officer.to_vec()), &text);
            require(
                matches!(
                    result,
                    Err(Error::Rejected(RejectionReason::ModuleLifecycle(
                        ModuleLifecycleRejection::TokenContextStale
                    )))
                ) && module.call_counts()? == before,
                "blank_target_retired_after_initialization",
            )?;
        }
        module.refresh_tokens()?;
        let targets = module.administration_targets()?;
        let selected: Vec<_> = targets
            .iter()
            .filter(|t| {
                t.capabilities().label == expected
                    && t.capabilities().flags & CKF_TOKEN_INITIALIZED as u64 != 0
            })
            .collect();
        require(selected.len() == 1, "initialized_label_not_unique")?;
        let identity = &selected[0].capabilities().identity;
        let info = module.token_info(identity.slot)?;
        require(
            info.label == expected && info.flags & CKF_TOKEN_INITIALIZED as u64 != 0,
            "token_label_native_readback",
        )?;
        session = Some(module.select(identity)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("token_label_session"))?
            .login_as(
                LoginRole::SecurityOfficer,
                SecretPin::new(pins.officer.to_vec()),
            )?;
        logged = true;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(active) = &session {
        if logged {
            if let Err(error) = active.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = active.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Some(module) = &module {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
