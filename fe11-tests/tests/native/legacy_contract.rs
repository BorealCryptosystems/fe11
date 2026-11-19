// SPDX-License-Identifier: Apache-2.0
//! Legacy status/cancel returns do not consume an existing digest owner.
use super::{
    arguments::hex,
    configuration::Configuration,
    module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    ticket_identity_action,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn refused<W: Write>(
    result: fe11::Result<()>,
    function: &'static str,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function && code == fe11_sys::CKR_FUNCTION_NOT_PARALLEL as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("legacy_report"))
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("legacy_refusal_missing")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut ticket = None;
    let setup = (|| -> std::result::Result<String, Failure> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("legacy_fixture_open"))?
            .take(65)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("legacy_fixture_read"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 2
            || !matches!(fields[0], "Session" | "AdvancedSession")
            || !matches!(fields[1], "status" | "cancel" | "active")
        {
            return Err(Failure::Input("legacy_fixture_fields"));
        }
        owner = Some(Owner::open(
            &module,
            config,
            fields[0] == "AdvancedSession",
        )?);
        if fields[1] == "active" {
            ticket = Some(ticket_identity_action::begin(
                owner.as_ref().ok_or(Failure::Input("legacy_owner"))?,
            )?);
        }
        Ok(fields[1].into())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(action), Some(owner)) = (&setup, &owner) else {
            return Ok(());
        };
        if action != "cancel" {
            let result = match owner {
                Owner::Session(s) => s.get_function_status(),
                Owner::Advanced(s) => s.get_function_status(),
            };
            refused(result, "C_GetFunctionStatus", &mut report)?;
        }
        if action != "status" {
            let result = match owner {
                Owner::Session(s) => s.cancel_function(),
                Owner::Advanced(s) => s.cancel_function(),
            };
            refused(result, "C_CancelFunction", &mut report)?;
        }
        if action == "active" {
            let digest = ticket_identity_action::finish(
                owner,
                ticket.as_mut().ok_or(Failure::Input("legacy_ticket"))?,
            )?;
            let expected = hex(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                32,
            )
            .map_err(Failure::Input)?;
            if digest.as_bytes() != expected {
                return Err(Failure::Oracle("legacy_calls_changed_digest"));
            }
        }
        Ok(())
    })();
    drop(ticket);
    let mut cleanup = owner.as_ref().map(|x| x.close(None)).unwrap_or_default();
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
