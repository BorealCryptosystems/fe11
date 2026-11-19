// SPDX-License-Identifier: Apache-2.0
//! Idle setting changes and refusals during a real cooperative digest ownership.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<(bool, Vec<u8>), Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("settings_fixture_open"))?
        .take(129)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("settings_fixture_read"))?;
    if data.len() > 128 {
        return Err(Failure::Input("settings_fixture_size"));
    }
    let text =
        std::str::from_utf8(&data).map_err(|_| Failure::Input("settings_fixture_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 2 || !matches!(fields[0], "pacing" | "capture") {
        return Err(Failure::Input("settings_fixture_fields"));
    }
    let expected = hex(fields[1], 32).map_err(Failure::Input)?;
    if expected.len() != 32 {
        return Err(Failure::Input("settings_fixture_digest"));
    }
    Ok((fields[0] == "capture", expected))
}

fn one_step(module: &Module, before: &BTreeMap<&str, u64>) -> std::result::Result<(), Failure> {
    let after = module.call_counts()?;
    let previous: u64 = before.values().sum();
    let current: u64 = after.values().sum();
    if current
        .checked_sub(previous)
        .map_or(true, |count| count > 1)
    {
        return Err(Failure::Oracle("settings_cooperative_native_step"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut ticket = None;
    let mut output = None;
    let setup = (|| -> std::result::Result<(bool, Vec<u8>), Failure> {
        let case = read(path)?;
        let identity =
            select_token(&module, &config.label).ok_or(Failure::Input("settings_token"))?;
        session = Some(
            module
                .select(&identity)?
                .open_session(true)?
                .into_advanced()?,
        );
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match (&setup, &mut session) {
        (Ok((capture, expected)), Some(owner)) => (|| -> std::result::Result<(), Failure> {
            let before = module.call_counts()?;
            owner.set_pacing(OperationPacing::Eager)?;
            owner.set_pacing(OperationPacing::Cooperative)?;
            owner.set_validation_capture(ValidationCaptureMode::Disabled)?;
            if *capture {
                owner.set_validation_capture(ValidationCaptureMode::Capture)?;
            }
            if owner.mode() != AdvancedSessionMode::Synchronous || module.call_counts()? != before {
                return Err(Failure::Oracle("settings_idle_changes_dispatched"));
            }
            ticket = Some(owner.digest_native(
                NativeDigestAlgorithm::Sha256,
                &[b"abc"],
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
            )?);
            one_step(&module, &before)?;
            let before_change = module.call_counts()?;
            let changed = if *capture {
                owner.set_validation_capture(ValidationCaptureMode::Disabled)
            } else {
                owner.set_pacing(OperationPacing::Eager)
            };
            match changed {
                Err(Error::Busy(BusyReason::OperationOwnership(
                    OperationOwnershipBusy::AdvancedOperation,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(Failure::Oracle("settings_active_change_accepted")),
            }
            if module.call_counts()? != before_change
                || owner.mode() != AdvancedSessionMode::Synchronous
            {
                return Err(Failure::Oracle("settings_active_change_dispatched"));
            }
            let ticket = ticket.as_mut().ok_or(Failure::Input("settings_ticket"))?;
            // The one-part digest has Update/Final, optional validation query,
            // and local publication. Six polls bound protocol work, not elapsed time.
            for _ in 0..6 {
                let before = module.call_counts()?;
                let result = owner.poll(ticket);
                one_step(&module, &before)?;
                match result {
                    Ok(OperationProgress::Ready) => continue,
                    Ok(OperationProgress::NativeDigest(value)) => {
                        if value.as_bytes() != expected {
                            return Err(Failure::Oracle("settings_digest_known_answer"));
                        }
                        output = Some(value);
                        if *capture {
                            let observations = ticket
                                .validation_report()
                                .ok_or(Failure::Oracle("settings_capture_report_absent"))?
                                .observations();
                            if observations.len() != 1
                                || observations[0].function != "C_DigestFinal"
                                || observations[0].message_index.is_some()
                            {
                                return Err(Failure::Oracle("settings_capture_correlation"));
                            }
                            match (config.interface, observations[0].validation) {
                                (InterfaceSelection::Legacy240, SessionValidation::Unavailable) => {
                                    ()
                                }
                                (
                                    InterfaceSelection::Standard { .. },
                                    SessionValidation::Reported(flags),
                                ) => {
                                    report
                                        .observation(
                                            Phase::Body,
                                            "native_validation_flags",
                                            Producer::Native,
                                            Observation::Number(flags),
                                        )
                                        .map_err(|_| Failure::Input("settings_report_write"))?;
                                }
                                _ => {
                                    return Err(Failure::Oracle(
                                        "settings_capture_interface_result",
                                    ))
                                }
                            }
                        } else if ticket.validation_report().is_some() {
                            return Err(Failure::Oracle("settings_unrequested_report"));
                        }
                        return Ok(());
                    }
                    Err(
                        error @ Error::Native {
                            function: "C_GetSessionValidationFlags",
                            code,
                            may_have_effect: false,
                        },
                    ) if *capture && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => {
                        if ticket.validation_report().is_some() {
                            return Err(Failure::Oracle("settings_refusal_report_published"));
                        }
                        // The design permits this exact unavailable observation, not
                        // an arbitrary failure or a successful digest-result claim.
                        outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("settings_report_write"))?;
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("settings_digest_result_kind")),
                }
            }
            Err(Failure::Oracle("settings_digest_not_completed"))
        })(),
        _ => Ok(()),
    };
    drop(output);
    drop(ticket);
    let mut cleanup = Vec::new();
    if let Some(owner) = &session {
        match owner.close() {
            Ok(AdvancedCloseStatus::Complete) => (),
            Ok(_) => cleanup.push(Failure::Oracle("settings_synchronous_close")),
            Err(error) => cleanup.push(error.into()),
        }
    }
    drop(session);
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
            "settings_owner_preserved",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
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
