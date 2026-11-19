// SPDX-License-Identifier: Apache-2.0
//! Unsupported real native entry points still have explicit owner transitions.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "ccm_initialization.rs"]
mod ccm_initialization;
#[path = "cms_initialization.rs"]
mod cms_initialization;
#[path = "curve_operations.rs"]
mod curve_operations;
#[path = "ecdh_parameters.rs"]
mod ecdh_parameters;
#[path = "hkdf_refusal.rs"]
mod hkdf_refusal;
#[path = "message_initialization.rs"]
mod message_initialization;
#[path = "recover_initialization.rs"]
mod recover_initialization;
#[path = "rsa_cipher_roundtrip.rs"]
mod rsa_cipher_roundtrip;

struct Case {
    message: bool,
    state: String,
    action: String,
    key: Vec<Vec<u8>>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_utf8"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() < 4
            || !matches!(fields[0], "message" | "recover")
            || !matches!(fields[1], "ABSENT" | "REFUSED" | "CLOSED")
            || !matches!(fields[2], "start" | "close")
        {
            return Err(Failure::Input("unsupported_lifecycle_fixture"));
        }
        let message = fields[0] == "message";
        if fields.len() != if message { 4 } else { 11 } {
            return Err(Failure::Input("key_fields"));
        }
        let key = fields[3..]
            .iter()
            .map(|field| hex(field, 512).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if key.iter().any(Vec::is_empty) || (!message && key[0].len() != 256) {
            return Err(Failure::Input("key_dimensions"));
        }
        Ok(Self {
            message,
            state: fields[1].into(),
            action: fields[2].into(),
            key,
        })
    }
}

fn start(
    owner: &Owner,
    key: &NativeObjectRef,
    message: bool,
) -> std::result::Result<fe11::Result<()>, Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    match (owner, message) {
        (Owner::Advanced(session), true) => Ok(session
            .execute_native_message(
                key,
                NativeMessageParameters::Mac(NativeMacParameters::Full(
                    NativeMacAlgorithm::SHA256_HMAC,
                )),
                NativeMessageRoute::Single(NativeMessagePart {
                    data: b"abc",
                    parameters: None,
                }),
                NativeMessageAction::Sign {
                    output_capacity: 32,
                },
                limits,
                None,
            )
            .map(|_| ())),
        (Owner::Session(session), false) => Ok(session
            .begin_sign_recover(
                key,
                RecoverMechanism::RsaPkcs,
                b"abc",
                limits,
                RecoverOutputPlan::Buffer { capacity: 256 },
                256,
            )
            .map(|_| ())),
        _ => Err(Failure::Input("unsupported_lifecycle_owner")),
    }
}

fn close(owner: &Owner) -> std::result::Result<(), Failure> {
    match owner {
        Owner::Session(session) => session.close().map_err(Failure::from),
        Owner::Advanced(session) => match session.close()? {
            AdvancedCloseStatus::Complete => Ok(()),
            AdvancedCloseStatus::Pending => Err(Failure::Oracle("synchronous_close_pending")),
        },
    }
}

fn unsupported<W: Write>(
    result: fe11::Result<()>,
    message: bool,
    report: &mut Report<W>,
    phase: Phase,
) -> std::result::Result<(), Failure> {
    let expected = if message {
        "C_MessageSignInit"
    } else {
        "C_SignRecoverInit"
    };
    match result {
        Err(error @ Error::Native { function, code, .. })
            if function == expected && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 =>
        {
            // Keep the original native diagnostic, including its effect flag.
            outcome::record(report, phase, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("unsupported_operation_succeeded")),
    }
}

fn closed(result: std::result::Result<(), Failure>) -> std::result::Result<(), Failure> {
    match result {
        Err(Failure::Product(Error::Rejected(RejectionReason::SessionLifecycle(
            SessionLifecycleRejection::SessionClosed,
        )))) => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(Failure::Oracle("closed_session_accepted")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    if rsa_cipher_roundtrip::selected(path) {
        return rsa_cipher_roundtrip::execute(module, config, path, report);
    }
    if curve_operations::selected(path) {
        return curve_operations::execute(module, config, path, report);
    }
    if ccm_initialization::selected(path) {
        return super::single_key_case::execute::<ccm_initialization::Case, W>(
            module, config, path, report,
        );
    }
    if cms_initialization::selected(path) {
        return super::single_key_case::execute::<cms_initialization::Case, W>(
            module, config, path, report,
        );
    }
    if recover_initialization::selected(path) {
        return super::single_key_case::execute::<recover_initialization::Case, W>(
            module, config, path, report,
        );
    }
    if ecdh_parameters::selected(path) {
        return super::derived_value_case::execute::<ecdh_parameters::Case, W>(
            module, config, path, report,
        );
    }
    if hkdf_refusal::selected(path) {
        return super::derived_value_case::execute::<hkdf_refusal::Case, W>(
            module, config, path, report,
        );
    }
    if message_initialization::selected(path) {
        return super::single_key_case::execute::<message_initialization::Case, W>(
            module, config, path, report,
        );
    }
    let mut owner = None;
    let mut key = None;
    let mut is_closed = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, case.message)?);
        let live = owner.as_ref().ok_or(Failure::Input("lifecycle_owner"))?;
        key = Some(if case.message {
            live.import_secret(
                &case.key[0],
                fe11_sys::CKK_GENERIC_SECRET,
                [StandardAttribute::SIGN, StandardAttribute::VERIFY],
            )?
        } else {
            live.import_rsa_private(&case.key, StandardAttribute::SIGN_RECOVER)?
        });
        let reference = key.as_ref().ok_or(Failure::Input("lifecycle_key"))?;
        if case.state == "REFUSED" {
            unsupported(
                start(live, reference, case.message)?,
                case.message,
                &mut report,
                Phase::Setup,
            )?;
        }
        if case.state == "CLOSED" {
            close(live)?;
            is_closed = true;
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let live = owner.as_ref().ok_or(Failure::Input("lifecycle_owner"))?;
            let reference = key.as_ref().ok_or(Failure::Input("lifecycle_key"))?;
            let before = module.call_counts()?;
            if case.state == "CLOSED" {
                let result = if case.action == "start" {
                    start(live, reference, case.message)?.map_err(Failure::from)
                } else {
                    close(live)
                };
                closed(result)?;
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("closed_lifecycle_dispatched"));
                }
            } else if case.action == "start" {
                unsupported(
                    start(live, reference, case.message)?,
                    case.message,
                    &mut report,
                    Phase::Body,
                )?;
            } else {
                close(live)?;
                is_closed = true;
            }
            Ok(())
        })(),
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if !is_closed {
        if let Some(live) = &owner {
            cleanup = live.close(key.as_ref());
        }
    }
    drop(key);
    drop(owner);
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
            "unsupported_native_or_closed_local_owner",
            Producer::Fe11Local,
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
