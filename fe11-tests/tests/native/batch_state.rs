// SPDX-License-Identifier: Apache-2.0
//! Owned digest and GCM batches across capture, cancellation and publication.
use super::{
    arguments::hex,
    batch_capacity,
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

struct Case {
    gcm: bool,
    action: String,
    expected: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("batch_state_open"))?
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("batch_state_read"))?;
        if bytes.len() > 256 {
            return Err(Failure::Input("batch_state_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("batch_state_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 3
            || !matches!(f[0], "digest" | "gcm")
            || !(matches!(
                f[1],
                "start" | "complete" | "poll_consumed" | "close" | "capture" | "cancel"
            ) || batch_capacity::selected(f[1], f[0] == "gcm").is_some())
        {
            return Err(Failure::Input("batch_state_fields"));
        }
        let expected = hex(f[2], 32).map_err(Failure::Input)?;
        if expected.len() != if f[0] == "gcm" { 16 } else { 32 } {
            return Err(Failure::Input("batch_state_expected_width"));
        }
        Ok(Self {
            gcm: f[0] == "gcm",
            action: f[1].into(),
            expected,
        })
    }
}

fn bytes(value: &OperationProgress) -> std::result::Result<&[u8], Failure> {
    match value {
        OperationProgress::NativeDigest(value) => Ok(value.as_bytes()),
        OperationProgress::ExtensionDigest(value) => Ok(value.as_bytes()),
        OperationProgress::ClassicAeadEncrypted(value) => Ok(value.as_bytes()),
        _ => Err(Failure::Oracle("batch_state_result_kind")),
    }
}
fn one_step(
    module: &Module,
    before: &std::collections::BTreeMap<&str, u64>,
) -> std::result::Result<(), Failure> {
    let after = module.call_counts()?;
    let old: u64 = before.values().sum();
    let new: u64 = after.values().sum();
    if new.checked_sub(old).map_or(true, |count| count > 1) {
        return Err(Failure::Oracle("cooperative_batch_multiple_calls"));
    }
    Ok(())
}
fn complete(
    module: &Module,
    session: &AdvancedSession,
    ticket: &mut OperationTicket,
    case: &Case,
) -> std::result::Result<OperationProgress, Failure> {
    // One owned part means at most Init, Update and Final, followed by local
    // publication. This is a protocol-step bound, not a wall-clock deadline.
    for _ in 0..4 {
        let before = module.call_counts()?;
        let progress = session.poll(ticket)?;
        one_step(module, &before)?;
        if matches!(progress, OperationProgress::Ready) {
            continue;
        }
        if bytes(&progress)? != case.expected {
            return Err(Failure::Oracle("batch_state_known_answer"));
        }
        return Ok(progress);
    }
    Err(Failure::Oracle("batch_state_did_not_publish"))
}
fn close(session: &AdvancedSession) -> std::result::Result<(), Failure> {
    if !matches!(session.close()?, AdvancedCloseStatus::Complete) {
        return Err(Failure::Oracle("batch_state_synchronous_close"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut ordinary = None;
    let mut session = None;
    let mut key = None;
    let mut ticket = None;
    let mut output = None;
    let mut closed = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        ordinary = Some(Owner::open(&module, config, false)?);
        if case.gcm {
            key = Some(
                ordinary
                    .as_ref()
                    .ok_or(Failure::Input("batch_state_owner"))?
                    .import_secret(
                        &[0; 16],
                        fe11_sys::CKK_AES,
                        [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
                    )?,
            );
        }
        let Some(Owner::Session(owner)) = ordinary.take() else {
            return Err(Failure::Input("batch_state_owner"));
        };
        session = Some(owner.into_advanced()?);
        let owner = session
            .as_mut()
            .ok_or(Failure::Input("batch_state_owner"))?;
        owner.set_pacing(OperationPacing::Cooperative)?;
        owner.set_validation_capture(ValidationCaptureMode::Disabled)?;
        let before = module.call_counts()?;
        ticket = Some(if case.gcm {
            owner.start_encrypt_classic_aead(
                key.as_ref().ok_or(Failure::Input("batch_state_key"))?,
                ClassicAeadParameters::Gcm {
                    iv: &[0; 12],
                    aad: &[],
                    tag_bits: 128,
                },
                MessageRoute::Single,
                &[&[]],
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 12,
                },
                CipherOutputPlan::Buffer {
                    capacity: if batch_capacity::selected(&case.action, true).is_some() {
                        15
                    } else {
                        16
                    },
                },
            )?
        } else if batch_capacity::selected(&case.action, false).is_some() {
            batch_capacity::start_digest(&module, owner)?
        } else {
            owner.digest_native(
                NativeDigestAlgorithm::Sha256,
                &[b"abc"],
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
            )?
        });
        one_step(&module, &before)?;
        let after = module.call_counts()?;
        let init = if case.gcm {
            "C_EncryptInit"
        } else {
            "C_DigestInit"
        };
        if after
            .get(init)
            .copied()
            .unwrap_or(0)
            .checked_sub(before.get(init).copied().unwrap_or(0))
            != Some(1)
        {
            return Err(Failure::Oracle("batch_state_initialization_count"));
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match (&setup, &session, &mut ticket) {
        (Ok(case), Some(owner), Some(ticket)) => (|| -> std::result::Result<(), Failure> {
            match case.action.as_str() {
                "capture" => {
                    // Cooperative capture prepares its observation before the
                    // native state query. Ready is progress, not a saved state.
                    match owner.start_state_capture(ticket, 4096)? {
                        StateCaptureProgress::Ready => (),
                        _ => return Err(Failure::Oracle("batch_capture_initial_progress")),
                    }
                    match owner.poll_state_capture(ticket) {
                        Err(
                            error @ Error::Native {
                                function: "C_GetOperationState",
                                code,
                                ..
                            },
                        ) if code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => {
                            outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                                .map_err(|_| Failure::Input("report_write"))?;
                        }
                        Err(error) => return Err(error.into()),
                        Ok(_) => return Err(Failure::Oracle("batch_state_unexpected_capture")),
                    }
                }
                "cancel" => {
                    let result = owner.cancel(CancellationFlags::ENCRYPT);
                    match result {
                        Err(Error::Rejected(RejectionReason::Cancellation(
                            CancellationRejection::CSessionCancelUnavailable,
                        ))) if matches!(config.interface, InterfaceSelection::Legacy240) => (),
                        Err(
                            error @ Error::Native {
                                function: "C_SessionCancel",
                                code,
                                may_have_effect: false,
                            },
                        ) if matches!(
                            config.interface,
                            InterfaceSelection::Standard {
                                version: (3, 2),
                                ..
                            }
                        ) && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 =>
                        {
                            outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                                .map_err(|_| Failure::Input("report_write"))?;
                        }
                        Err(error) => return Err(error.into()),
                        Ok(_) => return Err(Failure::Oracle("batch_state_unexpected_cancel")),
                    }
                }
                _ => (),
            }
            output = Some(
                if let Some(capacity) = batch_capacity::selected(&case.action, case.gcm) {
                    batch_capacity::exercise(&module, owner, ticket, case.gcm, capacity)?
                } else {
                    complete(&module, owner, ticket, case)?
                },
            );
            if case.action == "poll_consumed" {
                let before = module.call_counts()?;
                match owner.poll(ticket) {
                    Err(Error::Rejected(RejectionReason::Authentication(
                        AuthenticationRejection::ForeignOrConsumedOperationTicket,
                    ))) => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("batch_state_second_publication")),
                }
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("batch_state_consumed_dispatch"));
                }
            }
            if case.action == "close" {
                close(owner)?;
                closed = true;
            }
            if bytes(
                output
                    .as_ref()
                    .ok_or(Failure::Input("batch_state_output"))?,
            )? != case.expected
            {
                return Err(Failure::Oracle("batch_state_owned_result_changed"));
            }
            Ok(())
        })(),
        _ => Ok(()),
    };
    drop(ticket);
    let mut cleanup = Vec::new();
    if let Some(owner) = &session {
        if !closed {
            if let Some(key) = &key {
                if let Err(error) = owner.destroy_native_object(key) {
                    cleanup.push(error.into());
                }
            }
            if let Err(error) = close(owner) {
                cleanup.push(error);
            }
        }
    }
    if let Some(owner) = &ordinary {
        cleanup.extend(owner.close(key.as_ref()));
    }
    drop(key);
    drop(session);
    drop(ordinary);
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
            "owned_batch_state_and_exact_output",
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
