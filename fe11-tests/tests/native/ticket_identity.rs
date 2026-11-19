// SPDX-License-Identifier: Apache-2.0
//! Foreign and consumed tickets never dispatch or replace the original digest.
use super::{
    arguments::hex,
    configuration::Configuration,
    credentials::Credentials,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
    ticket_identity_action as action,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    advanced: bool,
    method: String,
    consumed: bool,
    recovery: bool,
    expected: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(513)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 512 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 5
            || !matches!(f[0], "Session" | "AdvancedSession")
            || !matches!(f[2], "foreign" | "consumed")
            || !matches!(f[3], "authentication" | "recovery")
        {
            return Err(Failure::Input("ticket_identity_fields"));
        }
        let advanced = f[0] == "AdvancedSession";
        let permitted = if advanced {
            matches!(
                f[1],
                "authenticate_context"
                    | "login_context"
                    | "login_context_user"
                    | "next_native_function"
                    | "poll"
                    | "poll_published_eager"
                    | "poll_published_cooperative"
                    | "poll_signature"
                    | "start_state_capture"
                    | "poll_state_capture"
                    | "start_detachment"
                    | "poll_detachment"
                    | "capture_gcm_recovery"
                    | "capture_dual_gcm_recovery"
                    | "capture_ccm_recovery"
                    | "capture_stream_aead_recovery"
                    | "capture_stream_aead_recovery_salsa"
                    | "resize_recovery_output"
            )
        } else {
            matches!(
                f[1],
                "authenticate_context"
                    | "poll_signature"
                    | "poll_recovery"
                    | "resize_recovery_output"
            )
        };
        let recovery = f[1].contains("recovery");
        let expected = hex(f[4], 32).map_err(Failure::Input)?;
        if !permitted
            || recovery != (f[3] == "recovery")
            || expected.len() != 32
            || (f[1].starts_with("poll_published_") && f[2] != "consumed")
        {
            return Err(Failure::Input("ticket_identity_method"));
        }
        Ok(Self {
            advanced,
            method: f[1].into(),
            consumed: f[2] == "consumed",
            recovery,
            expected,
        })
    }
}
fn open(
    module: &Module,
    config: &Configuration,
    advanced: bool,
) -> std::result::Result<Owner, Failure> {
    let mut owner = Owner::open(module, config, advanced)?;
    if let Owner::Advanced(session) = &mut owner {
        session.set_pacing(OperationPacing::Cooperative)?;
        session.set_validation_capture(ValidationCaptureMode::Disabled)?;
    }
    Ok(owner)
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut origin = None;
    let mut other = None;
    let mut ticket = None;
    let mut published = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        origin = Some(open(&module, config, case.advanced)?);
        if case.method == "poll_published_eager" {
            let Some(Owner::Advanced(session)) = &mut origin else {
                return Err(Failure::Input("publication_advanced_owner"));
            };
            session.set_pacing(OperationPacing::Eager)?;
        }
        if !case.consumed {
            other = Some(open(&module, config, case.advanced)?);
        }
        let owner = origin.as_ref().ok_or(Failure::Input("ticket_origin"))?;
        let queued = case.method.starts_with("poll_published_");
        ticket = Some(if queued {
            action::begin_queued(owner)?
        } else {
            action::begin(owner)?
        });
        if case.consumed {
            let active = ticket.as_mut().ok_or(Failure::Input("ticket_origin"))?;
            let value = if queued {
                action::finish_queued(owner, active)?
            } else {
                action::finish(owner, active)?
            };
            if value.as_bytes() != case.expected {
                return Err(Failure::Oracle("ticket_producer_digest"));
            }
            published = Some(value);
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let receiver = if case.consumed {
                origin.as_ref()
            } else {
                other.as_ref()
            }
            .ok_or(Failure::Input("ticket_receiver"))?;
            let ticket = ticket.as_mut().ok_or(Failure::Input("ticket_origin"))?;
            let before = module.call_counts()?;
            let expected = if case.recovery {
                RejectionReason::OperationOwnership(
                    OperationOwnershipRejection::ForeignOrConsumedRecoveryTicket,
                )
            } else {
                RejectionReason::Authentication(
                    AuthenticationRejection::ForeignOrConsumedOperationTicket,
                )
            };
            match action::invoke(receiver, &case.method, ticket, &pins.user) {
                Err(Failure::Product(Error::Rejected(reason))) if reason == expected => (),
                Err(error) => return Err(error),
                Ok(()) => return Err(Failure::Oracle("foreign_or_consumed_ticket_accepted")),
            }
            if module.call_counts()? != before {
                return Err(Failure::Oracle("ticket_refusal_dispatched"));
            }
            if !case.consumed {
                let value = action::finish(
                    origin.as_ref().ok_or(Failure::Input("ticket_origin"))?,
                    ticket,
                )?;
                if value.as_bytes() != case.expected {
                    return Err(Failure::Oracle("ticket_original_digest"));
                }
                published = Some(value);
            }
            Ok(())
        })(),
    };
    let mut cleanup = Vec::new();
    for owner in [&other, &origin].into_iter().flatten() {
        cleanup.extend(owner.close(None));
    }
    drop(ticket);
    drop(other);
    drop(origin);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let (Ok(case), Some(value)) = (&setup, &published) {
        if value.as_bytes() != case.expected {
            cleanup.push(Failure::Oracle("ticket_published_digest_changed"));
        }
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
