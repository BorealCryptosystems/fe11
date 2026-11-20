// SPDX-License-Identifier: Apache-2.0
//! State-specific generation actions preserve native owners and exact refusals.
use super::{
    configuration::Configuration,
    generation_transition_fixture::{Case, Fixture},
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

fn rejected<T>(
    value: std::result::Result<T, Failure>,
    reason: RejectionReason,
) -> std::result::Result<(), Failure> {
    match value {
        Err(Failure::Product(Error::Rejected(actual))) if actual == reason => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(Failure::Oracle("generation_expected_refusal")),
    }
}

/// A retained generation ticket can contain a native refusal instead of a pair.
/// Compare that refusal with the independently observed return; cleanup still
/// checks the namespace and no successful creation is credited by this path.
fn finish_retained<W: Write>(
    f: &mut Fixture,
    module: &Module,
    c: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match f.finish(module, c) {
        Err(Failure::Product(error @ Error::Native {
            function: "C_GenerateKeyPair",
            code,
            ..
        })) if code == fe11_sys::CKR_MECHANISM_INVALID as u64
            && f.observes_pair_return()
            && f.generation_returns.last() == Some(&code) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            // The ticket has been consumed by polling its terminal refusal.
            f.completed = true;
            Ok(())
        }
        result => result,
    }
}
pub fn execute<W: Write>(
    f: &mut Fixture,
    module: &Module,
    c: &Case,
    config: &Configuration,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let retired = c.state == "RETIRED";
    let consumed = c.state == "CONSUMED";
    let closed = RejectionReason::SessionLifecycle(SessionLifecycleRejection::SessionClosed);
    let used =
        RejectionReason::Authentication(AuthenticationRejection::ForeignOrConsumedOperationTicket);
    match c.action.as_str() {
        "unsupported" => {
            // The recipe does not implement the actual Montgomery generator.
            // A refusal is not evidence that an Edwards key is interchangeable.
            // Cooperative start returns a retained ticket, including when its
            // native call failed. Observe that ticket before judging creation.
            let result = f
                .start(module, c, &config.label)
                .and_then(|()| f.finish(module, c));
            match result {
                Err(Failure::Product(
                    error @ Error::Native {
                        function: "C_GenerateKeyPair",
                        code,
                        ..
                    },
                )) if code == fe11_sys::CKR_MECHANISM_INVALID as u64 => {
                    outcome::record(report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    return Ok(());
                }
                Err(error) => return Err(error),
                Ok(()) => return Err(Failure::Oracle("unsupported_generator_succeeded")),
            }
        }
        "init" => {
            if matches!(c.state.as_str(), "IDLE" | "CONSUMED" | "REFUSED_TERMINAL") {
                f.start(module, c, &config.label)?;
            } else {
                let result = f.begin(c, &config.label, false);
                if retired {
                    rejected(result, closed)?;
                } else {
                    match result {
                        Err(Failure::Product(Error::Busy(BusyReason::OperationOwnership(
                            OperationOwnershipBusy::AdvancedOperation,
                        )))) => (),
                        Err(error) => return Err(error),
                        Ok(_) => return Err(Failure::Oracle("competing_generation_accepted")),
                    }
                }
            }
        }
        "poll" => {
            if retired {
                rejected(f.poll_once(module), closed)?;
            } else if consumed {
                rejected(f.poll_once(module), used)?;
            } else {
                finish_retained(f, module, c, report)?;
            }
        }
        "capture" => {
            let result = f
                .subject()?
                .start_state_capture(
                    f.ticket
                        .as_ref()
                        .ok_or(Failure::Input("generation_ticket"))?,
                    4096,
                )
                .map_err(Failure::from);
            let reason = if retired {
                closed
            } else if consumed {
                used
            } else if f.observes_pair_return()
                && f.generation_returns.last()
                    == Some(&(fe11_sys::CKR_MECHANISM_INVALID as u64))
            {
                // A completed native refusal reaches the ownership guard
                // before the operation-family capture check.
                RejectionReason::OperationOwnership(
                    OperationOwnershipRejection::OperationNotCapturable,
                )
            } else {
                RejectionReason::CheckpointCapture(
                    CheckpointCaptureRejection::OperationFamilyNotCapturable,
                )
            };
            rejected(result, reason)?;
        }
        "cancel" => {
            let result = f.subject()?.cancel(CancellationFlags::NONE);
            if retired {
                rejected(result.map_err(Failure::from), closed)?;
            } else if matches!(config.interface, InterfaceSelection::Legacy240) {
                rejected(
                    result.map_err(Failure::from),
                    RejectionReason::Cancellation(CancellationRejection::CSessionCancelUnavailable),
                )?;
            } else {
                match result {
                    Err(
                        error @ Error::Native {
                            function: "C_SessionCancel",
                            code,
                            may_have_effect: false,
                        },
                    ) if code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => {
                        outcome::record(report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))?;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("unsupported_generation_cancel_accepted")),
                }
            }
        }
        "logout" => {
            f.peer()?.logout()?;
            f.logged = false;
            if f.peer()?.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("generation_logout_role"));
            }
        }
        "close" => {
            let result = f.close();
            if retired {
                rejected(result, closed)?;
            } else {
                result?;
            }
        }
        "drop_ticket" => {
            let before = module.call_counts()?;
            f.ticket = None;
            if module.call_counts()? != before {
                return Err(Failure::Oracle("ticket_drop_native_call"));
            }
        }
        _ => return Err(Failure::Input("generation_action")),
    }
    // A refused competing start, capture or cancellation cannot consume the
    // existing creation. Authentication changes and closed sessions have their
    // separate independent-peer cleanup assertions instead.
    if f.ticket.is_some() && !f.closed && !f.completed && c.action != "logout" {
        finish_retained(f, module, c, report)?;
    }
    Ok(())
}
