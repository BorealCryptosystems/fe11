// SPDX-License-Identifier: Apache-2.0
//! Exercise one GCM continuation and preserve both authentication and ownership.
use super::{
    configuration::Configuration,
    gcm_transition_fixture::{Case, Fixture},
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
        Err(e) => Err(e),
        Ok(_) => Err(Failure::Oracle("expected_local_refusal")),
    }
}
fn native<T, W: Write>(
    value: Result<T>,
    function: &'static str,
    code: u64,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match value {
        Err(
            e @ Error::Native {
                function: actual,
                code: actual_code,
                ..
            },
        ) if actual == function && actual_code == code => {
            outcome::record(report, Phase::Body, &Failure::Product(e))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(e) => Err(e.into()),
        Ok(_) => Err(Failure::Oracle("expected_native_refusal")),
    }
}

pub fn execute<W: Write>(
    f: &mut Fixture,
    c: &Case,
    config: &Configuration,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let retired = c.state == "RETIRED";
    let consumed = c.state == "CONSUMED";
    let waiting = matches!(
        c.state.as_str(),
        "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"
    );
    let closed = RejectionReason::SessionLifecycle(SessionLifecycleRejection::SessionClosed);
    let used = RejectionReason::OperationOwnership(
        OperationOwnershipRejection::ForeignOrConsumedCipherTicket,
    );
    let used_generic =
        RejectionReason::Authentication(AuthenticationRejection::ForeignOrConsumedOperationTicket);
    let not_ready = RejectionReason::CipherContinuation(
        CipherContinuationRejection::CipherIsNotReadyForAnotherInput,
    );
    let not_waiting = RejectionReason::CipherContinuation(
        CipherContinuationRejection::CipherIsNotWaitingForStorage,
    );
    f.verify_owned()?;
    if f.ticket.is_some() && !f.closed && !f.completed {
        f.progress(c)?;
    }
    match c.action.as_str() {
        "init" => {
            let result = f.begin(c, false, 32);
            if retired {
                rejected(result, closed)?;
            } else if matches!(c.state.as_str(), "IDLE" | "CONSUMED" | "REFUSED_TERMINAL") {
                f.start(result?);
            } else {
                match result {
                    Err(Failure::Product(Error::Busy(BusyReason::OperationOwnership(
                        OperationOwnershipBusy::AdvancedOperation,
                    )))) => (),
                    Err(e) => return Err(e),
                    Ok(_) => return Err(Failure::Oracle("competing_gcm_init_accepted")),
                }
            }
        }
        "update" => {
            let result = f.update(c);
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if waiting {
                rejected(result, not_ready)?;
            } else {
                Fixture::ready(result?)?;
            }
        }
        "final" => {
            let result = f.finish_step();
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if waiting && c.encrypt {
                // The producer already closed input to reach Final's capacity
                // request. A second finish is not a second input closure;
                // resize and poll preserve and resume the first Final.
                rejected(result, not_ready)?;
            } else if c.state == "OUTPUT_REQUIRED" {
                Fixture::required(result?, c)?;
            } else if !c.encrypt && c.state == "INITIALIZED" {
                // No input means no authentication tag. This is an intentional
                // native negative, never an empty authenticated plaintext.
                match result {
                    Err(Failure::Product(e)) => native::<(), W>(
                        Err(e),
                        "C_DecryptFinal",
                        fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64,
                        report,
                    )?,
                    Err(e) => return Err(e),
                    Ok(_) => return Err(Failure::Oracle("gcm_missing_tag_accepted")),
                }
                f.completed = true;
            } else {
                f.publish(result?, c)?;
            }
        }
        "provide_capacity" => {
            let result = f.resize(c);
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if c.state == "OUTPUT_REQUIRED" {
                result?;
                f.replacement = true;
            } else {
                rejected(result, not_waiting)?;
            }
        }
        "poll" => {
            let result = f.poll();
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used_generic)?;
            } else if c.state == "OUTPUT_REQUIRED" {
                Fixture::required(result?, c)?;
            } else if c.state == "OUTPUT_STORAGE_SELECTED" && c.encrypt {
                f.publish(result?, c)?;
            } else {
                Fixture::ready(result?)?;
                f.pending = false;
                f.replacement = false;
            }
        }
        "take" => {
            let result = f.take();
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if waiting {
                rejected(result, not_ready)?;
            } else if !c.encrypt {
                match result {
                    Err(Failure::Product(Error::Busy(BusyReason::CipherContinuation(
                        CipherContinuationBusy::AeadPlaintextAwaitsSuccessfulFinal,
                    )))) => (),
                    Err(e) => return Err(e),
                    Ok(_) => return Err(Failure::Oracle("gcm_unauthenticated_plaintext_exposed")),
                }
            } else {
                result?;
                f.take()?;
            }
        }
        "capture" => {
            let result = f
                .subject()?
                .start_state_capture(f.ticket.as_ref().ok_or(Failure::Input("gcm_ticket"))?, 4096);
            if retired {
                rejected(result.map_err(Failure::from), closed)?;
            } else if consumed {
                rejected(result.map_err(Failure::from), used_generic)?;
            } else {
                native(
                    result,
                    "C_GetOperationState",
                    fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64,
                    report,
                )?;
            }
        }
        "cancel" => {
            let result = f.subject()?.cancel(if c.encrypt {
                CancellationFlags::ENCRYPT
            } else {
                CancellationFlags::DECRYPT
            });
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
                        e @ Error::Native {
                            function: "C_SessionCancel",
                            code,
                            may_have_effect: false,
                        },
                    ) if code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => {
                        outcome::record(report, Phase::Body, &Failure::Product(e))
                            .map_err(|_| Failure::Input("report_write"))?;
                    }
                    Err(e) => return Err(e.into()),
                    Ok(_) => return Err(Failure::Oracle("unsupported_cancel_accepted")),
                }
            }
        }
        "logout" => {
            let peer = f.peer.as_ref().ok_or(Failure::Input("gcm_peer"))?;
            peer.logout()?;
            f.logged = false;
            if peer.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("gcm_logout_role"));
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
        "drop_ticket" => drop(f.ticket.take()),
        _ => return Err(Failure::Input("gcm_action")),
    }
    f.complete(c)
}
