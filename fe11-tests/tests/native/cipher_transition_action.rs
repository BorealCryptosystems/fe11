// SPDX-License-Identifier: Apache-2.0
//! One action per retained AES stream, followed by an explicit completion check.
use super::{
    cipher_transition_fixture::{Case, Fixture},
    configuration::Configuration,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

fn rejected<T>(
    result: std::result::Result<T, Failure>,
    reason: RejectionReason,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Failure::Product(Error::Rejected(actual))) if actual == reason => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(Failure::Oracle("expected_local_refusal")),
    }
}
fn native<T, W: Write>(
    result: Result<T>,
    function: &'static str,
    code: u64,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code: actual_code,
                ..
            },
        ) if actual == function && actual_code == code => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("expected_native_refusal")),
    }
}

pub fn execute<W: Write>(
    fixture: &mut Fixture,
    case: &Case,
    config: &Configuration,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let retired = case.state == "RETIRED";
    let consumed = case.state == "CONSUMED";
    let waiting = matches!(
        case.state.as_str(),
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
    fixture.verify_owned()?;
    if fixture.ticket.is_some() && !fixture.closed && !fixture.completed {
        fixture.progress()?;
    }
    match case.action.as_str() {
        "init" => {
            let result = fixture.begin(case, false, 16);
            if retired {
                rejected(result, closed)?;
            } else if matches!(
                case.state.as_str(),
                "IDLE" | "CONSUMED" | "REFUSED_TERMINAL"
            ) {
                fixture.ticket = Some(result?);
                fixture.completed = false;
                fixture.input_closed = false;
                fixture.blocks = 0;
                fixture.transferred.clear();
            } else {
                match result {
                    Err(Failure::Product(Error::Busy(BusyReason::OperationOwnership(
                        OperationOwnershipBusy::AdvancedOperation,
                    )))) => (),
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Failure::Oracle("competing_cipher_init_accepted")),
                }
            }
        }
        "update" => {
            let result = fixture.update(case);
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if waiting {
                rejected(result, not_ready)?;
            } else {
                Fixture::ready(result?)?;
                fixture.blocks += 1;
            }
        }
        "final" => {
            if case.state == "OUTPUT_REQUIRED" {
                Fixture::buffer_required(fixture.finish_step()?, case)?;
            } else if case.state == "OUTPUT_STORAGE_SELECTED" {
                fixture.finish(case)?;
                fixture.pending_input = false;
                fixture.replacement = false;
            } else {
                let result = fixture.finish(case);
                if retired {
                    rejected(result, closed)?;
                } else if consumed {
                    rejected(result, used)?;
                } else {
                    result?;
                }
            }
        }
        "provide_capacity" => {
            let result = fixture.resize();
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if case.state == "OUTPUT_REQUIRED" {
                result?;
                fixture.replacement = true;
            } else {
                rejected(result, not_waiting)?;
            }
        }
        "poll" => {
            let result = fixture.poll();
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used_generic)?;
            } else if case.state == "OUTPUT_REQUIRED" {
                Fixture::buffer_required(result?, case)?;
            } else {
                Fixture::ready(result?)?;
                if fixture.pending_input {
                    fixture.pending_input = false;
                    fixture.replacement = false;
                }
            }
        }
        "take" => {
            let result = fixture
                .subject()?
                .take_cipher_stream_output(
                    fixture
                        .ticket
                        .as_ref()
                        .ok_or(Failure::Input("cipher_ticket"))?,
                )
                .map_err(Failure::from);
            if retired {
                rejected(result, closed)?;
            } else if consumed {
                rejected(result, used)?;
            } else if waiting {
                rejected(result, not_ready)?;
            } else {
                let chunk = result?;
                if chunk.is_unauthenticated_plaintext() != !case.encrypt
                    || chunk.as_bytes() != case.expected.repeat(fixture.blocks)
                {
                    return Err(Failure::Oracle("cipher_chunk_known_answer"));
                }
                fixture.retain_chunk(chunk, case.expected.repeat(fixture.blocks));
                let empty = fixture.subject()?.take_cipher_stream_output(
                    fixture
                        .ticket
                        .as_ref()
                        .ok_or(Failure::Input("cipher_ticket"))?,
                )?;
                if !empty.as_bytes().is_empty() {
                    return Err(Failure::Oracle("cipher_chunk_republished"));
                }
            }
        }
        "capture" => {
            let result = fixture.subject()?.start_state_capture(
                fixture
                    .ticket
                    .as_ref()
                    .ok_or(Failure::Input("cipher_ticket"))?,
                4096,
            );
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
            let flags = if case.encrypt {
                CancellationFlags::ENCRYPT
            } else {
                CancellationFlags::DECRYPT
            };
            let result = fixture.subject()?.cancel(flags);
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
                    Ok(_) => return Err(Failure::Oracle("unsupported_cancel_accepted")),
                }
            }
        }
        "logout" => {
            let peer = fixture.peer.as_ref().ok_or(Failure::Input("cipher_peer"))?;
            peer.logout()?;
            fixture.logged = false;
            if peer.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("cipher_logout_role"));
            }
        }
        "close" => {
            let result = fixture.close();
            if retired {
                rejected(result, closed)?;
            } else {
                result?;
            }
        }
        "drop_ticket" => {
            drop(fixture.ticket.take());
        }
        _ => return Err(Failure::Input("cipher_action")),
    }
    if fixture.ticket.is_some() && !fixture.closed && !fixture.completed {
        fixture.progress()?;
        if fixture.pending_input {
            if !fixture.replacement {
                fixture.resize()?;
            }
            let resumed = fixture.poll()?;
            if fixture.input_closed {
                fixture.publish_final(resumed, case)?;
            } else {
                Fixture::ready(resumed)?;
            }
            fixture.pending_input = false;
            fixture.replacement = false;
            if !fixture.completed {
                fixture.progress()?;
            }
        }
        if !fixture.completed {
            fixture.finish(case)?;
        }
    }
    fixture.verify_owned()
}
