// SPDX-License-Identifier: Apache-2.0
//! Exact public actions on retained digest terminal calls and facade observers.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    digest_capacity_fixture::{too_small, Case, Fixture},
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

fn rejected<T>(result: Result<T>, reason: RejectionReason) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(actual)) if actual == reason => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("digest_expected_refusal")),
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
        Ok(_) => Err(Failure::Oracle("digest_expected_native_refusal")),
    }
}
fn waiting(fixture: &Fixture, case: &Case) -> std::result::Result<(), Failure> {
    if let Some(ticket) = &fixture.ticket {
        let (status, progress) = ticket.digest_progress()?;
        let (submissions, bytes) = if fixture.appended {
            (2, 56)
        } else if case.state.starts_with("ZERO_") {
            (3, 3)
        } else {
            (1, 3)
        };
        if status != StreamInputStatus::Closed
            || progress.submissions != submissions
            || progress.input_bytes != bytes
            || progress.key_inputs != 0
            || progress.output_bytes != 0
        {
            return Err(Failure::Oracle("digest_retained_terminal_progress"));
        }
    }
    Ok(())
}
pub fn execute<W: Write>(
    fixture: &mut Fixture,
    module: &Module,
    case: &Case,
    config: &Configuration,
    pins: &Credentials,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if case.action == "exact" {
        // This is the first Final, with capacity32 selected before Init.
        // It deliberately does not enter the retained-too-small state below.
        let output = fixture.final_result()??;
        fixture.accept(output, case)?;
        return fixture.verify(case);
    }
    waiting(fixture, case)?;
    match case.action.as_str() {
        "requirement" => {
            let before = module.call_counts()?;
            let ticket = fixture
                .ticket
                .as_ref()
                .ok_or(Failure::Input("digest_ticket"))?;
            if ticket.digest_output_requirement()? != Some(32)
                || ticket.extension_digest_output_requirement()? != Some(32)
                || module.call_counts()? != before
            {
                return Err(Failure::Oracle("digest_required_length_observation"));
            }
            waiting(fixture, case)?;
            fixture.resize()?;
            fixture.replacement = true;
            let output = fixture.poll_result()??;
            fixture.accept(output, case)?;
        }
        "init" => match fixture
            .subject()?
            .begin_native_digest(NativeDigestAlgorithm::Sha256)
        {
            Err(Error::Busy(BusyReason::OperationOwnership(
                OperationOwnershipBusy::AdvancedOperation,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("second_digest_init_accepted")),
        },
        "update" => {
            let mut ticket = fixture
                .ticket
                .take()
                .ok_or(Failure::Input("digest_ticket"))?;
            // BUFFER_TOO_SMALL leaves the native digest active. Once storage
            // is selected, an explicit Update can append the remaining bytes
            // of NIST's two-block SHA-256 example without replaying "abc".
            let appended = case.state == "OUTPUT_STORAGE_SELECTED";
            let bytes: &[u8] = if appended {
                b"dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            } else {
                b"x"
            };
            let result = fixture.subject()?.digest_update(
                &mut ticket,
                bytes,
                InputLimits {
                    maximum_parts: 2,
                    maximum_total_bytes: 56,
                },
            );
            fixture.ticket = Some(ticket);
            if appended {
                result?;
                fixture.appended = true;
            } else {
                rejected(
                    result,
                    RejectionReason::DigestContinuation(
                        DigestContinuationRejection::DigestInputPhase,
                    ),
                )?;
            }
        }
        "final" | "poll" => {
            let result = if case.action == "final" {
                fixture.final_result()?
            } else {
                fixture.poll_result()?
            };
            if case.state == "OUTPUT_REQUIRED" {
                too_small(result)?;
            } else {
                fixture.accept(result?, case)?;
            }
        }
        "take" => {
            let result = fixture.subject()?.take_digest_ticket();
            if case.state == "FACADE_RETAINED" {
                fixture.ticket = Some(result?);
            } else {
                rejected(
                    result,
                    RejectionReason::DigestContinuation(
                        DigestContinuationRejection::DigestContinuationTicketUnavailable,
                    ),
                )?;
            }
            if case.state == "FACADE_RETAINED" {
                rejected(
                    fixture.subject()?.take_digest_ticket(),
                    RejectionReason::DigestContinuation(
                        DigestContinuationRejection::DigestContinuationTicketUnavailable,
                    ),
                )?;
            }
        }
        "output_capacity" => {
            if case.state == "OUTPUT_REQUIRED" {
                fixture.resize()?;
                fixture.replacement = true;
            } else {
                let result = fixture.subject()?.provide_extension_digest_output_capacity(
                    fixture
                        .ticket
                        .as_ref()
                        .ok_or(Failure::Input("digest_ticket"))?,
                    32,
                );
                rejected(
                    result,
                    RejectionReason::DigestContinuation(
                        DigestContinuationRejection::DigestOutputIsNotAwaitingStorage,
                    ),
                )?;
            }
        }
        "capture" => {
            let result = fixture.subject()?.start_state_capture(
                fixture
                    .ticket
                    .as_ref()
                    .ok_or(Failure::Input("digest_ticket"))?,
                4096,
            );
            native(
                result,
                "C_GetOperationState",
                fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64,
                report,
            )?;
        }
        "cancel" => {
            let result = fixture.subject()?.cancel(CancellationFlags::DIGEST);
            if matches!(config.interface, InterfaceSelection::Legacy240) {
                rejected(
                    result,
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
        "login" => {
            let peer = fixture.peer.as_ref().ok_or(Failure::Input("digest_peer"))?;
            native(
                peer.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec())),
                "C_Login",
                fe11_sys::CKR_USER_ALREADY_LOGGED_IN as u64,
                report,
            )?;
        }
        "logout" => {
            let peer = fixture.peer.as_ref().ok_or(Failure::Input("digest_peer"))?;
            peer.logout()?;
            fixture.logged = false;
            if peer.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("digest_logout_state"));
            }
        }
        "close" => fixture.close()?,
        "drop_ticket" => {
            drop(fixture.ticket.take());
        }
        _ => return Err(Failure::Input("digest_capacity_action")),
    }
    if !fixture.closed && case.action != "drop_ticket" && fixture.output.is_none() {
        if fixture.ticket.is_none() {
            fixture.ticket = Some(fixture.subject()?.take_digest_ticket()?);
        }
        waiting(fixture, case)?;
        if !fixture.replacement {
            fixture.resize()?;
        }
        let result = fixture.final_result()??;
        fixture.accept(result, case)?;
    }
    if fixture.output.is_some() {
        fixture.verify(case)?;
    }
    Ok(())
}
