// SPDX-License-Identifier: Apache-2.0
//! Caller-fed digest actions: exact refusals, retained ownership and explicit finish.
use super::{
    arguments::hex,
    configuration::Configuration,
    credentials::Credentials,
    digest_fixture::{Fixture, State},
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
    state: State,
    action: String,
    producer: Vec<u8>,
    expected: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("fixture_read"))?;
    if bytes.len() > 1024 {
        return Err(Failure::Input("fixture_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 4 {
        return Err(Failure::Input("fixture_fields"));
    }
    if !matches!(
        fields[1],
        "init"
            | "update"
            | "final"
            | "take"
            | "poll"
            | "output_capacity"
            | "capture"
            | "detach"
            | "capture-credits"
            | "preparation-credits"
            | "drop-observer"
            | "login"
            | "logout"
            | "close"
            | "drop_ticket"
            | "read_output"
    ) {
        return Err(Failure::Input("digest_action"));
    }
    let producer = hex(fields[2], 32).map_err(Failure::Input)?;
    let expected = hex(fields[3], 32).map_err(Failure::Input)?;
    if producer.len() != 32 || expected.len() != 32 {
        return Err(Failure::Input("digest_width"));
    }
    Ok(Case {
        state: State::parse(fields[0])?,
        action: fields[1].into(),
        producer,
        expected,
    })
}

fn rejected(
    result: std::result::Result<(), Failure>,
    reason: RejectionReason,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Failure::Product(Error::Rejected(actual))) if actual == reason => Ok(()),
        Err(error) => Err(error),
        Ok(()) => Err(Failure::Oracle("expected_local_refusal")),
    }
}

fn native<W: Write>(
    result: Result<()>,
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
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("expected_native_refusal")),
    }
}

fn action<W: Write>(
    module: &Module,
    fixture: &mut Fixture,
    case: &Case,
    pins: &Credentials,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let state = case.state;
    let action = case.action.as_str();
    let closed = RejectionReason::SessionLifecycle(SessionLifecycleRejection::SessionClosed);
    let consumed = RejectionReason::OperationOwnership(
        OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
    );
    let consumed_generic =
        RejectionReason::Authentication(AuthenticationRejection::ForeignOrConsumedOperationTicket);
    let active = matches!(
        state,
        State::Initialized | State::Active | State::LocalRefusal
    );
    let limits = InputLimits {
        maximum_parts: 4,
        maximum_total_bytes: 4,
    };
    let mut finished = false;
    match action {
        "preparation-credits" => {
            if state != State::Absent {
                return Err(Failure::Input("preparation_credit_initial_state"));
            }
            let counts = module.call_counts()?;
            let quota = module.resource_status()?;
            rejected(
                fixture
                    .subject()?
                    .digest_sha256(
                        &[b"abc"],
                        InputLimits {
                            maximum_parts: 1,
                            maximum_total_bytes: 2,
                        },
                    )
                    .map(|_| ())
                    .map_err(Failure::from),
                RejectionReason::ClassicalSignatures(
                    ClassicalSignaturesRejection::CryptoTotalCeiling,
                ),
            )?;
            if module.call_counts()? != counts || module.resource_status()? != quota {
                return Err(Failure::Oracle("preparation_refusal_dispatch_or_quota"));
            }
            fixture.ticket = Some(
                fixture
                    .subject()?
                    .begin_native_digest(NativeDigestAlgorithm::Sha256)?,
            );
            fixture.update(b"abc", limits)?;
            fixture.finish()?;
            finished = true;
        }
        "drop-observer" => {
            if state != State::Active {
                return Err(Failure::Input("drop_observer_initial_state"));
            }
            let counts = module.call_counts()?;
            let quota = module.resource_status()?;
            drop(fixture.ticket.take());
            match fixture
                .subject()?
                .begin_native_digest(NativeDigestAlgorithm::Sha256)
            {
                Err(Error::Busy(BusyReason::OperationOwnership(
                    OperationOwnershipBusy::AdvancedOperation,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("dropped_observer_lost_owner")),
            }
            if module.call_counts()? != counts || module.resource_status()? != quota {
                return Err(Failure::Oracle("drop_observer_dispatch_or_quota"));
            }
            fixture.close_subject()?;
            let after = module.resource_status()?;
            if quota.usage.total != 2 || after.usage.total != 1 || after.usage.open != 1 {
                return Err(Failure::Oracle("explicit_close_quota_settlement"));
            }
            finished = true;
        }
        "detach" => {
            if state != State::Active {
                return Err(Failure::Input("detachment_requires_live_digest"));
            }
            let before = module.call_counts()?;
            let owner = fixture
                .subject
                .as_ref()
                .ok_or(Failure::Input("digest_subject"))?;
            let ticket = fixture
                .ticket
                .as_mut()
                .ok_or(Failure::Input("digest_ticket"))?;
            rejected(
                owner
                    .start_detachment(ticket, 4096)
                    .map(|_| ())
                    .map_err(Failure::from),
                RejectionReason::Detachment(DetachmentRejection::AsynchronousDetachmentSessionMode),
            )?;
            if module.call_counts()? != before {
                return Err(Failure::Oracle("synchronous_detachment_dispatched"));
            }
        }
        "init" => {
            let result = fixture
                .subject()?
                .begin_native_digest(NativeDigestAlgorithm::Sha256);
            if state == State::Closed {
                rejected(result.map(|_| ()).map_err(Failure::from), closed)?;
            } else if state == State::Absent || state == State::Published {
                fixture.ticket = Some(result?);
                fixture.update(b"abc", limits)?;
                fixture.finish()?;
                finished = true;
            } else {
                match result {
                    Err(Error::Busy(BusyReason::OperationOwnership(
                        OperationOwnershipBusy::AdvancedOperation,
                    ))) => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("second_digest_init_not_refused")),
                }
            }
        }
        "update" => {
            let result = fixture.update(b"d", limits);
            if state == State::Closed {
                rejected(result, closed)?;
            } else if state == State::Published {
                rejected(result, consumed)?;
            } else {
                result?;
                fixture.finish()?;
                finished = true;
            }
        }
        "final" => {
            let result = fixture.finish();
            if state == State::Closed {
                rejected(result, closed)?;
            } else if state == State::Published {
                rejected(result, consumed)?;
            } else {
                result?;
                finished = true;
            }
        }
        "take" => {
            let reason = if state == State::Closed {
                closed
            } else if state == State::Absent || state == State::Published {
                RejectionReason::OperationOwnership(OperationOwnershipRejection::OperationAbsent)
            } else {
                RejectionReason::DigestContinuation(
                    DigestContinuationRejection::DigestContinuationTicketUnavailable,
                )
            };
            rejected(
                fixture
                    .subject()?
                    .take_digest_ticket()
                    .map(|_| ())
                    .map_err(Failure::from),
                reason,
            )?;
        }
        "poll" => {
            let owner = fixture
                .subject
                .as_ref()
                .ok_or(Failure::Input("digest_subject"))?;
            let ticket = fixture
                .ticket
                .as_mut()
                .ok_or(Failure::Input("digest_ticket"))?;
            let result = owner.poll(ticket);
            if state == State::Closed {
                rejected(result.map(|_| ()).map_err(Failure::from), closed)?;
            } else if state == State::Published {
                rejected(result.map(|_| ()).map_err(Failure::from), consumed_generic)?;
            } else {
                if !matches!(result?, OperationProgress::Ready) {
                    return Err(Failure::Oracle("open_digest_poll_must_be_ready"));
                }
                fixture.update(b"d", limits)?;
                fixture.finish()?;
                finished = true;
            }
        }
        "output_capacity" => {
            let ticket = fixture
                .ticket
                .as_ref()
                .ok_or(Failure::Input("digest_ticket"))?;
            let result = fixture
                .subject()?
                .provide_digest_output_capacity(ticket, 32)
                .map_err(Failure::from);
            rejected(
                result,
                if state == State::Closed {
                    closed
                } else if state == State::Published {
                    consumed
                } else {
                    RejectionReason::DigestContinuation(
                        DigestContinuationRejection::DigestOutputIsNotAwaitingStorage,
                    )
                },
            )?;
        }
        "capture" | "capture-credits" => {
            if action == "capture-credits" && state != State::Active {
                return Err(Failure::Input("capture_credit_initial_state"));
            }
            // This public snapshot covers session quotas. It does not expose
            // the private byte-budget balance, which is not inferred here.
            let quota = if action == "capture-credits" {
                Some(module.resource_status()?)
            } else {
                None
            };
            let ticket = fixture
                .ticket
                .as_ref()
                .ok_or(Failure::Input("digest_ticket"))?;
            let result = fixture
                .subject()?
                .start_state_capture(ticket, 4096)
                .map(|_| ());
            if state == State::Closed {
                rejected(result.map_err(Failure::from), closed)?;
            } else if state == State::Published {
                rejected(result.map_err(Failure::from), consumed_generic)?;
            } else {
                native(
                    result,
                    "C_GetOperationState",
                    fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64,
                    report,
                )?;
            }
            if let Some(quota) = quota {
                if module.resource_status()? != quota {
                    return Err(Failure::Oracle("capture_refusal_quota_changed"));
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
            fixture
                .peer
                .as_ref()
                .ok_or(Failure::Input("digest_peer"))?
                .logout()?;
            fixture.logged_in = false;
        }
        "close" => {
            let result = fixture.close_subject();
            if state == State::Closed {
                rejected(result, closed)?;
            } else {
                result?;
            }
        }
        "drop_ticket" => {
            drop(fixture.ticket.take());
        }
        "read_output" => {
            fixture.check_output(&case.producer)?;
        }
        _ => return Err(Failure::Input("digest_action")),
    }
    // Prove that an ordinary refusal left the *same* ticket usable. Closing or
    // dropping deliberately has no continuation; no replacement Init is hidden.
    if active && !finished && !matches!(action, "close" | "drop_ticket") {
        fixture.finish()?;
    }
    if fixture.published.is_some() {
        fixture.check_output(&case.expected)?;
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = Fixture::empty();
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        fixture.prepare(&module, config, pins, case.state)?;
        if case.state == State::Published {
            fixture.check_output(&case.producer)?;
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let mut previous = None;
    let (setup_result, body, expected) = match setup {
        Err(error) => (Err(error), Ok(()), None),
        Ok(case) => {
            if case.state == State::Published && case.action == "init" {
                previous = fixture.published.take();
            }
            let result = action(&module, &mut fixture, &case, pins, &mut report);
            (Ok(()), result, Some((case.producer, case.expected)))
        }
    };
    let mut cleanup = fixture.cleanup();
    if let Some((producer, expected)) = expected {
        if fixture.published.is_some() {
            if let Err(error) = fixture.check_output(&expected) {
                cleanup.push(error);
            }
        }
        if let Some(value) = &previous {
            if value.as_bytes() != producer {
                cleanup.push(Failure::Oracle("previous_published_digest_changed"));
            }
        }
    }
    drop(previous);
    drop(fixture);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
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
            "digest_transition_and_owned_result",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup_result.is_ok() {
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
