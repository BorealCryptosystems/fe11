// SPDX-License-Identifier: Apache-2.0
//! Ticket accessors refuse consumed owners without executing another native call.
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
    action: String,
    consumed: bool,
    expected: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 256 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3 || !matches!(fields[1], "live" | "consumed") {
            return Err(Failure::Input("ticket_guard_fields"));
        }
        let consumed = matches!(
            fields[0],
            "aead_progress"
                | "cipher_progress"
                | "digest_requirement"
                | "digest_progress"
                | "created_objects"
                | "signature_progress"
                | "message_progress"
        );
        if (!consumed
            && !matches!(
                fields[0],
                "cancellation_absent" | "digest_ticket_absent" | "dual_recovery_family"
            ))
            || consumed != (fields[1] == "consumed")
        {
            return Err(Failure::Input("ticket_guard_state"));
        }
        let expected = hex(fields[2], 32).map_err(Failure::Input)?;
        if expected.len() != 32 {
            return Err(Failure::Input("digest_width"));
        }
        Ok(Self {
            action: fields[0].into(),
            consumed,
            expected,
        })
    }
}
fn check(f: &mut Fixture, module: &Module, case: &Case) -> std::result::Result<(), Failure> {
    let ticket = f.ticket.as_ref().ok_or(Failure::Input("digest_ticket"))?;
    let before = module.call_counts()?;
    let (result, reason) = match case.action.as_str() {
        "aead_progress" => (
            ticket.aead_message_progress().map(|_| ()),
            RejectionReason::AeadMessages(AeadMessagesRejection::ConsumedAeadMessageTicket),
        ),
        "cipher_progress" => (
            ticket.cipher_progress().map(|_| ()),
            RejectionReason::CipherContinuation(CipherContinuationRejection::ConsumedCipherTicket),
        ),
        "digest_requirement" => (
            ticket.digest_output_requirement().map(|_| ()),
            RejectionReason::DigestContinuation(DigestContinuationRejection::ConsumedDigestTicket),
        ),
        "digest_progress" => (
            ticket.digest_progress().map(|_| ()),
            RejectionReason::OperationOwnership(
                OperationOwnershipRejection::ConsumedOperationTicket,
            ),
        ),
        "created_objects" => (
            ticket.created_objects().map(|_| ()),
            RejectionReason::OperationOwnership(
                OperationOwnershipRejection::ConsumedOperationTicket,
            ),
        ),
        "signature_progress" => (
            ticket.signature_progress().map(|_| ()),
            RejectionReason::SignatureContinuation(
                SignatureContinuationRejection::ConsumedSignatureTicket,
            ),
        ),
        "message_progress" => (
            ticket.message_signature_progress().map(|_| ()),
            RejectionReason::SignatureMessages(SignatureMessagesRejection::ConsumedMessageTicket),
        ),
        "cancellation_absent" => (
            f.subject()?.poll_cancellation().map(|_| ()),
            RejectionReason::Cancellation(CancellationRejection::CancellationAbsent),
        ),
        "digest_ticket_absent" => (
            f.subject()?.take_digest_ticket().map(|_| ()),
            RejectionReason::DigestContinuation(
                DigestContinuationRejection::DigestContinuationTicketUnavailable,
            ),
        ),
        "dual_recovery_family" => (
            f.subject()?
                .capture_dual_gcm_recovery(
                    ticket,
                    RecordLimits {
                        bytes: 4096,
                        messages: 1,
                        fragments: 1,
                    },
                )
                .map(|_| ()),
            RejectionReason::CombinedOperations(
                CombinedOperationsRejection::RecoveryRequiresDualGcmDecryption,
            ),
        ),
        _ => return Err(Failure::Input("ticket_guard_action")),
    };
    match result {
        Err(Error::Rejected(actual)) if actual == reason => (),
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("ticket_guard_expected_refusal")),
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("ticket_guard_native_call"));
    }
    if !case.consumed {
        // A rejected accessor must not consume, cancel or replace the live owner.
        f.update(
            b"abc",
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        f.finish()?;
    }
    f.check_output(&case.expected)
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = Fixture::empty();
    let setup = Case::read(path).and_then(|case| {
        fixture.prepare(
            &module,
            config,
            pins,
            if case.consumed {
                State::Published
            } else {
                State::Initialized
            },
        )?;
        if case.consumed {
            fixture.check_output(&case.expected)?;
        }
        Ok(case)
    });
    let started = setup.is_ok();
    let (setup_result, body, expected) = match setup {
        Err(error) => (Err(error), Ok(()), None),
        Ok(case) => (
            Ok(()),
            check(&mut fixture, &module, &case),
            Some(case.expected),
        ),
    };
    let mut cleanup = fixture.cleanup();
    if body.is_ok() && started {
        if let Some(expected) = expected {
            if let Err(error) = fixture.check_output(&expected) {
                cleanup.push(error);
            }
        }
    }
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
            "exact_ticket_guard_and_retained_output",
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
