// SPDX-License-Identifier: Apache-2.0
//! Exact family and identity refusals, preserving every live digest continuation.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    ticket_family_dispatch,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Partition {
    Family,
    Foreign,
    Consumed,
}

struct Case {
    advanced: bool,
    partition: Partition,
    method: String,
    expected: RejectionReason,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("vector_open"))?
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("vector_read"))?;
    if bytes.len() > 1024 {
        return Err(Failure::Input("vector_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 3 {
        return Err(Failure::Input("vector_fields"));
    }
    let advanced = match fields[0] {
        "session" => false,
        "advanced" => true,
        _ => return Err(Failure::Input("ticket_owner")),
    };
    let partition = match fields[2] {
        "family" => Partition::Family,
        "foreign" => Partition::Foreign,
        "consumed" => Partition::Consumed,
        _ => return Err(Failure::Input("ticket_partition")),
    };
    let expected = if partition == Partition::Family {
        ticket_family_dispatch::expected(fields[1])?
    } else {
        ticket_family_dispatch::identity_error(fields[1])?
    };
    if advanced && fields[1].starts_with("poll_") {
        return Err(Failure::Input("ticket_family_route"));
    }
    Ok(Case {
        advanced,
        partition,
        method: fields[1].to_owned(),
        expected,
    })
}

fn begin(owner: &Owner) -> Result<OperationTicket> {
    match owner {
        Owner::Session(session) => session.begin_digest(HashAlgorithm::Sha256),
        Owner::Advanced(session) => session.begin_digest(HashAlgorithm::Sha256),
    }
}

fn resume(owner: &Owner, ticket: &mut OperationTicket) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    let digest = match owner {
        Owner::Session(session) => {
            session.digest_update(ticket, b"abc", limits)?;
            session.finish_digest(ticket)?
        }
        Owner::Advanced(session) => {
            session.digest_update(ticket, b"abc", limits)?;
            match session.finish_digest(ticket)? {
                OperationProgress::Digest(value) => value,
                _ => return Err(Failure::Oracle("digest_completion")),
            }
        }
    };
    let expected = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected || digest.algorithm() != HashAlgorithm::Sha256 {
        return Err(Failure::Oracle("digest_continuation_changed"));
    }
    Ok(())
}

fn check<W: Write>(
    owner: &Owner,
    receiver: &Owner,
    ticket: &mut OperationTicket,
    case: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let attempted = ticket_family_dispatch::invoke(
        receiver,
        &case.method,
        ticket,
        case.partition != Partition::Family,
    )?;
    let assertion = match attempted {
        Err(error @ Error::Rejected(reason)) if reason == case.expected => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("wrong_ticket_family_accepted")),
    };
    // Check preservation even when the primary family assertion fails. Closing
    // the session alone would not establish that the original digest survived.
    let continuation = if case.partition == Partition::Consumed {
        Ok(())
    } else {
        resume(owner, ticket)
    };
    if let Err(error) = &continuation {
        outcome::record(report, Phase::Body, error).map_err(|_| Failure::Input("report_write"))?;
    }
    assertion?;
    continuation
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut peer = None;
    let mut ticket = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        owner = Some(Owner::open(&module, config, case.advanced)?);
        // Capacity-family guards use a cooperative, caller-fed digest. No
        // optional capture may introduce a native state query before the guard.
        if matches!(
            case.method.as_str(),
            "resize_cipher_output"
                | "resize_aes_output"
                | "prepare_aead_message_output"
                | "resize_recovery_output"
                | "provide_signature_output_capacity"
        ) {
            if let Some(Owner::Advanced(session)) = &mut owner {
                session.set_pacing(OperationPacing::Cooperative)?;
                session.set_validation_capture(ValidationCaptureMode::Disabled)?;
            }
        }
        if case.partition == Partition::Foreign {
            peer = Some(Owner::open(&module, config, case.advanced)?);
        }
        ticket = Some(begin(
            owner.as_ref().ok_or(Failure::Input("ticket_owner"))?,
        )?);
        if case.partition == Partition::Consumed {
            resume(
                owner.as_ref().ok_or(Failure::Input("ticket_owner"))?,
                ticket.as_mut().ok_or(Failure::Input("ticket_owner"))?,
            )?;
        }
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match (&owner, &mut ticket) {
                (Some(owner), Some(ticket)) => check(
                    owner,
                    peer.as_ref().unwrap_or(owner),
                    ticket,
                    &case,
                    &mut report,
                ),
                _ => Err(Failure::Input("ticket_fixture_incomplete")),
            },
        ),
    };
    drop(ticket);
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |owner| owner.close(None));
    if let Some(peer) = &peer {
        cleanup.extend(peer.close(None));
    }
    drop(peer);
    drop(owner);
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
            "ticket_family_and_continuation",
            Producer::Fe11Local,
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
