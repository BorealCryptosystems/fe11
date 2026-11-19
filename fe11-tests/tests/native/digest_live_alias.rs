// SPDX-License-Identifier: Apache-2.0
//! Generic polling and family refusals preserve an open, real digest operation.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    ticket_identity_action,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    advanced: bool,
    action: String,
    expected: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("digest_alias_open"))?
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("digest_alias_read"))?;
        if bytes.len() > 256 {
            return Err(Failure::Input("digest_alias_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("digest_alias_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !matches!(fields[0], "Session" | "AdvancedSession")
            || !matches!(
                fields[1],
                "poll" | "message_progress" | "gcm" | "ccm" | "chacha" | "salsa"
            )
        {
            return Err(Failure::Input("digest_alias_fields"));
        }
        let advanced = fields[0] == "AdvancedSession";
        if !advanced && !matches!(fields[1], "poll" | "message_progress") {
            return Err(Failure::Input("digest_alias_receiver"));
        }
        let expected = hex(fields[2], 32).map_err(Failure::Input)?;
        if expected.len() != 32 {
            return Err(Failure::Input("digest_alias_width"));
        }
        Ok(Self {
            advanced,
            action: fields[1].into(),
            expected,
        })
    }
}

fn check(
    owner: &Owner,
    ticket: &mut OperationTicket,
    action: &str,
) -> std::result::Result<(), Failure> {
    if action == "poll" {
        let progress = match owner {
            Owner::Session(s) => s.poll_signature(ticket)?,
            Owner::Advanced(s) => s.poll_signature(ticket)?,
        };
        return if matches!(progress, OperationProgress::Ready) {
            Ok(())
        } else {
            Err(Failure::Oracle("open_digest_poll_not_ready"))
        };
    }
    let (result, expected) = if action == "message_progress" {
        (
            ticket.message_signature_progress().map(|_| ()),
            RejectionReason::SignatureMessages(
                SignatureMessagesRejection::MessageSignatureTicketRequired,
            ),
        )
    } else {
        let Owner::Advanced(session) = owner else {
            return Err(Failure::Input("digest_alias_owner"));
        };
        let limits = RecordLimits {
            bytes: 1_048_576,
            messages: 1,
            fragments: 1,
        };
        let result = match action {
            "gcm" => session.capture_gcm_recovery(ticket, limits).map(|_| ()),
            "ccm" => session.capture_ccm_recovery(ticket, limits).map(|_| ()),
            "chacha" => session
                .capture_stream_aead_recovery(ticket, limits, StreamAeadAlgorithm::ChaCha20)
                .map(|_| ()),
            "salsa" => session
                .capture_stream_aead_recovery(ticket, limits, StreamAeadAlgorithm::Salsa20)
                .map(|_| ()),
            _ => return Err(Failure::Input("digest_alias_action")),
        };
        (
            result,
            RejectionReason::AeadMessages(
                AeadMessagesRejection::RecoveryRequiresAeadMessageDecryption,
            ),
        )
    };
    match result {
        Err(Error::Rejected(actual)) if actual == expected => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("digest_wrong_family_accepted")),
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut ticket = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, case.advanced)?);
        let receiver = owner.as_mut().ok_or(Failure::Input("digest_alias_owner"))?;
        if let Owner::Advanced(session) = receiver {
            session.set_pacing(OperationPacing::Cooperative)?;
            session.set_validation_capture(ValidationCaptureMode::Disabled)?;
        }
        ticket = Some(ticket_identity_action::begin(receiver)?);
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => (|| -> std::result::Result<(), Failure> {
            let receiver = owner.as_ref().ok_or(Failure::Input("digest_alias_owner"))?;
            let ticket = ticket
                .as_mut()
                .ok_or(Failure::Input("digest_alias_ticket"))?;
            let before = module.call_counts()?;
            check(receiver, ticket, &case.action)?;
            if before != module.call_counts()? {
                return Err(Failure::Oracle("digest_alias_native_dispatch"));
            }
            let digest = ticket_identity_action::finish(receiver, ticket)?;
            if digest.as_bytes() != case.expected {
                return Err(Failure::Oracle("digest_alias_original_result"));
            }
            Ok(())
        })(),
    };
    drop(ticket);
    let mut cleanup = owner.as_ref().map(|o| o.close(None)).unwrap_or_default();
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
    if setup.is_ok() {
        report.observation(
            Phase::Body,
            "live_digest_preserved_after_local_action",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if setup.is_err() {
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
