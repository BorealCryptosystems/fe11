// SPDX-License-Identifier: Apache-2.0
//! Explicitly recover a facade-retained digest after a real short output buffer.
use super::{
    arguments::hex,
    configuration::Configuration,
    digest_capacity_fixture::too_small,
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
    advanced: bool,
    action: String,
    expected: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("retained_digest_open"))?
            .take(257)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("retained_digest_read"))?;
        if data.len() > 256 {
            return Err(Failure::Input("retained_digest_size"));
        }
        let text =
            std::str::from_utf8(&data).map_err(|_| Failure::Input("retained_digest_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !matches!(fields[0], "Session" | "AdvancedSession")
            || !matches!(fields[1], "take" | "update" | "consumed")
        {
            return Err(Failure::Input("retained_digest_fields"));
        }
        let expected = hex(fields[2], 32).map_err(Failure::Input)?;
        if expected.len() != 32 {
            return Err(Failure::Input("retained_digest_width"));
        }
        Ok(Self {
            advanced: fields[0] == "AdvancedSession",
            action: fields[1].into(),
            expected,
        })
    }
}
fn start(module: &Module, owner: &Owner) -> std::result::Result<(), Failure> {
    // SAFETY: the selected module supports standard parameterless SHA256 from
    // 2.40 onward. Exactly DigestInit/Update/Final, no key or pointer parameters.
    let contract = unsafe {
        module.declare_mechanism_extension(
            fe11_sys::CKM_SHA256 as u64,
            (2, 40),
            ExtensionOperation::DigestMultipart,
            false,
        )
    }?;
    // SAFETY: empty graph is precisely the native NULL/0 parameter representation.
    let request = unsafe {
        ExtensionRequest::new(
            &contract,
            ExtensionParameters {
                blocks: &[],
                pointers: &[],
                root: None,
                outputs: &[],
            },
        )
    };
    let input = ExtensionInput::DigestMultipart {
        parts: &[b"abc"],
        output_capacity: 31,
    };
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    too_small(match owner {
        Owner::Session(s) => s.execute_extension(request, input, limits, None),
        Owner::Advanced(s) => s.execute_extension(request, input, limits, None),
    })
}
fn take(owner: &Owner) -> Result<OperationTicket> {
    match owner {
        Owner::Session(s) => s.take_digest_ticket(),
        Owner::Advanced(s) => s.take_digest_ticket(),
    }
}
fn refusal<T>(
    result: Result<T>,
    expected: DigestContinuationRejection,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::DigestContinuation(actual))) if actual == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("retained_digest_refusal_missing")),
    }
}
fn finish(
    owner: &Owner,
    ticket: &mut OperationTicket,
) -> std::result::Result<ExtensionResult, Failure> {
    match owner {
        Owner::Session(s) => Ok(s.finish_extension_digest_stream(ticket)?),
        Owner::Advanced(s) => match s.finish_extension_digest_stream(ticket)? {
            OperationProgress::ExtensionDigest(value) => Ok(value),
            _ => Err(Failure::Oracle("retained_digest_result_owner")),
        },
    }
}
fn check(
    module: &Module,
    owner: &Owner,
    ticket: &mut Option<OperationTicket>,
    case: &Case,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    *ticket = Some(take(owner)?);
    refusal(
        take(owner),
        DigestContinuationRejection::DigestContinuationTicketUnavailable,
    )?;
    let ticket = ticket
        .as_mut()
        .ok_or(Failure::Input("retained_digest_ticket"))?;
    if ticket.extension_digest_output_requirement()? != Some(32) {
        return Err(Failure::Oracle("retained_digest_requirement"));
    }
    if case.action == "update" {
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 1,
        };
        refusal(
            match owner {
                Owner::Session(s) => s.digest_update(ticket, b"d", limits),
                Owner::Advanced(s) => s.digest_update(ticket, b"d", limits),
            },
            DigestContinuationRejection::DigestInputPhase,
        )?;
    }
    match owner {
        Owner::Session(s) => s.provide_digest_output_capacity(ticket, 32)?,
        Owner::Advanced(s) => s.provide_digest_output_capacity(ticket, 32)?,
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("retained_digest_local_dispatch"));
    }
    let output = finish(owner, ticket)?;
    let mut expected = before;
    *expected.entry("C_DigestFinal").or_default() += 1;
    if module.call_counts()? != expected {
        return Err(Failure::Oracle("retained_digest_input_replay"));
    }
    if output.as_bytes() != case.expected {
        return Err(Failure::Oracle("retained_digest_known_answer"));
    }
    if case.action == "consumed" {
        let before = module.call_counts()?;
        refusal(
            ticket.extension_digest_output_requirement(),
            DigestContinuationRejection::ConsumedDigestTicket,
        )?;
        if module.call_counts()? != before {
            return Err(Failure::Oracle("consumed_digest_accessor_dispatched"));
        }
    }
    Ok(())
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
        start(
            &module,
            owner
                .as_ref()
                .ok_or(Failure::Input("retained_digest_owner"))?,
        )?;
        Ok(case)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(case) => match owner.as_ref() {
            Some(owner) => check(&module, owner, &mut ticket, case),
            None => Err(Failure::Input("retained_digest_owner")),
        },
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
            "retained_digest_transfer_and_exact_resume",
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
