// SPDX-License-Identifier: Apache-2.0
//! Digest views must leave a live caller-fed AES operation finishable.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
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
}
fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("digest_view_open"))?
        .take(129)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("digest_view_read"))?;
    let f: Vec<_> = text.split_terminator('\n').collect();
    if text.len() > 128
        || f.len() != 2
        || !matches!(f[0], "session" | "advanced")
        || !matches!(
            f[1],
            "take_digest_ticket" | "digest_progress" | "digest_output_requirement"
        )
    {
        return Err(Failure::Input("digest_view_fixture"));
    }
    Ok(Case {
        advanced: f[0] == "advanced",
        method: f[1].into(),
    })
}

fn begin(owner: &Owner, key: &NativeObjectRef) -> Result<OperationTicket> {
    let parameters = CipherParameters::Aes(AesCipherParameters::Ecb);
    let output = CipherOutputPlan::Buffer { capacity: 48 };
    match owner {
        Owner::Session(s) => {
            s.begin_encrypt_stream(CipherKeyReference::Secret(key), parameters, output)
        }
        Owner::Advanced(s) => {
            s.begin_encrypt_stream(CipherKeyReference::Secret(key), parameters, output)
        }
    }
}
fn continue_cipher(
    owner: &Owner,
    ticket: &mut OperationTicket,
) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 16,
    };
    let update = match owner {
        Owner::Session(s) => s.cipher_update(ticket, &[0; 16], limits),
        Owner::Advanced(s) => s.cipher_update(ticket, &[0; 16], limits),
    }?;
    if !matches!(update, OperationProgress::Ready) {
        return Err(Failure::Oracle("digest_view_cipher_update"));
    }
    let result = match owner {
        Owner::Session(s) => s.finish_cipher_stream(ticket),
        Owner::Advanced(s) => s.finish_cipher_stream(ticket),
    }?;
    let expected = hex("c6a13b37878f5b826f4f8162a1c8d879", 16).map_err(Failure::Input)?;
    match result {
        OperationProgress::CipherEncrypted(output) if output.as_bytes() == expected => Ok(()),
        _ => Err(Failure::Oracle("digest_view_cipher_known_answer")),
    }
}
fn check<W: Write>(
    module: &Module,
    owner: &Owner,
    ticket: &mut OperationTicket,
    case: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    let progress = ticket.cipher_progress()?;
    if progress != (StreamInputStatus::Open, StreamProgress::default()) {
        return Err(Failure::Oracle("digest_view_live_caller_input"));
    }
    let result = match case.method.as_str() {
        "take_digest_ticket" => match owner {
            Owner::Session(s) => s.take_digest_ticket().map(|_| ()),
            Owner::Advanced(s) => s.take_digest_ticket().map(|_| ()),
        },
        "digest_progress" => ticket.digest_progress().map(|_| ()),
        "digest_output_requirement" => ticket.digest_output_requirement().map(|_| ()),
        _ => return Err(Failure::Input("digest_view_method")),
    };
    let assertion = (|| {
        match result {
            Err(
                error @ Error::Rejected(RejectionReason::OperationOwnership(
                    OperationOwnershipRejection::DigestTicketRequired,
                )),
            ) => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("digest_view_cipher_accepted")),
        }
        if module.call_counts()? != before || ticket.cipher_progress()? != progress {
            return Err(Failure::Oracle("digest_view_changed_cipher"));
        }
        Ok::<_, Failure>(())
    })();
    // Attempt the real continuation even when the refusal assertion failed.
    // A successful Close alone cannot demonstrate preservation of the owner.
    let continuation = continue_cipher(owner, ticket);
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
    let mut key = None;
    let mut ticket = None;
    let setup = (|| {
        let case = read(path)?;
        owner = Some(Owner::open(&module, config, case.advanced)?);
        let o = owner.as_ref().ok_or(Failure::Input("digest_view_owner"))?;
        let material = hex("000102030405060708090a0b0c0d0e0f", 16).map_err(Failure::Input)?;
        key = Some(o.import_secret(
            &material,
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?);
        ticket = Some(begin(
            o,
            key.as_ref().ok_or(Failure::Input("digest_view_key"))?,
        )?);
        Ok::<_, Failure>(case)
    })();
    let body = match (&setup, &owner, &mut ticket) {
        (Ok(case), Some(o), Some(t)) => check(&module, o, t, case, &mut report),
        (Err(_), _, _) => Ok(()),
        _ => Err(Failure::Input("digest_view_incomplete_setup")),
    };
    drop(ticket);
    let mut cleanup = owner
        .as_ref()
        .map(|o| o.close(key.as_ref()))
        .unwrap_or_default();
    drop(key);
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
