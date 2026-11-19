// SPDX-License-Identifier: Apache-2.0
//! Unsupported cancellation preserves the digest owner and its published output.
use super::{
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

const SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

fn read(path: &Path) -> std::result::Result<State, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("state_open"))?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("state_read"))?;
    if bytes.len() > 32 {
        return Err(Failure::Input("state_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("state_encoding"))?;
    let state = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("digest_state"))?;
    State::parse(state)
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = Fixture::empty();
    let setup = (|| -> std::result::Result<State, Failure> {
        let state = read(path)?;
        fixture.prepare(&module, config, pins, state)?;
        if state == State::Published {
            fixture.check_output(&SHA256_ABC)?;
        }
        Ok(state)
    })();
    let started = setup.is_ok();
    let mut previous = None;
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(state) => {
            let result = (|| -> std::result::Result<(), Failure> {
                match fixture.subject()?.cancel(CancellationFlags::DIGEST) {
                    Err(Error::Rejected(RejectionReason::SessionLifecycle(
                        SessionLifecycleRejection::SessionClosed,
                    ))) if state == State::Closed => (),
                    Err(Error::Rejected(RejectionReason::Cancellation(
                        CancellationRejection::CSessionCancelUnavailable,
                    ))) if state != State::Closed
                        && matches!(config.interface, InterfaceSelection::Legacy240) =>
                    {
                        ()
                    }
                    Err(
                        error @ Error::Native {
                            function: "C_SessionCancel",
                            code,
                            may_have_effect: false,
                        },
                    ) if state != State::Closed
                        && !matches!(config.interface, InterfaceSelection::Legacy240)
                        && code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 =>
                    {
                        outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))?;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("expected_cancellation_refusal")),
                }
                if matches!(state, State::Absent | State::Published) {
                    previous = fixture.published.take();
                    fixture.ticket = Some(
                        fixture
                            .subject()?
                            .begin_native_digest(NativeDigestAlgorithm::Sha256)?,
                    );
                }
                if matches!(
                    state,
                    State::Absent | State::Published | State::Initialized | State::LocalRefusal
                ) {
                    fixture.update(
                        b"abc",
                        InputLimits {
                            maximum_parts: 1,
                            maximum_total_bytes: 3,
                        },
                    )?;
                }
                if !matches!(state, State::TicketDropped | State::Closed) {
                    fixture.finish()?;
                    fixture.check_output(&SHA256_ABC)?;
                }
                Ok(())
            })();
            (Ok(()), result)
        }
    };
    let mut cleanup = fixture.cleanup();
    if fixture.published.is_some() {
        if let Err(error) = fixture.check_output(&SHA256_ABC) {
            cleanup.push(error);
        }
    }
    if let Some(value) = &previous {
        if value.algorithm() != NativeDigestAlgorithm::Sha256 || value.as_bytes() != SHA256_ABC {
            cleanup.push(Failure::Oracle("previous_published_digest_changed"));
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
            "unsupported_cancellation_preserves_digest",
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
