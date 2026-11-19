// SPDX-License-Identifier: Apache-2.0
//! Preserve phase failures without printing cryptographic inputs or panic payloads.
use crate::report::{Observation, Phase, Producer, Report};
use std::io::{self, Write};

pub enum Failure {
    Product(fe11::Error),
    Oracle(&'static str),
    Input(&'static str),
    DirectNative { function: &'static str, code: u64 },
}

impl From<fe11::Error> for Failure {
    fn from(error: fe11::Error) -> Self {
        Self::Product(error)
    }
}

pub fn record<W: Write>(report: &mut Report<W>, phase: Phase, failure: &Failure) -> io::Result<()> {
    match failure {
        Failure::Oracle(name) => report.observation(
            phase,
            name,
            Producer::TestOracle,
            Observation::Boolean(false),
        ),
        Failure::Input(name) => report.observation(
            phase,
            name,
            Producer::Supervisor,
            Observation::Boolean(false),
        ),
        Failure::Product(error) => product(report, phase, error),
        Failure::DirectNative { function, code } => report.observation(
            phase,
            function,
            Producer::Native,
            Observation::Number(*code),
        ),
    }
}

fn product<W: Write>(report: &mut Report<W>, phase: Phase, error: &fe11::Error) -> io::Result<()> {
    match error {
        fe11::Error::CleanupFailed { operation, cleanup } => {
            // These are both parts of the reported invocation's error, not a
            // new cleanup performed by this reporting function. Keep their
            // order and typed causes without formatting arbitrary error text.
            report.observation(
                phase,
                "compound_cleanup_failure",
                Producer::Fe11Local,
                Observation::Boolean(true),
            )?;
            product(report, phase, operation)?;
            product(report, phase, cleanup)
        }
        fe11::Error::Busy(reason) => report.observation(
            phase,
            "local_busy",
            Producer::Fe11Local,
            Observation::Busy(*reason),
        ),
        fe11::Error::Rejected(reason) => report.observation(
            phase,
            "local_rejection",
            Producer::Fe11Local,
            Observation::Rejected(*reason),
        ),
        fe11::Error::Native {
            function,
            code,
            may_have_effect,
        } => report.observation(
            phase,
            "native_error",
            Producer::Native,
            Observation::Native {
                function,
                code: *code,
                may_have_effect: *may_have_effect,
            },
        ),
        fe11::Error::ObjectsMayRemain(cause) => {
            report.observation(
                phase,
                "objects_may_remain",
                Producer::Fe11Local,
                Observation::Boolean(true),
            )?;
            product(report, phase, cause)
        }
        fe11::Error::NativeAndLocalFailure {
            function,
            code,
            cause,
        } => {
            // This variant does not establish the effect classification. Do not
            // manufacture a may_have_effect value to fit the ordinary error shape.
            report.observation(
                phase,
                function,
                Producer::Native,
                Observation::Number(*code),
            )?;
            product(report, phase, cause)
        }
        _ => report.observation(
            phase,
            "unexpected_fe11_error",
            Producer::Fe11Local,
            Observation::Boolean(true),
        ),
    }
}
