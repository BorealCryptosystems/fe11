// SPDX-License-Identifier: Apache-2.0
//! One-key case ownership; setup, operation and cleanup retain separate verdicts.
use super::{
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

pub trait SingleKeyCase: Sized {
    const ASSERTION: &'static str;
    /// Provenance of the asserted answer, distinct from the origin of key bytes.
    /// Permission and state-machine refusals use TestOracle even when their
    /// otherwise valid inputs were taken from published known-answer vectors.
    const PRODUCER: Producer = Producer::PublishedVector;
    fn read(path: &Path) -> std::result::Result<Self, Failure>;
    /// Establish a caller-owned declaration before any key or session is made.
    fn bind_module(&mut self, _module: &Module) -> std::result::Result<(), Failure> {
        Ok(())
    }
    fn advanced(&self) -> bool;
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure>;
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure>;
}

pub fn execute<V: SingleKeyCase, W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let setup = (|| -> std::result::Result<V, Failure> {
        let mut vector = V::read(path)?;
        vector.bind_module(&module)?;
        owner = Some(Owner::open(&module, config, vector.advanced())?);
        let owner = owner.as_ref().ok_or(Failure::Input("single_key_owner"))?;
        key = Some(vector.import(owner)?);
        Ok(vector)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => vector.check(owner, key, &mut report),
                _ => Err(Failure::Input("single_key_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |owner| owner.close(key.as_ref()));
    drop(key);
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
            V::ASSERTION,
            V::PRODUCER,
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
