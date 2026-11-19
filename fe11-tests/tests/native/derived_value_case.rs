// SPDX-License-Identifier: Apache-2.0
//! Base and derived-key ownership, with independent cleanup reporting.
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

pub trait DerivedValueCase: Sized {
    fn read(path: &Path) -> std::result::Result<Self, Failure>;
    fn advanced(&self) -> bool;
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef>;
    fn parameters(&self) -> NativeKeyDerivation<'_>;
    fn expected(&self) -> &[u8];
    /// Distinguish an original published answer from an independently calculated one.
    fn expected_origin(&self) -> ExpectedOrigin {
        ExpectedOrigin::Published
    }
    /// A refusal fixture uses the same creation-owner cleanup as a value case,
    /// while making its different oracle explicit before execution.
    fn observation(&self) -> (&'static str, Producer) {
        self.expected_origin().observation()
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        retained: &mut Option<CreatedObjectSet>,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        super::derived_value::check(owner, key, self.parameters(), self.expected(), retained)
    }
}

#[derive(Clone, Copy)]
pub enum ExpectedOrigin {
    Published,
    IndependentlyCalculated,
}

impl ExpectedOrigin {
    pub(super) fn observation(self) -> (&'static str, Producer) {
        match self {
            Self::Published => ("published_derived_value", Producer::PublishedVector),
            Self::IndependentlyCalculated => (
                "independently_calculated_derived_value",
                Producer::IndependentReference,
            ),
        }
    }
}

pub fn execute<V: DerivedValueCase, W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut derived = None;
    let setup = (|| -> std::result::Result<V, Failure> {
        let vector = V::read(path)?;
        owner = Some(Owner::open(&module, config, vector.advanced())?);
        let owner = owner.as_ref().ok_or(Failure::Input("single_key_owner"))?;
        key = Some(vector.import(owner)?);
        Ok(vector)
    })();
    let started = setup.is_ok();
    let observation = setup.as_ref().ok().map(|vector| vector.observation());
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(vector) => (
            Ok(()),
            match (&owner, &key) {
                (Some(owner), Some(key)) => vector.check(owner, key, &mut derived, &mut report),
                _ => Err(Failure::Input("single_key_fixture_incomplete")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let (Some(owner), Some(objects)) = (&owner, &derived) {
        for object in objects.as_slice() {
            let result = match owner {
                Owner::Session(session) => session.destroy_native_object(object),
                Owner::Advanced(session) => session.destroy_native_object(object),
            };
            if let Err(error) = result {
                cleanup.push(error.into());
            }
        }
    }
    drop(derived);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(key.as_ref()));
    }
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
    if let Some((assertion, producer)) = observation {
        report.observation(
            Phase::Body,
            assertion,
            producer,
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

/// Group value-producing routes without changing their individual fixture contracts.
pub fn dispatch<W: Write>(
    module: Module,
    args: &super::arguments::Arguments,
    report: Report<W>,
) -> io::Result<bool> {
    match args.mode.as_str() {
        "encrypt-data-vector" => execute::<super::encrypt_data_fixture::Vector, _>(
            module,
            &args.config,
            &args.vector,
            report,
        ),
        "dh-vector" => {
            execute::<super::dh_fixture::Vector, _>(module, &args.config, &args.vector, report)
        }
        "ecdh-vector" => {
            execute::<super::ecdh_fixture::Vector, _>(module, &args.config, &args.vector, report)
        }
        "concatenation-values" => execute::<super::concatenation_values::Case, _>(
            module,
            &args.config,
            &args.vector,
            report,
        ),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "derivation route",
        )),
    }
}
