// SPDX-License-Identifier: Apache-2.0
//! Session overrides inherit the exact scoped deadline and cancellation signal.
use super::{
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

fn read(path: &Path) -> std::result::Result<bool, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(17)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("fixture_read"))?;
    match bytes.as_slice() {
        b"session\n" => Ok(false),
        b"advanced\n" => Ok(true),
        _ => Err(Failure::Input("admission_owner")),
    }
}
fn current(owner: &Owner) -> SessionAdmission {
    match owner {
        Owner::Session(s) => s.admission(),
        Owner::Advanced(s) => s.admission(),
    }
}
fn immediate(owner: &Owner) -> std::result::Result<(), Failure> {
    if matches!(current(owner), SessionAdmission::Immediate) {
        Ok(())
    } else {
        Err(Failure::Oracle("admission_not_immediate"))
    }
}
fn scoped(owner: &Owner, wanted: Instant, cancelled: bool) -> std::result::Result<(), Failure> {
    match current(owner) {
        SessionAdmission::WaitUntil {
            deadline,
            cancellation,
        } if deadline == wanted && cancellation.is_cancelled() == cancelled => Ok(()),
        _ => Err(Failure::Oracle("admission_deadline_or_signal_changed")),
    }
}
fn check(module: &Module, owner: &mut Owner) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    immediate(owner)?;
    // A supervision bound only: no waiting occurs in this accessor scenario.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(3600))
        .ok_or(Failure::Input("admission_deadline"))?;
    let signal = AdmissionCancellation::new();
    with_resource_admission(
        ResourceAdmission::WaitUntil {
            deadline,
            cancellation: signal.clone(),
        },
        || -> std::result::Result<(), Failure> {
            scoped(owner, deadline, false)?;
            match owner {
                Owner::Session(s) => s.set_admission(SessionAdmission::Immediate),
                Owner::Advanced(s) => s.set_admission(SessionAdmission::Immediate),
            }
            immediate(owner)?;
            match owner {
                Owner::Session(s) => s.inherit_admission(),
                Owner::Advanced(s) => s.inherit_admission(),
            }
            scoped(owner, deadline, false)?;
            signal.cancel();
            scoped(owner, deadline, true)
        },
    )?;
    immediate(owner)?;
    if module.call_counts()? != before {
        return Err(Failure::Oracle("admission_accessor_dispatched"));
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
    let setup = read(path).and_then(|advanced| {
        owner = Some(Owner::open(&module, config, advanced)?);
        Ok(())
    });
    let started = setup.is_ok();
    let body = if started {
        match &mut owner {
            Some(owner) => check(&module, owner),
            None => Err(Failure::Input("admission_owner")),
        }
    } else {
        Ok(())
    };
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |owner| owner.close(None));
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
    if started {
        report.observation(
            Phase::Body,
            "admission_override_inheritance_and_shared_signal",
            Producer::Fe11Local,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
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
