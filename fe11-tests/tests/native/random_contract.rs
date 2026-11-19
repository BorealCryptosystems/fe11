// SPDX-License-Identifier: Apache-2.0
//! Provider random bytes: exact lengths, owned outputs and explicit seed calls.
//! No entropy, uniqueness or deterministic reseeding property is inferred.
use super::{
    configuration::{select_token, Budgets, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

enum Case {
    Generate(usize),
    Seed(bool),
    BudgetBoundary(i8),
    Overflow,
    Ownership,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("random_fixture_open"))?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("random_fixture_read"))?;
    match bytes.as_slice() {
        b"generate 0\n" => Ok(Case::Generate(0)),
        b"generate 1\n" => Ok(Case::Generate(1)),
        b"generate 15\n" => Ok(Case::Generate(15)),
        b"generate 16\n" => Ok(Case::Generate(16)),
        b"generate 17\n" => Ok(Case::Generate(17)),
        b"generate 32\n" => Ok(Case::Generate(32)),
        b"generate 64\n" => Ok(Case::Generate(64)),
        b"generate 257\n" => Ok(Case::Generate(257)),
        b"seed empty\n" => Ok(Case::Seed(false)),
        b"seed binary\n" => Ok(Case::Seed(true)),
        b"budget -1\n" => Ok(Case::BudgetBoundary(-1)),
        b"budget 0\n" => Ok(Case::BudgetBoundary(0)),
        b"budget 1\n" => Ok(Case::BudgetBoundary(1)),
        b"overflow\n" => Ok(Case::Overflow),
        b"ownership\n" => Ok(Case::Ownership),
        _ => Err(Failure::Input("random_fixture_fields")),
    }
}

fn ownership() -> std::result::Result<(), Failure> {
    // A second applicable implementation would make this inference ambiguous.
    // This checks the public traits at compilation, without reading freed memory.
    trait NoClone<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> NoClone<()> for T {}
    impl<T: ?Sized + Clone> NoClone<u8> for T {}
    let _ = <SecretBytes as NoClone<_>>::check;
    trait NoDebug<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> NoDebug<()> for T {}
    impl<T: ?Sized + std::fmt::Debug> NoDebug<u8> for T {}
    let _ = <SecretBytes as NoDebug<_>>::check;
    let mut secret = SecretBytes::new(32)?;
    if secret.len() != 32 || secret.as_slice() != [0; 32] {
        return Err(Failure::Oracle("secret_buffer_initialized"));
    }
    secret.as_mut_slice().fill(0x5a);
    if secret.as_slice() != [0x5a; 32] {
        return Err(Failure::Oracle("secret_buffer_mutable_borrow"));
    }
    drop(secret);
    // Erasure is a Drop implementation guarantee, not an observation obtained
    // by dereferencing deallocated storage in this public API test.
    Ok(())
}

fn local<W: Write>(
    module: &Module,
    session: &Session,
    case: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    match case {
        Case::BudgetBoundary(offset) => {
            let maximum = Budgets::ordinary().buffer_bytes;
            let length = match offset {
                -1 => maximum - 1,
                0 => maximum,
                1 => maximum + 1,
                _ => return Err(Failure::Input("random_budget_offset")),
            };
            // The ceiling covers resident metadata and the stable call frame
            // as well as payload. All three payloads therefore exceed it;
            // there is no separate per-output maximum equal to this ceiling.
            match session.generate_random(length) {
                Err(Error::ResourceLimitExceeded {
                    resource: ResourceKind::SymmetricByteBudget,
                    requested,
                    limit,
                }) if limit == maximum && requested > maximum => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("random_budget_excess_accepted")),
            }
        }
        Case::Overflow => {
            // On LLP64 the native length conversion is the first guard. On
            // LP64, adding frame overhead overflows before any allocation.
            let expected = if std::mem::size_of::<fe11_sys::CK_ULONG>()
                < std::mem::size_of::<usize>()
            {
                RejectionReason::InputBounds(InputBoundsRejection::LengthConversion)
            } else {
                RejectionReason::RandomGeneration(RandomGenerationRejection::RandomOutputAccounting)
            };
            match session.generate_random(usize::MAX) {
                Err(Error::Rejected(reason)) if reason == expected => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("random_overflow_accepted")),
            }
        }
        Case::Ownership => ownership()?,
        _ => return Err(Failure::Input("random_local_action")),
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("random_local_guard_dispatched"));
    }
    report
        .observation(
            Phase::Body,
            "random_local_contract_without_dispatch",
            Producer::TestOracle,
            Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("report_write"))
}

fn check<W: Write>(
    module: &Module,
    session: &Session,
    case: &Case,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if matches!(
        case,
        Case::BudgetBoundary(_) | Case::Overflow | Case::Ownership
    ) {
        return local(module, session, case, report);
    }
    let before = module.call_counts()?;
    let function = match case {
        Case::Generate(length) => {
            let output = session.generate_random(*length)?;
            if output.len() != *length
                || output.as_slice().len() != *length
                || output.is_empty() != (*length == 0)
            {
                return Err(Failure::Oracle("random_exact_owned_length"));
            }
            // The output remains live while its public length is checked. No
            // generated byte is copied into a report or used as a deterministic oracle.
            report
                .observation(
                    Phase::Body,
                    "random_output_length",
                    Producer::Fe11Local,
                    Observation::Number(output.len() as u64),
                )
                .map_err(|_| Failure::Input("report_write"))?;
            drop(output);
            "C_GenerateRandom"
        }
        Case::Seed(binary) => {
            // Public fixture bytes are input data, not a credential or fallback key.
            let mut seed = SecretBytes::new(if *binary { 16 } else { 0 })?;
            for (index, byte) in seed.as_mut_slice().iter_mut().enumerate() {
                *byte = index as u8;
            }
            session.seed_random(seed)?;
            "C_SeedRandom"
        }
        _ => return Err(Failure::Input("random_native_action")),
    };
    let after = module.call_counts()?;
    if after
        .get(function)
        .copied()
        .unwrap_or(0)
        .checked_sub(before.get(function).copied().unwrap_or(0))
        != Some(1)
        || after
            .values()
            .sum::<u64>()
            .checked_sub(before.values().sum::<u64>())
            != Some(1)
    {
        return Err(Failure::Oracle("random_exact_native_dispatch"));
    }
    report
        .observation(
            Phase::Body,
            "random_exact_native_dispatch",
            Producer::TestOracle,
            Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        let token = select_token(&module, &config.label).ok_or(Failure::Input("random_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("random_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(case)
    })();
    let body = match &setup {
        Ok(case) => match &session {
            Some(session) => check(&module, session, case, &mut report),
            None => Err(Failure::Input("random_session")),
        },
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
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
