// SPDX-License-Identifier: Apache-2.0
//! Search boundaries around a two-handle batch, with independently owned objects.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    search_fixture::Case,
};
use fe11::*;
use std::{
    io::{self, Write},
    num::NonZeroUsize,
    path::Path,
};

mod partitions;

fn take(
    session: &Session,
    case: &Case,
    iterator: &mut NativeObjectIterator<'_>,
    found: &mut Vec<NativeObjectRef>,
) -> std::result::Result<bool, Failure> {
    match iterator.next() {
        None => Ok(false),
        Some(result) => {
            found.push(result?);
            let last = found.last().ok_or(Failure::Input("search_publication"))?;
            case.identity(session, last)?;
            Ok(true)
        }
    }
}

fn complete_set(
    session: &Session,
    case: &Case,
    iterator: &mut NativeObjectIterator<'_>,
    found: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    while take(session, case, iterator, found)? {}
    let mut ids = found
        .iter()
        .map(|object| case.identity(session, object))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ids.sort_unstable();
    if ids != (0..case.population).collect::<Vec<_>>() {
        return Err(Failure::Oracle("search_complete_set"));
    }
    if iterator.next().is_some() {
        return Err(Failure::Oracle("search_exhaustion_not_fused"));
    }
    Ok(())
}

fn transition<W: Write>(
    session: &Session,
    case: &Case,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let template = case.template();
    let batch = NonZeroUsize::new(2).ok_or(Failure::Input("search_batch"))?;
    let start = || session.iter_native_objects(&template, case.limits(), batch);
    let mut iterator = Some(start()?);
    let mut found = Vec::new();
    let result = (|| -> std::result::Result<(), Failure> {
        let cursor = iterator.as_mut().ok_or(Failure::Input("search_owner"))?;
        match (case.before.as_str(), case.action.as_str()) {
            ("ABSENT", "init") => complete_set(session, case, cursor, &mut found)?,
            ("ACTIVE", "init") => {
                match start() {
                    Err(
                        error @ Error::Native {
                            function: "C_FindObjectsInit",
                            code,
                            ..
                        },
                    ) if code == fe11_sys::CKR_OPERATION_ACTIVE as u64 => {
                        outcome::record(report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))?;
                    }
                    Err(error) => return Err(error.into()),
                    Ok(mut other) => {
                        if let Err(error) = other.finish() {
                            cleanup.push(error.into());
                        }
                        return Err(Failure::Oracle("second_search_init_accepted"));
                    }
                }
                complete_set(session, case, cursor, &mut found)?;
            }
            ("ACTIVE", "next") => {
                if !take(session, case, cursor, &mut found)? {
                    return Err(Failure::Oracle("search_nonempty_result"));
                }
                complete_set(session, case, cursor, &mut found)?;
            }
            ("EXHAUSTED", "next") => complete_set(session, case, cursor, &mut found)?,
            ("ACTIVE" | "FINISHED", "finish") | ("FINISHED", "next") => {
                if case.population > 0 && !take(session, case, cursor, &mut found)? {
                    return Err(Failure::Oracle("search_result_before_finish"));
                }
                cursor.finish()?;
                if case.before == "FINISHED" {
                    if case.action == "finish" {
                        cursor.finish()?;
                    } else if cursor.next().is_some() {
                        return Err(Failure::Oracle("finished_iterator_yielded"));
                    }
                }
                if case.before == "FINISHED" && case.action == "finish" {
                    let mut fresh = start()?;
                    let mut fresh_found = Vec::new();
                    let result = complete_set(session, case, &mut fresh, &mut fresh_found);
                    if let Err(error) = fresh.finish() {
                        cleanup.push(error.into());
                    }
                    result?;
                }
            }
            ("ACTIVE", "drop") => {
                if case.population > 0 && !take(session, case, cursor, &mut found)? {
                    return Err(Failure::Oracle("search_result_before_drop"));
                }
                drop(iterator.take());
                let mut fresh = start()?;
                let mut fresh_found = Vec::new();
                let result = complete_set(session, case, &mut fresh, &mut fresh_found);
                if let Err(error) = fresh.finish() {
                    cleanup.push(error.into());
                }
                result?;
            }
            _ => return Err(Failure::Input("search_population_transition")),
        }
        // References returned before Final or Drop remain independent objects.
        for object in &found {
            case.identity(session, object)?;
        }
        Ok(())
    })();
    if let Some(cursor) = &mut iterator {
        if let Err(error) = cursor.finish() {
            cleanup.push(error.into());
        }
    }
    result
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    match partitions::read(path) {
        Ok(Some(definition)) => {
            return partitions::execute(module, config, pins, report, definition)
        }
        Ok(None) => {}
        Err(error) => {
            let cleanup = module
                .close()
                .err()
                .map(Failure::from)
                .into_iter()
                .collect();
            return super::module_controls::finish(report, Err(error), Ok(()), cleanup);
        }
    }
    let mut session = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("search_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(case)
    })();
    let started = setup.is_ok();
    let mut cleanup = Vec::new();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(mut case) => (
            Ok(()),
            (|| -> std::result::Result<(), Failure> {
                let session = session.as_ref().ok_or(Failure::Input("search_session"))?;
                let first = u8::from(case.before == "ACTIVE" && case.action == "next");
                for population in first..=4 {
                    case.population = population;
                    let mut owned = Vec::new();
                    let result = (|| -> std::result::Result<(), Failure> {
                        for index in 0..population {
                            owned.push(case.create(session, index)?);
                        }
                        transition(session, &case, &mut report, &mut cleanup)
                    })();
                    // Destroy only references created here, never the search results.
                    for object in &owned {
                        if let Err(error) = session.destroy_native_object(object) {
                            cleanup.push(error.into());
                        }
                    }
                    result?;
                    if !cleanup.is_empty() {
                        return Err(Failure::Oracle("population_cleanup"));
                    }
                    report
                        .observation(
                            Phase::Body,
                            "search_population_verified",
                            Producer::Fe11Local,
                            Observation::Number(population as u64),
                        )
                        .map_err(|_| Failure::Input("report_write"))?;
                }
                Ok(())
            })(),
        ),
    };
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
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
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
