// SPDX-License-Identifier: Apache-2.0
//! Exact search populations around requested batch sizes, including a nonmatch.
use super::*;
use std::{fs::File, io::Read};

pub(super) struct Definition {
    batch: NonZeroUsize,
    population: u8,
    nonmatching: bool,
    selection: bool,
}

/// Transition fixtures have a separate grammar from population partitions.
pub(super) fn read(path: &Path) -> std::result::Result<Option<Definition>, Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("fixture_open"))?
        .take(2049)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("fixture_read"))?;
    if data.len() > 2048 {
        return Err(Failure::Input("fixture_size"));
    }
    if !data.starts_with(b"partition\n") && !data.starts_with(b"selection\n") {
        return Ok(None);
    }
    let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 4 {
        return Err(Failure::Input("search_partition_fields"));
    }
    let batch = fields[1]
        .parse::<usize>()
        .map_err(|_| Failure::Input("search_batch"))?;
    let population = fields[2]
        .parse::<u8>()
        .map_err(|_| Failure::Input("search_population"))?;
    let nonmatching = match fields[3] {
        "0" => false,
        "1" => true,
        _ => return Err(Failure::Input("search_nonmatching")),
    };
    let selection = fields[0] == "selection";
    let supported = if selection {
        (batch, population, nonmatching) == (2, 3, false)
    } else {
        matches!(
            (batch, population, nonmatching),
            (1, 0..=2, false) | (16, 0 | 16 | 17, false) | (2, 4, true)
        )
    };
    if !supported {
        return Err(Failure::Input("search_partition"));
    }
    Ok(Some(Definition {
        batch: NonZeroUsize::new(batch).ok_or(Failure::Input("search_batch"))?,
        population,
        nonmatching,
        selection,
    }))
}

/// Multiple matches are observable, not an implicit uniqueness policy. Each
/// index belongs to its own complete enumeration; order may change between calls.
fn select_indices(
    session: &Session,
    fixture: &Case,
    batch: NonZeroUsize,
) -> std::result::Result<(), Failure> {
    let template = fixture.template();
    for index in 0..=usize::from(fixture.population) {
        let selected = session.find_native_object_at(
            &template,
            fixture.limits(),
            SearchPlan {
                maximum_objects: Some(usize::from(fixture.population)),
                batch_size: batch,
            },
            index,
        )?;
        if selected.matched != usize::from(fixture.population) {
            return Err(Failure::Oracle("indexed_search_cardinality"));
        }
        match selected.object {
            Some(object) if index < usize::from(fixture.population) => {
                fixture.identity_sized::<16>(session, &object)?;
            }
            None if index == usize::from(fixture.population) => {}
            _ => return Err(Failure::Oracle("indexed_search_presence")),
        }
    }
    Ok(())
}

fn enumerate(
    session: &Session,
    fixture: &Case,
    batch: NonZeroUsize,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let template = fixture.template();
    let mut iterator = session.iter_native_objects(&template, fixture.limits(), batch)?;
    let result = (|| -> std::result::Result<(), Failure> {
        let mut ids = Vec::new();
        for object in iterator.by_ref() {
            let object = object?;
            ids.push(fixture.identity_sized::<16>(session, &object)?);
            // Stop a broken iterator without consuming unbounded test memory.
            if ids.len() > usize::from(fixture.population) {
                return Err(Failure::Oracle("search_extra_result"));
            }
        }
        ids.sort_unstable();
        if ids != (0..fixture.population).collect::<Vec<_>>() {
            return Err(Failure::Oracle("search_exact_population"));
        }
        if iterator.next().is_some() {
            return Err(Failure::Oracle("search_exhaustion_not_fused"));
        }
        Ok(())
    })();
    // Final precedes object destruction on both the success and error branches.
    if let Err(error) = iterator.finish() {
        cleanup.push(error.into());
    }
    result
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    pins: &Credentials,
    mut report: Report<W>,
    definition: Definition,
) -> io::Result<bool> {
    let mut session = None;
    let mut logged = false;
    let mut owned = Vec::new();
    let fixture = Case {
        before: "ABSENT".into(),
        action: "init".into(),
        label: format!("{}:matching", config.label).into_bytes(),
        population: definition.population,
    };
    let other = Case {
        before: "ABSENT".into(),
        action: "init".into(),
        label: format!("{}:other", config.label).into_bytes(),
        population: 1,
    };
    let setup = (|| -> std::result::Result<(), Failure> {
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        let session = session.as_ref().ok_or(Failure::Input("search_session"))?;
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        for index in 0..definition.population {
            owned.push(fixture.create_sized::<16>(session, index)?);
        }
        if definition.nonmatching {
            owned.push(other.create_sized::<16>(session, 0)?);
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    let body = if setup.is_ok() {
        (|| -> std::result::Result<(), Failure> {
            let session = session.as_ref().ok_or(Failure::Input("search_session"))?;
            if definition.selection {
                select_indices(session, &fixture, definition.batch)?;
            } else {
                enumerate(session, &fixture, definition.batch, &mut cleanup)?;
            }
            if definition.nonmatching {
                // A missing nonmatch cannot make the filtering assertion pass.
                other.identity_sized::<16>(
                    session,
                    owned
                        .last()
                        .ok_or(Failure::Input("search_nonmatch_owner"))?,
                )?;
            }
            report
                .observation(
                    Phase::Body,
                    "search_partition_verified",
                    Producer::TestOracle,
                    Observation::Boolean(true),
                )
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        })()
    } else {
        Ok(())
    };
    if let Some(session) = &session {
        // Search results are aliases; cleanup owns only the created references.
        for object in &owned {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(owned);
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
