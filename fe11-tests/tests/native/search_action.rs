// SPDX-License-Identifier: Apache-2.0
//! Iterator transitions retain references and compare sets without native order assumptions.
use super::{
    outcome::{self, Failure},
    report::{Phase, Report},
    search_fixture::Case,
};
use fe11::*;
use std::{io::Write, num::NonZeroUsize};

fn closed(error: &Error) -> bool {
    matches!(
        error,
        Error::Rejected(RejectionReason::SessionLifecycle(
            SessionLifecycleRejection::SessionClosed
        ))
    )
}
fn expect_closed<T, W: Write>(
    result: Result<T>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(error)
            if closed(&error)
                || matches!(&error,Error::CleanupFailed{operation,cleanup} if closed(operation)&&closed(cleanup)) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("closed_search_owner_accepted")),
    }
}
/// Closing retires the observation owner before a retained iterator checks it.
/// Preserve both the retired-owner diagnostic and the separate closed cleanup.
fn expect_closed_next<T, W: Write>(
    result: Result<T>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(error)
            if matches!(&error, Error::CleanupFailed { operation, cleanup }
                if matches!(operation.as_ref(), Error::Rejected(
                    RejectionReason::SessionLifecycle(
                        SessionLifecycleRejection::AttributeObservationRetired)))
                    && closed(cleanup)) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        other => expect_closed(other, report),
    }
}
fn take(
    session: &Session,
    case: &Case,
    cursor: &mut NativeObjectIterator<'_>,
    seen: &mut Vec<u8>,
    published: &mut Vec<NativeObjectRef>,
) -> std::result::Result<bool, Failure> {
    let Some(result) = cursor.next() else {
        return Ok(false);
    };
    let object = result?;
    // Retain a yielded reference before an attribute observation can fail.
    published.push(object);
    let object = published
        .last()
        .ok_or(Failure::Input("search_publication"))?;
    let identity = case.identity(session, object)?;
    if seen.contains(&identity) {
        return Err(Failure::Oracle("duplicate_search_result"));
    }
    seen.push(identity);
    Ok(true)
}
fn exhaust(
    session: &Session,
    case: &Case,
    cursor: &mut NativeObjectIterator<'_>,
    seen: &mut Vec<u8>,
    published: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    while take(session, case, cursor, seen, published)? {}
    seen.sort_unstable();
    if seen.as_slice() != [0, 1, 2] {
        return Err(Failure::Oracle("complete_search_set"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    session: &Session,
    case: &Case,
    closed_session: &mut bool,
    logged_in: &mut bool,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let template = case.template();
    let batch = NonZeroUsize::new(2).ok_or(Failure::Input("search_batch"))?;
    let start = || session.iter_native_objects(&template, case.limits(), batch);
    let mut cursor = None;
    let mut seen = Vec::new();
    let mut published = Vec::new();
    let operation = (|| -> std::result::Result<(), Failure> {
        if case.before != "ABSENT" {
            cursor = Some(start()?);
            let c = cursor.as_mut().ok_or(Failure::Input("search_cursor"))?;
            match case.before.as_str() {
                "CACHED" => {
                    if !take(session, case, c, &mut seen, &mut published)? {
                        return Err(Failure::Oracle("search_first_result"));
                    }
                }
                "EXHAUSTED" => exhaust(session, case, c, &mut seen, &mut published)?,
                "FINISHED" => c.finish()?,
                "CLOSED" => {
                    session.close()?;
                    *closed_session = true;
                    *logged_in = false;
                }
                "DROPPED" => drop(cursor.take()),
                "ACTIVE" => (),
                _ => return Err(Failure::Input("search_before")),
            }
        }
        if case.before == "CLOSED" {
            match case.action.as_str() {
                "init" => expect_closed(start(), report)?,
                "close" => expect_closed(session.close(), report)?,
                "logout" => match session.logout() {
                    Err(
                        error @ Error::Rejected(RejectionReason::Authentication(
                            AuthenticationRejection::LogoutRequiresLiveSession,
                        )),
                    ) => outcome::record(report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?,
                    Err(error) => return Err(error.into()),
                    Ok(()) => return Err(Failure::Oracle("closed_logout_accepted")),
                },
                "finish" => expect_closed(
                    cursor
                        .as_mut()
                        .ok_or(Failure::Input("search_cursor"))?
                        .finish(),
                    report,
                )?,
                "next" => {
                    let c = cursor.as_mut().ok_or(Failure::Input("search_cursor"))?;
                    expect_closed_next(
                        c.next()
                            .ok_or(Failure::Oracle("closed_search_result_absent"))?,
                        report,
                    )?;
                    if c.next().is_some() {
                        return Err(Failure::Oracle("failed_search_not_terminal"));
                    }
                }
                "drop" => drop(cursor.take()),
                _ => return Err(Failure::Input("closed_search_action")),
            }
            // Dropping a closed cursor must not revive the session or call native Final.
            return Ok(());
        }
        match case.action.as_str() {
            "init" if matches!(case.before.as_str(), "ACTIVE" | "CACHED") => {
                match start() {
                    Err(
                        error @ Error::Native {
                            function: "C_FindObjectsInit",
                            code,
                            ..
                        },
                    ) if code == fe11_sys::CKR_OPERATION_ACTIVE as u64 => {
                        outcome::record(report, Phase::Body, &Failure::Product(error))
                            .map_err(|_| Failure::Input("report_write"))?
                    }
                    Err(error) => return Err(error.into()),
                    Ok(mut other) => {
                        other.finish()?;
                        return Err(Failure::Oracle("second_search_init_accepted"));
                    }
                }
                exhaust(
                    session,
                    case,
                    cursor.as_mut().ok_or(Failure::Input("search_cursor"))?,
                    &mut seen,
                    &mut published,
                )?;
            }
            "init" => {
                let mut other = start()?;
                let mut fresh_seen = Vec::new();
                exhaust(session, case, &mut other, &mut fresh_seen, &mut published)?;
            }
            "next" => {
                let c = cursor.as_mut().ok_or(Failure::Input("search_cursor"))?;
                if matches!(case.before.as_str(), "FINISHED" | "EXHAUSTED") {
                    if c.next().is_some() {
                        return Err(Failure::Oracle("finished_search_yielded"));
                    }
                } else {
                    if !take(session, case, c, &mut seen, &mut published)? {
                        return Err(Failure::Oracle("search_next_absent"));
                    }
                    if case.before == "CACHED" && seen.len() != 2 {
                        return Err(Failure::Oracle("cached_search_count"));
                    }
                }
            }
            "finish" => cursor
                .as_mut()
                .ok_or(Failure::Input("search_cursor"))?
                .finish()?,
            "logout" => {
                session.logout()?;
                *logged_in = false;
                if session.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                    return Err(Failure::Oracle("search_logout_state"));
                }
                if matches!(case.before.as_str(), "ACTIVE" | "CACHED") {
                    exhaust(
                        session,
                        case,
                        cursor.as_mut().ok_or(Failure::Input("search_cursor"))?,
                        &mut seen,
                        &mut published,
                    )?;
                }
            }
            "close" => {
                session.close()?;
                *closed_session = true;
                *logged_in = false;
            }
            "drop" => {
                drop(cursor.take());
                let mut other = start()?;
                let mut fresh_seen = Vec::new();
                exhaust(session, case, &mut other, &mut fresh_seen, &mut published)?;
            }
            "read_published_object" => {
                let object = published
                    .first()
                    .ok_or(Failure::Input("search_published_object"))?;
                case.identity(session, object)?;
            }
            _ => return Err(Failure::Input("search_action")),
        }
        Ok(())
    })();
    if !*closed_session {
        if let Some(c) = &mut cursor {
            if let Err(error) = c.finish() {
                cleanup.push(error.into());
            }
        }
    }
    drop(cursor);
    operation?;
    if !*closed_session && cleanup.is_empty() {
        for object in &published {
            case.identity(session, object)?;
        }
    }
    Ok(())
}
