// SPDX-License-Identifier: Apache-2.0
//! Caller admission and synchronized real sessions, without duration assertions.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    io::{self, Write},
    sync::Barrier,
    time::{Duration, Instant},
};
#[path = "resource_observer.rs"]
mod observer;
#[path = "owner_progress.rs"]
mod owner_progress;
#[path = "resource_preparation.rs"]
mod preparation;

fn expired() -> ResourceAdmission {
    ResourceAdmission::WaitUntil {
        deadline: Instant::now(),
        cancellation: AdmissionCancellation::new(),
    }
}

fn deadline<T>(result: Result<T>) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::AdmissionDeadline) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("expired_admission_dispatched")),
    }
}

fn synchronized(first: &Session, second: &Session) -> std::result::Result<(), Failure> {
    let barrier = Barrier::new(3);
    // This is the suite's caller-selected admission timeout, not an execution
    // duration requirement or evidence of simultaneous native execution.
    let limit = Instant::now()
        .checked_add(Duration::from_secs(3600))
        .ok_or(Failure::Input("admission_deadline_overflow"))?;
    let observe = |session: &Session| {
        barrier.wait();
        with_resource_admission(
            ResourceAdmission::WaitUntil {
                deadline: limit,
                cancellation: AdmissionCancellation::new(),
            },
            || session.info(),
        )
    };
    std::thread::scope(|scope| {
        let left = scope.spawn(|| observe(first));
        let right = scope.spawn(|| observe(second));
        barrier.wait();
        // Always join both workers, even if one failed; no thread or native
        // invocation may remain live when session cleanup starts.
        let left = left.join();
        let right = right.join();
        for result in [left, right] {
            let info = result.map_err(|_| Failure::Oracle("session_worker_panicked"))??;
            if info.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("concurrent_session_state"));
            }
        }
        Ok(())
    })
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    action: &str,
    report: Report<W>,
) -> io::Result<bool> {
    if action.starts_with("owner-") {
        return owner_progress::execute(config, action, report);
    }
    if action == "preparation-release" {
        return preparation::execute(config, report);
    }
    if matches!(action, "drop-eager" | "drop-cooperative") {
        return observer::execute(config, action == "drop-eager", report);
    }
    let mut module = None;
    let mut session = None;
    let mut other = None;
    let setup = (|| -> std::result::Result<(), Failure> {
        if !matches!(
            action,
            "scoped-deadline"
                | "session-deadline"
                | "nested-deadline"
                | "cancelled"
                | "parallel-sessions"
                | "shared-session"
        ) {
            return Err(Failure::Input("resource_control_selector"));
        }
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("resource_control_module"))?;
        let token =
            select_token(m, &config.label).ok_or(Failure::Input("resource_control_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        if action == "parallel-sessions" {
            other = Some(m.select(&token)?.open_session(true)?);
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(()), Some(m), Some(s)) = (&setup, &module, &mut session) else {
            return Ok(());
        };
        let before = m.call_counts()?;
        match action {
            "scoped-deadline" => deadline(with_resource_admission(expired(), || s.info()))?,
            "session-deadline" => {
                s.set_admission(expired());
                let result = deadline(s.info());
                s.inherit_admission();
                result?;
            }
            "nested-deadline" => {
                with_resource_admission(expired(), || {
                    with_resource_admission(ResourceAdmission::Immediate, || s.info())?;
                    deadline(s.info())
                })?;
            }
            "cancelled" => {
                let signal = AdmissionCancellation::new();
                signal.cancel();
                // A cancelled signal is checked before the already expired
                // deadline. Neither result permits a native call.
                let policy = ResourceAdmission::WaitUntil {
                    deadline: Instant::now(),
                    cancellation: signal,
                };
                match with_resource_admission(policy, || s.info()) {
                    Err(Error::AdmissionCancelled) => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("cancelled_admission_dispatched")),
                }
            }
            "parallel-sessions" => {
                synchronized(s, other.as_ref().ok_or(Failure::Input("second_session"))?)?
            }
            "shared-session" => synchronized(s, s)?,
            _ => return Err(Failure::Input("resource_control_selector")),
        }
        if !matches!(
            action,
            "parallel-sessions" | "shared-session" | "nested-deadline"
        ) && m.call_counts()? != before
        {
            return Err(Failure::Oracle("admission_refusal_native_call"));
        }
        // Successful subsequent work proves that the scoped policy and session
        // override were restored. No timing or native parallelism is inferred.
        module_lifecycle::control(s)
    })();
    let mut cleanup = Vec::new();
    for s in [&other, &session].into_iter().flatten() {
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(other);
    drop(session);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    module_controls::finish(report, setup, body, cleanup)
}
