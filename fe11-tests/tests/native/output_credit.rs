// SPDX-License-Identifier: Apache-2.0
//! Retained output credit and caller-selected waiting on the real native module.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    io::{self, Write},
    sync::{mpsc, Barrier},
    time::{Duration, Instant},
};

const OUTPUT_BYTES: usize = 40 * 1024 * 1024;

#[path = "output_credit_boundaries.rs"]
mod boundaries;
#[path = "output_credit_cancellation.rs"]
mod cancellation;
#[path = "output_credit_capture.rs"]
mod capture;
#[path = "drain_owner_order.rs"]
mod drain_order;

// Learn the public diagnostic's charge from an intrinsically oversized request,
// then check that same request on new owners at charge-1 and charge. This avoids
// hard-coding private struct sizes, which differ across targets and Rust versions.
fn boundary_attempt(
    config: &Configuration,
    limit: usize,
    expected: Option<usize>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<usize, Failure> {
    let mut budgets = Budgets::ordinary();
    let length = budgets.buffer_bytes;
    budgets.buffer_bytes = limit;
    let module = config.open(&budgets)?;
    let mut session = None;
    let result = (|| -> std::result::Result<usize, Failure> {
        let token = select_token(&module, &config.label).ok_or(Failure::Input("boundary_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        let s = session.as_ref().ok_or(Failure::Input("boundary_session"))?;
        let before = module.call_counts()?;
        match s.generate_random(length) {
            Err(Error::ResourceLimitExceeded {
                resource: ResourceKind::SymmetricByteBudget,
                requested,
                limit: actual,
            }) if actual == limit
                && requested > limit
                && expected.map_or(true, |v| v == requested) =>
            {
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("boundary_refusal_dispatched"));
                }
                Ok(requested)
            }
            Ok(value) if expected == Some(limit) && value.len() == length => {
                drop(value);
                // A second request at the exact same ceiling proves release
                // of the first completed output and its call bookkeeping.
                let again = s.generate_random(length)?;
                if again.len() != length {
                    return Err(Failure::Oracle("boundary_retry_width"));
                }
                drop(again);
                Ok(limit)
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("boundary_unexpected_success")),
        }
    })();
    if let Some(s) = &session {
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    result
}

fn boundary<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let mut cleanup = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        let charge =
            boundary_attempt(config, Budgets::ordinary().buffer_bytes, None, &mut cleanup)?;
        if !cleanup.is_empty() {
            return Err(Failure::Oracle("boundary_probe_cleanup"));
        }
        let short = charge
            .checked_sub(1)
            .ok_or(Failure::Input("boundary_charge"))?;
        boundary_attempt(config, short, Some(charge), &mut cleanup)?;
        if !cleanup.is_empty() {
            return Err(Failure::Oracle("boundary_short_cleanup"));
        }
        boundary_attempt(config, charge, Some(charge), &mut cleanup)?;
        Ok(())
    })();
    module_controls::finish(report, Ok(()), body, cleanup)
}

fn width(value: SecretBytes) -> std::result::Result<(), Failure> {
    if value.len() != OUTPUT_BYTES {
        return Err(Failure::Oracle("retained_random_output_width"));
    }
    // SecretBytes owns both wiping and budget release. Never print its bytes.
    drop(value);
    Ok(())
}

fn waiting(peer: &Session, held: SecretBytes) -> std::result::Result<(), Failure> {
    let barrier = Barrier::new(2);
    let cancellation = AdmissionCancellation::new();
    let timeout = Duration::from_secs(3600);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(Failure::Input("output_credit_deadline"))?;
    let policy = ResourceAdmission::WaitUntil {
        deadline,
        cancellation: cancellation.clone(),
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::scope(|scope| {
        let task = scope.spawn(|| {
            barrier.wait();
            let result = with_resource_admission(policy, || peer.generate_random(OUTPUT_BYTES));
            sender
                .send(result)
                .map_err(|_| Failure::Oracle("output_credit_receiver_lost"))
        });
        barrier.wait();
        let early = receiver.try_recv();
        // The waiter must not reserve this session's native-call guard while
        // waiting for output storage. No sleep or speed assertion orders it.
        let concurrent = peer.info();
        // Release even on error before joining: otherwise this test itself
        // would retain the resource needed by the worker it is waiting for.
        drop(held);
        let was_early = !matches!(&early, Err(mpsc::TryRecvError::Empty));
        let completed = match early {
            Ok(result) => Ok(result),
            Err(mpsc::TryRecvError::Disconnected) => Err(()),
            Err(mpsc::TryRecvError::Empty) => receiver.recv_timeout(timeout).map_err(|_| ()),
        };
        if completed.is_err() {
            cancellation.cancel();
        }
        let joined = task.join();
        let result = completed.map_err(|_| Failure::Oracle("output_credit_wait_incomplete"))?;
        joined.map_err(|_| Failure::Oracle("output_credit_waiter_panicked"))??;
        if was_early {
            return Err(Failure::Oracle("output_credit_completed_before_release"));
        }
        if concurrent?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
            return Err(Failure::Oracle("output_credit_concurrent_session"));
        }
        width(result?)
    })
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    action: &str,
    report: Report<W>,
) -> io::Result<bool> {
    if let Some(order) = action.strip_prefix("drain-order-") {
        return drain_order::execute(config, order, report);
    }
    if action == "capture-release" {
        return capture::execute(config, report);
    }
    if action == "caller-boundary" {
        return boundaries::execute(config, report);
    }
    if action == "boundary" {
        return boundary(config, report);
    }
    let mut module = None;
    let mut sessions = Vec::new();
    let setup = (|| -> std::result::Result<(), Failure> {
        if !matches!(action, "immediate" | "wait" | "cancel-waiting") {
            return Err(Failure::Input("output_credit_action"));
        }
        let budgets = Budgets::ordinary();
        if budgets.buffer_bytes != 64 * 1024 * 1024 {
            return Err(Failure::Input("output_credit_fixture_budget"));
        }
        module = Some(config.open(&budgets)?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("output_credit_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("output_credit_token"))?;
        for _ in 0..2 {
            sessions.push(m.select(&token)?.open_session(true)?);
        }
        if matches!(action, "wait" | "cancel-waiting") {
            // Establish authentication observation before the resource-only
            // wait. A first info read would otherwise change Unknown to Public
            // and invalidate the admission snapshot as a separate transition.
            if sessions
                .get(1)
                .ok_or(Failure::Input("output_credit_peer"))?
                .info()?
                .state
                != fe11_sys::CKS_RW_PUBLIC_SESSION as u64
            {
                return Err(Failure::Oracle("output_credit_initial_session_state"));
            }
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let first = sessions
            .first()
            .ok_or(Failure::Input("output_credit_first"))?;
        let peer = sessions
            .get(1)
            .ok_or(Failure::Input("output_credit_peer"))?;
        let m = module
            .as_ref()
            .ok_or(Failure::Input("output_credit_module"))?;
        let held = first.generate_random(OUTPUT_BYTES)?;
        if held.len() != OUTPUT_BYTES {
            return Err(Failure::Oracle("output_credit_initial_width"));
        }
        if action == "cancel-waiting" {
            cancellation::execute(m, peer, held)?;
        } else if action == "wait" {
            waiting(peer, held)?;
        } else {
            let before = m.call_counts()?;
            match peer.generate_random(OUTPUT_BYTES) {
                Err(Error::Busy(BusyReason::MemoryAccounting(
                    MemoryAccountingBusy::SymmetricByteBudget,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("output_credit_retention_missing")),
            }
            if m.call_counts()? != before {
                return Err(Failure::Oracle("occupied_output_credit_dispatched"));
            }
            if peer.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("output_credit_idle_peer"));
            }
            drop(held);
            width(peer.generate_random(OUTPUT_BYTES)?)?;
        }
        module_lifecycle::control(peer)
    })();
    let mut cleanup = Vec::new();
    for session in &sessions {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(sessions);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    module_controls::finish(report, setup, body, cleanup)
}
