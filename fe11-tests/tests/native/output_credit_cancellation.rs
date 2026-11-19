// SPDX-License-Identifier: Apache-2.0
//! Cancel a caller-selected wait only after Linux observes the waiting thread.
//!
//! The phase interval contains just the Fe11 call: it excludes channel waits,
//! result publication and the thread's setup. No other thread holds a Fe11
//! guard. The retained output is the only contended resource, so a futex wait
//! in that interval plus zero native dispatch establishes a local admission
//! wait. This is a Linux integration observation, not a timing assertion.
use super::{width, Failure, OUTPUT_BYTES};
use fe11::*;
use std::{
    path::Path,
    result::Result,
    sync::{
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

fn observe_wait(path: &Path, phase: &AtomicU8, deadline: Instant) -> Result<(), Failure> {
    while Instant::now() < deadline {
        let before = phase.load(Ordering::SeqCst);
        if before == 2 {
            return Err(Failure::Oracle("cancel_wait_completed_before_signal"));
        }
        if before == 1 {
            let state = std::fs::read_to_string(path.join("wchan"))
                .map_err(|_| Failure::Input("cancel_wait_kernel_observation"))?;
            if state.trim().contains("futex") && phase.load(Ordering::SeqCst) == 1 {
                return Ok(());
            }
        }
        // Polling interval limits supervisor CPU use; it is not a required
        // operation duration. Only the caller-selected deadline ends the wait.
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(Failure::Oracle("cancel_wait_observation_timeout"))
}

pub(super) fn execute(module: &Module, peer: &Session, held: SecretBytes) -> Result<(), Failure> {
    let timeout = Duration::from_secs(3600);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(Failure::Input("cancel_wait_deadline"))?;
    let cancellation = AdmissionCancellation::new();
    let policy = ResourceAdmission::WaitUntil {
        deadline,
        cancellation: cancellation.clone(),
    };
    let phase = AtomicU8::new(0);
    let (ready_tx, ready_rx) = mpsc::channel();
    let before = module.call_counts()?;
    let result = std::thread::scope(|scope| {
        let worker = scope.spawn(|| -> Result<fe11::Result<SecretBytes>, Failure> {
            let task = std::fs::read_link("/proc/thread-self")
                .map_err(|_| Failure::Input("cancel_wait_linux_thread_identity"))?;
            let task = Path::new("/proc").join(task);
            ready_tx
                .send(task)
                .map_err(|_| Failure::Oracle("cancel_wait_receiver"))?;
            phase.store(1, Ordering::SeqCst);
            let result = with_resource_admission(policy, || peer.generate_random(OUTPUT_BYTES));
            phase.store(2, Ordering::SeqCst);
            Ok(result)
        });
        let observed = ready_rx
            .recv_timeout(timeout)
            .map_err(|_| Failure::Oracle("cancel_wait_thread_setup"))
            .and_then(|task| observe_wait(&task, &phase, deadline));
        // Signal even when observation failed, before joining. Keep the held
        // bytes alive through the join: freeing them cannot cause this wakeup.
        cancellation.cancel();
        let joined = worker.join();
        observed?;
        let outcome = joined.map_err(|_| Failure::Oracle("cancel_wait_thread_panic"))??;
        match outcome {
            Err(Error::AdmissionCancelled) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("cancel_wait_unexpected_success")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("cancel_wait_native_dispatch"));
        }
        Ok(())
    });
    drop(held);
    result?;
    // Cancellation belongs to the waiting request. A new immediate request on
    // the same session must regain the released bytes and reach the module.
    width(peer.generate_random(OUTPUT_BYTES)?)
}
