// SPDX-License-Identifier: Apache-2.0
//! Observe a Linux worker inside its Fe11 admission wait, without a duration oracle.
use super::Failure;
use std::{
    path::Path,
    result::Result,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

pub(super) fn observe_wait(
    path: &Path,
    phase: &AtomicU8,
    deadline: Instant,
) -> Result<(), Failure> {
    while Instant::now() < deadline {
        let before = phase.load(Ordering::SeqCst);
        if before == 2 {
            return Err(Failure::Oracle(
                "output_wait_call_returned_before_observation",
            ));
        }
        if before == 1 {
            let state = std::fs::read_to_string(path.join("wchan"))
                .map_err(|_| Failure::Input("output_wait_kernel_observation"))?;
            if state.trim().contains("futex") && phase.load(Ordering::SeqCst) == 1 {
                return Ok(());
            }
        }
        // Polling interval limits supervisor CPU use; it is not a required
        // operation duration. Only the caller-selected deadline ends the wait.
        std::thread::sleep(Duration::from_millis(1));
    }
    Err(Failure::Oracle("output_wait_observation_timeout"))
}
