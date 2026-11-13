// SPDX-License-Identifier: Apache-2.0
//! Public API integration scenarios against an isolated, real SoftHSM token.
//! The parent validates structured outcomes; arbitrary log text cannot pass a test.
#[cfg(target_os = "linux")]
mod environment;
#[cfg(target_os = "linux")]
mod fixture;
mod report;
#[cfg(target_os = "linux")]
mod scenarios;
mod supervisor;

fn main() -> std::process::ExitCode {
    // A panic must fail the process without formatting PINs or module objects.
    std::panic::set_hook(Box::new(|_| eprintln!("scenario_panic")));
    match supervisor::dispatch() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(()) => std::process::ExitCode::FAILURE,
    }
}
