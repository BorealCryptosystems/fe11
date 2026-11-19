// SPDX-License-Identifier: Apache-2.0
//! Loader path validation before any verification-engine entry point is called.
use fe11::{Error, ModuleIntegrity, RejectionReason, VerificationEngineRejection, VerifyEngine};

#[test]
fn relative_engine_path_is_rejected() {
    let actual = VerifyEngine::builder("engine.so".into(), ModuleIntegrity::NotRequested).open();
    assert!(matches!(
        actual,
        Err(Error::Rejected(RejectionReason::VerificationEngine(
            VerificationEngineRejection::AbsoluteVerificationEnginePathRequired
        )))
    ));
}

// Unix permits opening a directory as a file before metadata identifies its kind.
// Windows rejects the open itself; it does not exercise this metadata branch.
#[cfg(target_os = "linux")]
#[test]
fn directory_cannot_be_a_verification_engine() {
    let directory = std::env::current_dir().expect("the runner supplies an owned working directory");
    assert!(directory.is_absolute() && directory.is_dir());
    let actual = VerifyEngine::builder(directory, ModuleIntegrity::NotRequested).open();
    assert!(matches!(
        actual,
        Err(Error::Rejected(RejectionReason::VerificationEngine(
            VerificationEngineRejection::VerificationEngineIsNotARegularFile
        )))
    ));
}
