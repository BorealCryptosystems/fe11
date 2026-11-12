// SPDX-License-Identifier: Apache-2.0
use fe11::*;
use std::path::PathBuf;

/// Preserve operation and cleanup outcomes independently.
pub struct SessionRun<T> {
    pub operation: Result<T>,
    pub logout: Option<Result<()>>,
    pub close: Result<()>,
}

/// Use only when this application owns the token's authentication lifecycle.
/// The caller retains the session so cleanup failures remain recoverable.
pub fn authenticated_run<T>(
    session: &Session, pin: SecretPin,
    work: impl FnOnce(&Session) -> Result<T>,
) -> SessionRun<T> {
    let login = session.login_as(LoginRole::User, pin);
    let logged_in = login.is_ok();
    let operation = login.and_then(|()| work(session));
    let logout = if logged_in { Some(session.logout()) } else { None };
    let close = session.close();
    SessionRun { operation, logout, close }
}

/// Open one initialization with a lifecycle owner and ordinary clients.
pub fn shared_runtime(
    config: ModuleConfig, options: ModuleOptions,
) -> Result<(RuntimeOwner, Module)> {
    Module::builder(config, options).open_shared()
}

/// Select a trusted software component before opening the native module.
pub fn with_verification_engine(
    config: ModuleConfig, options: ModuleOptions,
    engine_path: PathBuf, expected_engine_sha256: [u8; 32],
) -> Result<Module> {
    let engine = VerifyEngine::builder(
        engine_path,
        ModuleIntegrity::Sha256 {
            expected: expected_engine_sha256,
            on_mismatch: ModuleDigestMismatch::Refuse,
        },
    ).open()?;
    Module::builder(config, options).verify_engine(Some(engine)).open()
}

/// Keep native diagnostics distinct from local publication and capacity results.
pub fn diagnostic_summary(error: &Error) -> String {
    match error {
        Error::Native { function, code, may_have_effect } =>
            format!("{function}: code=0x{code:x}, may_have_effect={may_have_effect}"),
        Error::OperationCompleted { function, .. } =>
            format!("{function} completed; reconcile native effects and publication"),
        Error::SignatureBufferRequired(_) =>
            "Signature output capacity required; preserve the session and continuation".into(),
        Error::CipherBufferRequired(_) =>
            "Cipher output capacity required; preserve the session and continuation".into(),
        Error::Busy(reason) => format!("Resource or lifecycle unavailable: {reason:?}"),
        _ => format!("{error}"),
    }
}
