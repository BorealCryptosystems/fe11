// SPDX-License-Identifier: Apache-2.0
//! Initialization callback completeness and native second-initialization refusal.
use super::{
    application_mutex,
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("initialization_fixture_open"))?
        .take(65)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("initialization_fixture_read"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("initialization_fixture_fields"))?;
    if !matches!(
        action,
        "callbacks"
            | "missing_create"
            | "missing_destroy"
            | "missing_lock"
            | "missing_unlock"
            | "second_initialize"
            | "failed_open_cleanup"
    ) {
        return Err(Failure::Input("initialization_fixture_action"));
    }
    Ok(action.into())
}

fn rejected_open<W: Write>(
    result: Result<Module>,
    expected: Error,
    cleanup: &mut Vec<Failure>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(actual) if actual == expected => {
            outcome::record(report, Phase::Body, &Failure::Product(actual))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(actual) => Err(actual.into()),
        Ok(unexpected) => {
            if let Err(error) = unexpected.close() {
                cleanup.push(error.into());
            }
            Err(Failure::Oracle("initialization_refusal_was_success"))
        }
    }
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut cleanup = Vec::new();
    let setup = (|| -> std::result::Result<String, Failure> {
        let action = read(path)?;
        // Load and finalize the exact recipe before opening the body runtime.
        // Negative initialization must not suppress dependency verification.
        let preparation = config.open(&Budgets::ordinary())?;
        preparation.close()?;
        Ok(action)
    })();
    let before = application_mutex::counts();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(action) = &setup else { return Ok(()) };
        let builder = config.builder(&Budgets::ordinary());
        if action == "failed_open_cleanup" {
            rejected_open(
                builder
                    .interface(InterfaceSelection::Standard {
                        version: (4, 0),
                        required_flags: 0,
                    })
                    .open(),
                Error::Rejected(RejectionReason::NativeInterfaces(
                    NativeInterfacesRejection::UnsupportedInterfaceSelection,
                )),
                &mut cleanup,
                &mut report,
            )?;
            module = Some(config.open(&Budgets::ordinary())?);
        } else if action == "second_initialize" {
            module = Some(builder.open()?);
            rejected_open(
                config.open(&Budgets::ordinary()),
                Error::Native {
                    function: "C_Initialize",
                    code: fe11_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED as u64,
                    may_have_effect: false,
                },
                &mut cleanup,
                &mut report,
            )?;
        } else {
            let mut functions = application_mutex::functions();
            match action.as_str() {
                "missing_create" => functions.create = None,
                "missing_destroy" => functions.destroy = None,
                "missing_lock" => functions.lock = None,
                "missing_unlock" => functions.unlock = None,
                "callbacks" => (),
                _ => return Err(Failure::Input("initialization_action")),
            }
            // SAFETY: callbacks implement real mutexes, contain unwinds and
            // retain all code/counters for process lifetime. Partial sets stay
            // valid individually; the module decides whether the set is usable.
            let owner = unsafe { InitializationMutexes::new(functions, ()) };
            let result = builder
                .initialization(InitializationOptions {
                    cannot_create_os_threads: false,
                    concurrency: NativeConcurrency::ApplicationMutexes,
                })
                .initialization_mutexes(Some(owner))
                .open();
            if action == "callbacks" {
                module = Some(result?);
            } else {
                rejected_open(
                    result,
                    Error::Native {
                        function: "C_Initialize",
                        code: fe11_sys::CKR_ARGUMENTS_BAD as u64,
                        may_have_effect: false,
                    },
                    &mut cleanup,
                    &mut report,
                )?;
                if application_mutex::counts() != before {
                    return Err(Failure::Oracle("partial_mutex_set_invoked"));
                }
                // Explicit later open is a recovery control, never a fallback
                // inside Fe11 or a reinterpretation of the preceding refusal.
                module = Some(config.open(&Budgets::ordinary())?);
            }
        }
        let m = module
            .as_ref()
            .ok_or(Failure::Input("initialization_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("initialization_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        module_lifecycle::control(
            session
                .as_ref()
                .ok_or(Failure::Input("initialization_session"))?,
        )
    })();
    if let Some(session) = &session {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Some(module) = module {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    let after = application_mutex::counts();
    if matches!(setup.as_deref(), Ok("callbacks")) && body.is_ok() {
        if after.created <= before.created
            || after.created != after.destroyed
            || after.locked == 0
            || after.locked != after.unlocked
            || after.panicked != 0
        {
            cleanup.push(Failure::Oracle("application_mutexes_not_balanced"));
        }
        report.observation(
            Phase::Body,
            "application_mutexes_created",
            Producer::TestOracle,
            Observation::Number(after.created as u64),
        )?;
        report.observation(
            Phase::Cleanup,
            "application_mutexes_destroyed",
            Producer::TestOracle,
            Observation::Number(after.destroyed as u64),
        )?;
    }
    if after.panicked != 0 {
        cleanup.push(Failure::Oracle("application_mutex_callback_panicked"));
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
