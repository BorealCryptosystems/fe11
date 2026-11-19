// SPDX-License-Identifier: Apache-2.0
//! Explicit optional verification-engine selection and its observable identity.
use super::{
    arguments::hex,
    configuration::{Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

#[path = "engine_component.rs"]
mod component;
#[path = "engine_retained.rs"]
mod retained;

fn read_action(path: &Path) -> std::result::Result<String, Failure> {
    let mut action = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("engine_fixture_open"))?
        .take(17)
        .read_to_string(&mut action)
        .map_err(|_| Failure::Input("engine_fixture_read"))?;
    if action.starts_with("api\n") {
        return Ok("api\n".into());
    }
    if action.starts_with("retained\n") {
        return Ok("retained\n".into());
    }
    if !matches!(
        action.as_str(),
        "module\n" | "builder\n" | "missing\n" | "mismatch\n"
    ) {
        return Err(Failure::Input("engine_fixture_action"));
    }
    Ok(action)
}

fn selected_engine(mismatch: bool) -> std::result::Result<VerifyEngine, Failure> {
    let path = PathBuf::from(
        std::env::var_os("FE11_PUBLIC_VERIFY_ENGINE")
            .ok_or(Failure::Input("engine_path_missing"))?,
    );
    let text = std::env::var("FE11_PUBLIC_VERIFY_ENGINE_SHA256")
        .map_err(|_| Failure::Input("engine_digest_missing"))?;
    let mut expected: [u8; 32] = hex(&text, 32)
        .map_err(Failure::Input)?
        .try_into()
        .map_err(|_| Failure::Input("engine_digest_length"))?;
    if !path.is_absolute() {
        return Err(Failure::Input("engine_path_absolute"));
    }
    // Change only the caller's expected identity. The exact existing file and
    // its digest-checked positive control are retained by the runner.
    if mismatch {
        expected[0] ^= 1;
    }
    Ok(VerifyEngine::builder(
        path,
        ModuleIntegrity::Sha256 {
            expected,
            on_mismatch: ModuleDigestMismatch::Refuse,
        },
    )
    .open()?)
}

fn observe(
    config: &Configuration,
    builder: ModuleBuilder,
    expected: Option<&VerifyEngine>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let module = builder.open()?;
    let mut session = None;
    let body = (|| -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        match (module.verify_engine(), expected) {
            (None, None) => (),
            (Some(actual), Some(expected))
                if actual.info().source_path == expected.info().source_path
                    && actual.info().source_sha256 == expected.info().source_sha256
                    && actual.info().abi_version == expected.info().abi_version =>
            {
                ()
            }
            _ => return Err(Failure::Oracle("engine_selected_identity")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("engine_accessor_native_dispatch"));
        }
        let token = super::configuration::select_token(&module, &config.label)
            .ok_or(Failure::Input("engine_choice_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        module_lifecycle::control(
            session
                .as_ref()
                .ok_or(Failure::Input("engine_choice_session"))?,
        )
    })();
    // Cleanup is attempted before propagating a failed oracle.
    if let Some(session) = &session {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if !cleanup.is_empty() {
        return Err(Failure::Oracle("engine_choice_cleanup_failed"));
    }
    body
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let setup = read_action(path);
    let mut cleanup = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(action) = &setup else {
            return Ok(());
        };
        if action == "retained\n" {
            return retained::check(config, path, selected_engine(false)?, &mut cleanup);
        }
        if action == "api\n" {
            let module = config.builder(&Budgets::ordinary()).open()?;
            let checked = (|| -> std::result::Result<(), Failure> {
                let before = module.call_counts()?;
                component::check(&selected_engine(false)?, path)?;
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("engine_component_native_fallback"));
                }
                Ok(())
            })();
            if let Err(error) = module.close() {
                cleanup.push(error.into());
            }
            return checked;
        }
        if action == "mismatch\n" {
            // Keep a real module observable while checking that an engine
            // identity refusal does not dispatch a native fallback operation.
            let module = config.builder(&Budgets::ordinary()).open()?;
            let checked = (|| -> std::result::Result<(), Failure> {
                let before = module.call_counts()?;
                match selected_engine(true) {
                    Err(Failure::Product(Error::Rejected(
                        RejectionReason::ModuleConfiguration(
                            ModuleConfigurationRejection::ModuleDigestMismatch,
                        ),
                    ))) => (),
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Failure::Oracle("mismatched_engine_identity_accepted")),
                }
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("engine_identity_refusal_dispatched"));
                }
                Ok(())
            })();
            if let Err(error) = module.close() {
                cleanup.push(error.into());
            }
            return checked;
        }
        if action == "missing\n" {
            let result = VerifyEngine::builder(
                config.module.clone(),
                ModuleIntegrity::Sha256 {
                    expected: config.module_sha256,
                    on_mismatch: ModuleDigestMismatch::Refuse,
                },
            )
            .open();
            return match result {
                Err(Error::Rejected(RejectionReason::VerificationEngine(
                    VerificationEngineRejection::VerificationEngineInterfaceExport,
                ))) => Ok(()),
                Err(error) => Err(error.into()),
                Ok(_) => Err(Failure::Oracle("pkcs11_image_accepted_as_engine")),
            };
        }
        if action == "module\n" {
            observe(
                config,
                config.builder(&Budgets::ordinary()),
                None,
                &mut cleanup,
            )?;
        }
        let engine = selected_engine(false)?;
        if action == "module\n" {
            observe(
                config,
                config
                    .builder(&Budgets::ordinary())
                    .verify_engine(Some(engine.clone())),
                Some(&engine),
                &mut cleanup,
            )?;
        }
        observe(
            config,
            config
                .builder(&Budgets::ordinary())
                .verify_engine(Some(engine))
                .verify_engine(None),
            None,
            &mut cleanup,
        )
    })();
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
