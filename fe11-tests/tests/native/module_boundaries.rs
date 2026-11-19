// SPDX-License-Identifier: Apache-2.0
//! Rejected file sources and genuinely unobserved native mechanism catalogues.
use super::{
    configuration::{Budgets, Configuration},
    module_controls,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("module_boundary_open"))?
        .take(33)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("module_boundary_read"))?;
    match data.as_slice() {
        b"relative\n" => Ok("relative".into()),
        b"directory\n" => Ok("directory".into()),
        b"catalogue\n" => Ok("catalogue".into()),
        b"process_file\n" => Ok("process_file".into()),
        _ => Err(Failure::Input("module_boundary_fixture")),
    }
}
fn paths(
    config: &Configuration,
    action: &str,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    if action == "process_file" {
        let budgets = Budgets::ordinary();
        let result = Module::process_builder(
            Limits {
                slots: budgets.slots,
                mechanisms: budgets.mechanisms,
                discovery_attempts: budgets.discovery_attempts,
                sessions: budgets.sessions,
            },
            config.options(&budgets),
        )
        .windows_file_pinning(WindowsFilePinning::Pin {
            reparse: WindowsReparseHandling::Reject,
            maximum_path_code_units: std::num::NonZeroUsize::new(4096)
                .ok_or(Failure::Input("process_path_width"))?,
            maximum_ancestors: Some(32),
        })
        .open();
        return match result {
            Err(Error::Unsupported(UnsupportedReason::ModuleLifecycle(
                ModuleLifecycleUnsupported::FileLoadingOptionsForProcessSource,
            ))) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(module) => {
                if let Err(error) = module.close() {
                    cleanup.push(error.into());
                }
                Err(Failure::Oracle("process_file_options_accepted"))
            }
        };
    }
    let mut directory = None;
    let target = if action == "relative" {
        std::path::PathBuf::from("relative-module.so")
    } else {
        let parent = std::env::current_dir()
            .and_then(|p| p.canonicalize())
            .map_err(|_| Failure::Input("module_boundary_directory"))?;
        let path = parent.join("non-module-directory");
        // Exclusive creation in this isolated invocation's owned working directory.
        // Never reuse or remove an existing entry, and never recursively delete.
        fs::create_dir(&path).map_err(|_| Failure::Input("module_boundary_create_directory"))?;
        directory = Some(path.clone());
        path
    };
    let altered = Configuration {
        module: target,
        module_sha256: config.module_sha256,
        interface: config.interface,
        label: config.label.clone(),
    };
    let result = altered.builder(&Budgets::ordinary()).open();
    let expected = if action == "relative" {
        ModuleLifecycleRejection::AbsoluteModulePathRequired
    } else {
        ModuleLifecycleRejection::ModuleIsNotRegularFile
    };
    let body = match result {
        Err(Error::Rejected(RejectionReason::ModuleLifecycle(actual))) if actual == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(unexpected) => {
            if let Err(error) = unexpected.close() {
                cleanup.push(error.into());
            }
            Err(Failure::Oracle("invalid_module_path_accepted"))
        }
    };
    if let Some(path) = directory {
        if fs::remove_dir(path).is_err() {
            cleanup.push(Failure::Input("module_boundary_remove_directory"));
        }
    }
    body
}
fn catalogue(
    config: &Configuration,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let module = config.open(&Budgets::ordinary())?;
    let body = (|| -> std::result::Result<(), Failure> {
        let before = module.call_counts()?;
        let blank: Vec<_> = module
            .initial_discovery()
            .tokens
            .iter()
            .filter(|c| c.flags & fe11_sys::CKF_TOKEN_INITIALIZED as u64 == 0)
            .cloned()
            .collect();
        if blank.is_empty() {
            return Err(Failure::Input("uninitialized_token_unavailable"));
        }
        for token in blank {
            if !matches!(
                token.mechanisms.discovery(),
                MechanismDiscovery::NotRequested
            ) {
                return Err(Failure::Oracle("blank_catalogue_provenance"));
            }
            match token.mechanisms.properties(&(fe11_sys::CKM_SHA256 as u64)) {
                Err(Error::Unsupported(UnsupportedReason::Mechanisms(
                    MechanismsUnsupported::MechanismListNotObserved,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("unobserved_mechanism_claimed")),
            }
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("unobserved_catalogue_dispatched"));
        }
        Ok(())
    })();
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    body
}
pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let setup = read(path);
    let mut cleanup = Vec::new();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(action) if action == "catalogue" => catalogue(config, &mut cleanup),
        Ok(action) => {
            // Initialize a separate valid owner as preparation so the complete
            // recipe dependencies are exercised and identified. The invalid
            // builder below must add no initialization or finalization call.
            match config.open(&Budgets::ordinary()) {
                Err(error) => Err(error.into()),
                Ok(module) => {
                    let body = paths(config, action, &mut cleanup);
                    if let Err(error) = module.close() {
                        cleanup.push(error.into());
                    }
                    body
                }
            }
        }
    };
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
