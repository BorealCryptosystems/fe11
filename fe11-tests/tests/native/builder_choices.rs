// SPDX-License-Identifier: Apache-2.0
//! Repeated builder choices are observed after opening the actual module.
use super::{
    arguments::hex,
    configuration::{select_token, Budgets, Configuration},
    module_controls,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    num::NonZeroUsize,
    path::Path,
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("builder_choice_open"))?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("builder_choice_read"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::Input("builder_choice_encoding"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("builder_choice_fields"))?;
    if !matches!(
        action,
        "crypto" | "file" | "image" | "dependencies" | "loader"
    ) {
        return Err(Failure::Input("builder_choice_action"));
    }
    Ok(action.into())
}

fn crypto(bytes: usize) -> CryptoOptions {
    CryptoOptions {
        limits: CryptoLimits {
            maximum_parts: 1,
            maximum_total_bytes: bytes,
        },
        edwards: EdwardsOptions {
            parameter_encoding: EdwardsParameterEncoding::Oid,
            point_encoding: EdwardsPointEncoding::Raw,
            key_size_units: EdwardsKeySizeUnits::FieldBits,
        },
    }
}

fn prepare(config: &Configuration, action: &str) -> std::result::Result<ModuleBuilder, Failure> {
    let builder = config
        .builder(&Budgets::ordinary())
        .object_limits(ObjectLimits {
            object_references: Some(77),
            managed_references: Some(66),
            destination_reservations: Some(55),
        });
    let width = NonZeroUsize::new(4096).ok_or(Failure::Input("builder_path_width"))?;
    Ok(match action {
        "crypto" => builder.crypto_options(crypto(2)).crypto_options(crypto(3)),
        "file" => builder
            .windows_file_pinning(WindowsFilePinning::Pin {
                reparse: WindowsReparseHandling::Reject,
                maximum_path_code_units: width,
                maximum_ancestors: Some(32),
            })
            .windows_file_pinning(WindowsFilePinning::NotRequested),
        "image" => builder
            .windows_image_consistency(WindowsImageConsistency::CompareToPinnedFile {
                maximum_mapped_path_code_units: width,
            })
            .windows_image_consistency(WindowsImageConsistency::NotRequested),
        "dependencies" => builder
            .windows_dependency_search(WindowsDependencySearch::Directories {
                module_directory: true,
                application_directory: false,
                application_added_directories: false,
                system32: true,
            })
            .windows_dependency_search(WindowsDependencySearch::ApplicationConfigured),
        "loader" => builder
            .windows_loader_observations(WindowsLoaderObservations::Selected {
                requests: WindowsLoaderRequests::all(WindowsLoaderRequest::Report),
                limits: WindowsLoaderObservationLimits {
                    maximum_path_code_units: width,
                    maximum_registry_entries: 32,
                    maximum_registry_value_bytes: width,
                    maximum_modules: 64,
                    maximum_activation_assemblies: 16,
                    maximum_activation_files: 64,
                    maximum_activation_query_bytes: width,
                },
            })
            .windows_loader_observations(WindowsLoaderObservations::NotRequested),
        _ => return Err(Failure::Input("builder_choice_action")),
    })
}

fn check(module: &Module, session: &Session, action: &str) -> std::result::Result<(), Failure> {
    let limits = module.object_limits();
    if limits.object_references != Some(77)
        || limits.managed_references != Some(66)
        || limits.destination_reservations != Some(55)
    {
        return Err(Failure::Oracle("builder_unrelated_choice_changed"));
    }
    let info = module.info();
    if *info.windows_file_pinning.selection() != WindowsFilePinning::NotRequested
        || *info.windows_image_consistency.selection() != WindowsImageConsistency::NotRequested
        || info.windows_dependency_search != WindowsDependencySearch::ApplicationConfigured
        || info.windows_loader_observations != WindowsLoaderObservations::NotRequested
    {
        return Err(Failure::Oracle("builder_last_loader_choice"));
    }
    let digest = session.digest(
        HashAlgorithm::Sha256,
        b"abc",
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
    )?;
    let expected = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected {
        return Err(Failure::Oracle("builder_digest_control"));
    }
    if action == "crypto" {
        let before = module.call_counts()?;
        match session.digest(
            HashAlgorithm::Sha256,
            b"abcd",
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 4,
            },
        ) {
            Err(Error::Rejected(RejectionReason::ClassicalSignatures(
                ClassicalSignaturesRejection::CryptoInputCeilings,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("builder_crypto_final_ceiling_ignored")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("builder_crypto_guard_dispatched"));
        }
    }
    Ok(())
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let setup = (|| -> std::result::Result<String, Failure> {
        let action = read(path)?;
        module = Some(prepare(config, &action)?.open()?);
        let m = module.as_ref().ok_or(Failure::Input("builder_owner"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("builder_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        Ok(action)
    })();
    let body = match (&setup, &module, &session) {
        (Ok(action), Some(module), Some(session)) => check(module, session, action),
        (Err(_), _, _) => Ok(()),
        _ => Err(Failure::Input("builder_owner")),
    };
    let mut cleanup = Vec::new();
    if let Some(s) = &session {
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
