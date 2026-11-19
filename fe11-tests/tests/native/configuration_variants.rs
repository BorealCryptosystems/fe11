// SPDX-License-Identifier: Apache-2.0
//! Observe an explicit module recipe through public metadata and digest calls.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

type Catalogue = BTreeMap<u64, (u64, u64, u64)>;

fn read(path: &Path) -> std::result::Result<(String, BTreeSet<u64>, Catalogue), Failure> {
    let mut text = String::new();
    File::open(path)
        .and_then(|file| file.take(8193).read_to_string(&mut text))
        .map_err(|_| Failure::Input("configuration_fixture_read"))?;
    if text.len() > 8192 || !text.ends_with('\n') {
        return Err(Failure::Input("configuration_fixture_size"));
    }
    let mut lines = text.lines();
    let action = lines
        .next()
        .and_then(|s| s.strip_prefix("configuration:"))
        .ok_or(Failure::Input("configuration_fixture_action"))?
        .to_owned();
    let mut ids = BTreeSet::new();
    let mut metadata = BTreeMap::new();
    for line in lines {
        let fields: Vec<_> = line.split('\t').collect();
        if !matches!(fields.len(), 1 | 4) {
            return Err(Failure::Input("configuration_catalogue_fields"));
        }
        let id = fields[0]
            .parse::<u64>()
            .map_err(|_| Failure::Input("configuration_fixture_id"))?;
        if ids.len() == 512 || !ids.insert(id) {
            return Err(Failure::Input("configuration_fixture_catalogue"));
        }
        if fields.len() == 4 {
            let number = |text: &str| {
                text.parse::<u64>()
                    .map_err(|_| Failure::Input("configuration_catalogue_number"))
            };
            metadata.insert(
                id,
                (number(fields[1])?, number(fields[2])?, number(fields[3])?),
            );
        }
    }
    if ids.is_empty() {
        return Err(Failure::Input("configuration_fixture_empty_catalogue"));
    }
    if !metadata.is_empty() && metadata.len() != ids.len() {
        return Err(Failure::Input("configuration_catalogue_mixed_shapes"));
    }
    Ok((action, ids, metadata))
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let (action, baseline, metadata) = match read(path) {
        Ok(value) => value,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), Vec::new()),
    };
    let action = action.as_str();
    let expected_init_failure = matches!(
        action,
        "log-invalid"
            | "absent-file"
            | "directory-missing"
            | "directory-file"
            | "directory-inaccessible"
    );
    let body = (|| -> std::result::Result<(), Failure> {
        if !matches!(
            action,
            "removable-true"
                | "removable-false"
                | "mechanisms-include"
                | "mechanisms-exclude"
                | "mechanisms-empty"
                | "mechanisms-default"
                | "reset-true"
                | "reset-false"
                | "log-error"
                | "log-warning"
                | "log-info"
                | "log-debug"
                | "log-invalid"
                | "malformed-line"
                | "unknown-key"
                | "absent-file"
                | "directory-missing"
                | "directory-file"
                | "directory-inaccessible"
                | "log-owned"
                | "log-unopenable"
                | "umask-zero"
                | "umask-private"
                | "umask-deny"
                | "umask-invalid"
        ) {
            return Err(Failure::Input("configuration_variant"));
        }
        if action == "directory-inaccessible" {
            // The CI container may run as root. A mode000 directory is a real
            // denial only after both DAC-bypass capabilities are absent from
            // this actual native worker, not merely from its supervisor.
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|_| Failure::Input("permission_worker_status"))?;
            let effective = status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:"))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .ok_or(Failure::Input("permission_worker_capabilities"))?;
            const DAC_BYPASS_CAPABILITIES: u64 = (1 << 1) | (1 << 2);
            if effective & DAC_BYPASS_CAPABILITIES != 0 {
                return Err(Failure::Input("permission_worker_can_bypass_denial"));
            }
        }
        match config.builder(&Budgets::ordinary()).open() {
            Err(Error::Native {
                function: "C_Initialize",
                code: 5,
                ..
            }) if expected_init_failure => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(value) => module = Some(value),
        }
        if expected_init_failure {
            return Err(Failure::Oracle("invalid_configuration_initialized"));
        }
        let m = module
            .as_ref()
            .ok_or(Failure::Input("configuration_module"))?;
        let token = select_token(m, &config.label)
            .ok_or(Failure::Oracle("configuration_owned_token_missing"))?;
        if matches!(action, "removable-true" | "removable-false") {
            let removable =
                m.slot_info(token.slot)?.flags & fe11_sys::CKF_REMOVABLE_DEVICE as u64 != 0;
            if removable != (action == "removable-true") {
                return Err(Failure::Oracle("configuration_removable_flag"));
            }
        }
        if action.starts_with("mechanisms-") {
            let mechanisms = m.mechanism_ids(token.slot)?;
            let sha256 = fe11_sys::CKM_SHA256 as u64;
            let expected = match action {
                "mechanisms-include" => BTreeSet::from([sha256]),
                "mechanisms-exclude" => baseline
                    .iter()
                    .copied()
                    .filter(|id| *id != sha256)
                    .collect(),
                _ => baseline.clone(),
            };
            let actual: BTreeSet<_> = mechanisms.iter().copied().collect();
            if actual.len() != mechanisms.len() || actual != expected {
                return Err(Failure::Oracle("configuration_mechanism_catalogue"));
            }
            // Filtering the list must not rewrite the capabilities of entries
            // that remain visible. Compare all three published metadata fields.
            if !metadata.is_empty() {
                for id in actual {
                    let wanted = metadata
                        .get(&id)
                        .ok_or(Failure::Input("configuration_metadata_absent"))?;
                    let info = m.mechanism_info(token.slot, id)?;
                    if (info.minimum, info.maximum, info.flags) != *wanted {
                        return Err(Failure::Oracle("configuration_mechanism_metadata"));
                    }
                }
            }
        }
        session = Some(m.select(&token)?.open_session(true)?);
        let s = session
            .as_ref()
            .ok_or(Failure::Input("configuration_session"))?;
        // The pinned recipe filters announcements. Its digest implementation
        // still accepts SHA256; the catalogue is not an access-control boundary.
        // Exercise and check this distinction instead of inventing a local gate.
        module_lifecycle::control(s)?;
        Ok(())
    })();
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
    drop(module);
    module_controls::finish(report, Ok(()), body, cleanup)
}
