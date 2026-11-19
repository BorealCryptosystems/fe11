// SPDX-License-Identifier: Apache-2.0
//! Explicit interface selection, rejected selections and independent metadata.
use super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

enum Expected {
    Open((u8, u8), u64),
    Unsupported,
    Absent,
    VersionMismatch,
    CountLimit,
    Attempts,
}

struct Case {
    selection: InterfaceSelection,
    limits: InterfaceDiscoveryLimits,
    expected: Expected,
}

fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut text = String::new();
    File::open(path)
        .map_err(|_| Failure::Input("interface_fixture_open"))?
        .take(65)
        .read_to_string(&mut text)
        .map_err(|_| Failure::Input("interface_fixture_read"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("interface_fixture_fields"))?;
    let standard = |version, required_flags| InterfaceSelection::Standard {
        version,
        required_flags,
    };
    let mut limits = InterfaceDiscoveryLimits {
        interfaces: 2,
        attempts: 2,
    };
    let (selection, expected) = match action {
        "provider_default" => (
            InterfaceSelection::ProviderDefault,
            Expected::Open((3, 2), 1),
        ),
        "legacy240" => (InterfaceSelection::Legacy240, Expected::Open((2, 40), 0)),
        "standard32" => (standard((3, 2), 0), Expected::Open((3, 2), 1)),
        "fork_flag" => (
            standard((3, 2), fe11_sys::CKF_INTERFACE_FORK_SAFE as u64),
            Expected::Open((3, 2), 1),
        ),
        "absent240" => (standard((2, 40), 0), Expected::Absent),
        "absent30" => (standard((3, 0), 0), Expected::Absent),
        "absent31" => (standard((3, 1), 0), Expected::Absent),
        "legacy220" => (InterfaceSelection::Legacy220, Expected::VersionMismatch),
        "legacy230" => (
            InterfaceSelection::Legacy230Draft,
            Expected::VersionMismatch,
        ),
        "unknown_flags" => (standard((3, 2), 2), Expected::Unsupported),
        "major4" => (standard((4, 0), 0), Expected::Unsupported),
        "version33" => (standard((3, 3), 0), Expected::Unsupported),
        "version239" => (standard((2, 39), 0), Expected::Unsupported),
        "interfaces0" => {
            limits.interfaces = 0;
            (standard((3, 2), 0), Expected::CountLimit)
        }
        "interfaces1" => {
            limits.interfaces = 1;
            (standard((3, 2), 0), Expected::Open((3, 2), 1))
        }
        "interfaces2" => {
            limits.interfaces = 2;
            (standard((3, 2), 0), Expected::Open((3, 2), 1))
        }
        "attempts0" => {
            limits.attempts = 0;
            (standard((3, 2), 0), Expected::Attempts)
        }
        "attempts1" => {
            limits.attempts = 1;
            (standard((3, 2), 0), Expected::Open((3, 2), 1))
        }
        "attempts2" => {
            limits.attempts = 2;
            (standard((3, 2), 0), Expected::Open((3, 2), 1))
        }
        _ => return Err(Failure::Input("interface_fixture_action")),
    };
    Ok(Case {
        selection,
        limits,
        expected,
    })
}

fn require(condition: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

fn rejected(error: Error, expected: &Expected) -> std::result::Result<(), Failure> {
    // Collection failures retain the completed native list count in addition
    // to the selection failure. Check both; do not discard the observation.
    match (expected, error) {
        (
            Expected::Unsupported,
            Error::Rejected(RejectionReason::NativeInterfaces(
                NativeInterfacesRejection::UnsupportedInterfaceSelection,
            )),
        ) => Ok(()),
        (
            Expected::Attempts,
            Error::Rejected(RejectionReason::NativeInterfaces(
                NativeInterfacesRejection::InterfaceDiscoveryAttemptsExhausted,
            )),
        ) => Ok(()),
        (
            Expected::VersionMismatch,
            Error::Rejected(RejectionReason::NativeExecution(
                NativeExecutionRejection::UnqualifiedInterfaceVersion,
            )),
        ) => Ok(()),
        (Expected::Absent, Error::NativeOutputAndLocalFailure { size, cause }) => {
            require(
                size.function == "C_GetInterfaceList"
                    && size.code == 0
                    && size.reported == 1
                    && size.limit == 1,
                "interface_absent_count",
            )?;
            match *cause {
                Error::Rejected(RejectionReason::NativeInterfaces(
                    NativeInterfacesRejection::RequestedInterfaceAbsent,
                )) => Ok(()),
                other => Err(other.into()),
            }
        }
        (Expected::CountLimit, Error::NativeOutputAndLocalFailure { size, cause }) => {
            require(
                size.function == "C_GetInterfaceList"
                    && size.code == 0
                    && size.reported == 1
                    && size.limit == 0,
                "interface_limit_count",
            )?;
            match *cause {
                Error::OutputSizeRejected {
                    size: inner,
                    reason: InputBoundsRejection::LengthBound,
                } if inner == size => Ok(()),
                other => Err(other.into()),
            }
        }
        (_, other) => Err(other.into()),
    }
}

fn positive<W: Write>(
    module: &Module,
    config: &Configuration,
    version: (u8, u8),
    flags: u64,
    session: &mut Option<Session>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let selected = module.info();
    require(
        selected.function_list_version == version && selected.interface_flags == flags,
        "interface_selected_table_and_flags",
    )?;
    let before = module.call_counts()?;
    let info = module.library_info()?;
    require(
        info.cryptoki_version == selected.interface_version
            && info.library_version == selected.library_version
            && info.manufacturer == selected.manufacturer
            && info.description == selected.description,
        "interface_library_metadata_independent",
    )?;
    let after = module.call_counts()?;
    require(
        after
            .get("C_GetInfo")
            .copied()
            .unwrap_or(0)
            .checked_sub(before.get("C_GetInfo").copied().unwrap_or(0))
            == Some(1),
        "interface_explicit_info_dispatch",
    )?;
    for (name, value) in [
        ("selected_table_major", version.0),
        ("selected_table_minor", version.1),
        ("reported_cryptoki_major", info.cryptoki_version.0),
        ("reported_cryptoki_minor", info.cryptoki_version.1),
    ] {
        report
            .observation(
                Phase::Body,
                name,
                Producer::Fe11Local,
                Observation::Number(value as u64),
            )
            .map_err(|_| Failure::Input("report_write"))?;
    }
    let token = select_token(module, &config.label).ok_or(Failure::Input("interface_token"))?;
    *session = Some(module.select(&token)?.open_session(true)?);
    module_lifecycle::control(
        session
            .as_ref()
            .ok_or(Failure::Input("interface_session"))?,
    )
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        // Exercise the frozen dependency recipe before intentionally rejected
        // selections, which may return before loading crypto providers.
        let preparation = config.open(&Budgets::ordinary())?;
        preparation.close()?;
        Ok(case)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(case) = &setup else { return Ok(()) };
        match config
            .builder(&Budgets::ordinary())
            .interface(case.selection)
            .interface_discovery(case.limits)
            .open()
        {
            Ok(owner) => {
                module = Some(owner);
                match case.expected {
                    Expected::Open(version, flags) => positive(
                        module.as_ref().ok_or(Failure::Input("interface_module"))?,
                        config,
                        version,
                        flags,
                        &mut session,
                        &mut report,
                    ),
                    _ => Err(Failure::Oracle("rejected_interface_opened")),
                }
            }
            Err(error) => rejected(error, &case.expected),
        }
    })();
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Some(module) = &module {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
