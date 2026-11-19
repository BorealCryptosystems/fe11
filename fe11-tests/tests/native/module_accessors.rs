// SPDX-License-Identifier: Apache-2.0
//! Public module choices and discovery snapshots are observed through their real owners.
use super::{
    configuration::{select_token, Budgets, Configuration},
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn require(value: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

fn same_capabilities(a: &Capabilities, b: &Capabilities) -> bool {
    a.identity == b.identity
        && a.label == b.label
        && a.flags == b.flags
        && a.minimum_pin_length == b.minimum_pin_length
        && a.maximum_pin_length == b.maximum_pin_length
        && a.maximum_sessions == b.maximum_sessions
        && a.maximum_read_write_sessions == b.maximum_read_write_sessions
        && a.slot_description == b.slot_description
        && a.mechanisms == b.mechanisms
        && a.observed_at == b.observed_at
}

fn same_discovery(a: &DiscoveryReport, b: &DiscoveryReport) -> bool {
    a.selection == b.selection
        && a.tokens.len() == b.tokens.len()
        && a.tokens
            .iter()
            .zip(&b.tokens)
            .all(|(a, b)| same_capabilities(a, b))
        && a.failures.len() == b.failures.len()
        && a.failures
            .iter()
            .zip(&b.failures)
            .all(|(a, b)| a.slot == b.slot && a.error == b.error)
}

fn policy(intersect: bool) -> SessionPolicy {
    SessionPolicy {
        module_read_write: 7,
        default_token: SessionLimit {
            total: 5,
            read_write: 3,
        },
        tokens: vec![],
        announced_limits: if intersect {
            AnnouncedSessionLimits::IntersectWithAnnounced
        } else {
            AnnouncedSessionLimits::Ignore
        },
    }
}

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("accessor_fixture_open"))?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("accessor_fixture_read"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::Input("accessor_fixture_encoding"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("accessor_fixture_terminator"))?;
    if !matches!(
        action,
        "targets"
            | "discovery"
            | "capabilities"
            | "resources"
            | "limits"
            | "chacha"
            | "builder_discovery"
            | "builder_objects"
            | "builder_sessions"
            | "builder_interface"
    ) {
        return Err(Failure::Input("accessor_fixture_action"));
    }
    Ok(action.into())
}

fn builder(config: &Configuration, action: &str, second: bool) -> ModuleBuilder {
    let builder = config.builder(&Budgets::ordinary());
    match action {
        "chacha" => {
            if second {
                builder
                    .chacha_nonce_length_encoding(ChaChaNonceLengthEncoding::Bits)
                    .chacha_nonce_length_encoding(ChaChaNonceLengthEncoding::BytesCompatibility)
            } else {
                builder
                    .chacha_nonce_length_encoding(ChaChaNonceLengthEncoding::BytesCompatibility)
                    .chacha_nonce_length_encoding(ChaChaNonceLengthEncoding::Bits)
            }
        }
        "builder_discovery" => {
            if second {
                builder
                    .discovery(DiscoverySelection::Deferred)
                    .discovery(DiscoverySelection::AllPresentSlots)
            } else {
                builder
                    .discovery(DiscoverySelection::AllPresentSlots)
                    .discovery(DiscoverySelection::Deferred)
            }
        }
        "builder_objects" => builder
            .object_limits(ObjectLimits {
                object_references: Some(7),
                managed_references: Some(8),
                destination_reservations: Some(9),
            })
            .object_limits(ObjectLimits {
                object_references: Some(11),
                managed_references: Some(12),
                destination_reservations: Some(13),
            }),
        "builder_sessions" => builder
            .session_policy(policy(true))
            .session_policy(policy(false)),
        "limits" => builder.session_policy(policy(second)),
        "builder_interface" => {
            let other = match config.interface {
                InterfaceSelection::Legacy240 => InterfaceSelection::Standard {
                    version: (3, 2),
                    required_flags: 0,
                },
                _ => InterfaceSelection::Legacy240,
            };
            builder.interface(other).interface(config.interface)
        }
        _ => builder,
    }
}

fn check(
    module: &Module,
    config: &Configuration,
    action: &str,
    second: bool,
    session: &mut Option<Session>,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    match action {
        "targets" => {
            let targets = module.administration_targets()?;
            let report = module.initial_discovery();
            require(
                report.failures.is_empty() && targets.len() == report.tokens.len(),
                "accessor_target_count",
            )?;
            for observed in &report.tokens {
                let matching: Vec<_> = targets
                    .iter()
                    .filter(|t| t.capabilities().identity == observed.identity)
                    .collect();
                require(
                    matching.len() == 1 && same_capabilities(matching[0].capabilities(), observed),
                    "accessor_target_snapshot",
                )?;
            }
        }
        "discovery" => {
            let initial = module.initial_discovery().clone();
            require(
                initial.selection == DiscoverySelection::AllPresentSlots
                    && initial.failures.is_empty(),
                "accessor_initial_scope",
            )?;
            require(
                module.call_counts()? == before,
                "accessor_initial_getter_dispatch",
            )?;
            let refreshed = module.refresh_tokens_report(DiscoverySelection::AllPresentSlots)?;
            require(refreshed.failures.is_empty(), "accessor_refresh_failure")?;
            let after_refresh = module.call_counts()?;
            require(
                same_discovery(&initial, module.initial_discovery()),
                "accessor_initial_snapshot_changed",
            )?;
            return require(
                module.call_counts()? == after_refresh,
                "accessor_initial_getter_dispatch",
            );
        }
        "capabilities" | "limits" => {
            let identity =
                select_token(module, &config.label).ok_or(Failure::Input("accessor_token"))?;
            let context = module.select(&identity)?;
            let cap = context.capabilities();
            let expected = module
                .initial_discovery()
                .tokens
                .iter()
                .find(|t| t.identity == identity)
                .ok_or(Failure::Oracle("accessor_token_snapshot_absent"))?;
            require(
                same_capabilities(cap, expected),
                "accessor_token_capabilities",
            )?;
            if action == "limits" {
                // Both PKCS#11 sentinels mean no finite native ceiling. They remain
                // distinct in the unchanged snapshot; only the arithmetic coincides.
                let intersect = |local: usize, native: u64| {
                    if !second
                        || native == fe11_sys::CK_EFFECTIVELY_INFINITE as u64
                        || native == fe11_sys::CK_UNAVAILABLE_INFORMATION as u64
                    {
                        local
                    } else {
                        local.min(usize::try_from(native).unwrap_or(usize::MAX))
                    }
                };
                require(
                    context.effective_session_limits()
                        == SessionLimit {
                            total: intersect(5, cap.maximum_sessions),
                            read_write: intersect(3, cap.maximum_read_write_sessions),
                        },
                    "accessor_effective_limits",
                )?;
            }
        }
        "resources" => {
            let baseline = module.resource_status()?;
            require(
                baseline.usage == SessionUsage::default() && baseline.tokens.is_empty(),
                "accessor_initial_usage",
            )?;
            require(
                module.call_counts()? == before,
                "accessor_resource_getter_dispatch",
            )?;
            let identity =
                select_token(module, &config.label).ok_or(Failure::Input("accessor_token"))?;
            *session = Some(module.select(&identity)?.open_session(true)?);
            let after_open = module.call_counts()?;
            let active = module.resource_status()?;
            let expected = SessionUsage {
                total: 1,
                read_write: 1,
                open: 1,
                ..SessionUsage::default()
            };
            require(
                active.usage == expected
                    && active.tokens.len() == 1
                    && active.tokens[0].identity == identity
                    && active.tokens[0].usage == expected,
                "accessor_active_session_usage",
            )?;
            require(
                module.call_counts()? == after_open,
                "accessor_resource_getter_dispatch",
            )?;
            session
                .as_ref()
                .ok_or(Failure::Input("accessor_session"))?
                .close()?;
            drop(session.take());
            let after_close = module.call_counts()?;
            require(
                module.resource_status()? == baseline,
                "accessor_released_session_usage",
            )?;
            return require(
                module.call_counts()? == after_close,
                "accessor_resource_getter_dispatch",
            );
        }
        "chacha" => require(
            module.chacha_nonce_length_encoding()
                == if second {
                    ChaChaNonceLengthEncoding::BytesCompatibility
                } else {
                    ChaChaNonceLengthEncoding::Bits
                },
            "accessor_chacha_choice",
        )?,
        "builder_discovery" => {
            let report = module.initial_discovery();
            if second {
                require(
                    report.selection == DiscoverySelection::AllPresentSlots
                        && !report.tokens.is_empty()
                        && report.failures.is_empty(),
                    "accessor_discovery_present",
                )?;
            } else {
                require(
                    report.selection == DiscoverySelection::Deferred
                        && report.tokens.is_empty()
                        && report.failures.is_empty()
                        && module.tokens().is_empty(),
                    "accessor_discovery_deferred",
                )?;
                for function in [
                    "C_GetSlotList",
                    "C_GetTokenInfo",
                    "C_GetMechanismList",
                    "C_GetMechanismInfo",
                ] {
                    require(
                        before.get(function).copied().unwrap_or(0) == 0,
                        "accessor_deferred_dispatch",
                    )?;
                }
            }
        }
        "builder_objects" => {
            let limits = module.object_limits();
            require(
                limits.object_references == Some(11)
                    && limits.managed_references == Some(12)
                    && limits.destination_reservations == Some(13),
                "accessor_object_limits",
            )?;
        }
        "builder_sessions" => {
            let p = module.session_policy();
            require(
                p.module_read_write == 7
                    && p.default_token == policy(false).default_token
                    && p.tokens.is_empty()
                    && p.announced_limits == AnnouncedSessionLimits::Ignore,
                "accessor_session_policy",
            )?;
        }
        "builder_interface" => {
            let version = match config.interface {
                InterfaceSelection::Legacy240 => (2, 40),
                InterfaceSelection::Standard { version, .. } => version,
                _ => return Err(Failure::Input("accessor_selected_interface")),
            };
            require(
                module.info().function_list_version == version,
                "accessor_selected_table",
            )?;
        }
        _ => return Err(Failure::Input("accessor_action")),
    }
    require(module.call_counts()? == before, "accessor_getter_dispatch")
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let setup = read(path);
    let started = setup.is_ok();
    let mut cleanup = Vec::new();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(action) => (|| -> std::result::Result<(), Failure> {
            let repeat = matches!(action.as_str(), "chacha" | "limits" | "builder_discovery");
            for second in [false, true].into_iter().take(if repeat { 2 } else { 1 }) {
                let module = builder(config, action, second).open()?;
                let mut session = None;
                let result = check(&module, config, action, second, &mut session);
                if let Some(session) = session {
                    if let Err(error) = session.close() {
                        cleanup.push(error.into());
                    }
                }
                if let Err(error) = module.close() {
                    cleanup.push(error.into());
                }
                result?;
                if !cleanup.is_empty() {
                    break;
                }
            }
            Ok(())
        })(),
    };
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "public_module_choice_and_snapshot",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
