// SPDX-License-Identifier: Apache-2.0
//! Synchronous KEM results outlive their native session; no ticket is invented.
use super::{
    configuration::Configuration,
    credentials::Credentials,
    kem_lifecycle_fixture::Fixture,
    module_controls,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "kem_capacity.rs"]
mod capacity;

struct Case {
    encapsulate: bool,
    state: String,
    action: String,
    parameter_set: Option<u64>,
}
fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("kem_fixture_open"))?
        .take(129)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("kem_fixture_read"))?;
    let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("kem_fixture_utf8"))?;
    let f: Vec<_> = text.split_terminator('\n').collect();
    if data.len() <= 128 && f.len() == 3 && f[0] == "capacity" {
        if !matches!(f[2], "zero" | "short" | "large" | "observation") {
            return Err(Failure::Input("kem_capacity_action"));
        }
        return Ok(Case {
            encapsulate: true,
            state: "CAPACITY".into(),
            action: f[2].into(),
            parameter_set: Some(match f[1] {
                "512" => fe11_sys::CKP_ML_KEM_512 as u64,
                "768" => fe11_sys::CKP_ML_KEM_768 as u64,
                "1024" => fe11_sys::CKP_ML_KEM_1024 as u64,
                _ => return Err(Failure::Input("kem_capacity_set")),
            }),
        });
    }
    if data.len() > 128
        || !matches!(f.len(), 3 | 4)
        || !matches!(f[0], "encapsulate" | "decapsulate")
        || !matches!(
            f[1],
            "IDLE" | "CONSUMED" | "REFUSED_TERMINAL" | "RETIRED" | "USAGE_DENIED"
        )
        || !matches!(
            f[2],
            "init" | "identity" | "public-import" | "take" | "logout" | "close" | "read_after_close"
        )
    {
        return Err(Failure::Input("kem_fixture_fields"));
    }
    if matches!(f[2], "public-import" | "identity") && (f.len() != 4 || f[..2] != ["encapsulate", "IDLE"]) {
        return Err(Failure::Input("kem_identity_case"));
    }
    Ok(Case {
        encapsulate: f[0] == "encapsulate",
        state: f[1].into(),
        action: f[2].into(),
        parameter_set: if f.len() == 4 {
            if f[..2] != ["encapsulate", "IDLE"] || !matches!(f[2], "init" | "identity" | "public-import") {
                return Err(Failure::Input("kem_parameter_case"));
            }
            Some(match f[3] {
                "ML-KEM-512" => fe11_sys::CKP_ML_KEM_512 as u64,
                "ML-KEM-768" => fe11_sys::CKP_ML_KEM_768 as u64,
                "ML-KEM-1024" => fe11_sys::CKP_ML_KEM_1024 as u64,
                _ => return Err(Failure::Input("kem_parameter_set")),
            })
        } else {
            None
        },
    })
}
fn fingerprint(f: &Fixture) -> Vec<([u8; 32], Option<Vec<u8>>)> {
    f.values
        .iter()
        .zip(&f.results)
        .map(|(value, result)| {
            (
                Sha256::digest(value.as_slice()).into(),
                result.ciphertext().map(Vec::from),
            )
        })
        .collect()
}
fn invoke(
    f: &mut Fixture,
    c: &Case,
    ciphertext: &[u8],
    expected: Option<usize>,
) -> std::result::Result<(), Failure> {
    if c.encapsulate {
        f.matching_pair()?;
    } else {
        let index = f.call(false, ciphertext, false)?;
        let sender = expected.ok_or(Failure::Input("kem_sender_control"))?;
        if f.values[index].as_slice() != f.values[sender].as_slice() {
            return Err(Failure::Oracle("kem_decapsulation_control"));
        }
    }
    Ok(())
}
fn retired<T>(
    result: std::result::Result<T, Failure>,
    logout: bool,
) -> std::result::Result<(), Failure> {
    let expected = if logout {
        RejectionReason::Authentication(AuthenticationRejection::LogoutRequiresLiveSession)
    } else {
        RejectionReason::SessionLifecycle(SessionLifecycleRejection::SessionClosed)
    };
    match result {
        Err(Failure::Product(Error::Rejected(actual))) if actual == expected => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(Failure::Oracle("kem_retired_session_accepted")),
    }
}
fn native_refusal(error: &Error, encapsulate: bool, expected_code: u64) -> bool {
    match error {
        Error::ObjectsMayRemain(cause) => native_refusal(cause, encapsulate, expected_code),
        Error::Native {
            function,
            code,
            may_have_effect,
        } => {
            *function
                == if encapsulate {
                    "C_EncapsulateKey"
                } else {
                    "C_DecapsulateKey"
                }
                && *code == expected_code
                && *may_have_effect
        }
        _ => false,
    }
}
pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = None;
    let mut ciphertext = Vec::new();
    let mut sender = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = read(path)?;
        fixture = Some(Fixture::open(&module, config)?);
        let f = fixture.as_mut().ok_or(Failure::Input("kem_fixture"))?;
        f.prepare(pins, case.parameter_set)?;
        // A decapsulation transition consumes a real peer encapsulation. These
        // lifecycle checks do not substitute for the separate published KATs.
        if !case.encapsulate {
            let index = f.call(true, &[], false)?;
            ciphertext = f.results[index]
                .ciphertext()
                .ok_or(Failure::Oracle("kem_control_ciphertext"))?
                .to_vec();
            sender = Some(index);
        }
        match case.state.as_str() {
            "CONSUMED" => invoke(f, &case, &ciphertext, sender)?,
            "REFUSED_TERMINAL" => {
                // Prove the same keys and output template work before removing
                // only CKA_CLASS. Keep all control objects for explicit cleanup.
                invoke(f, &case, &ciphertext, sender)?;
                match f.call(case.encapsulate, &ciphertext, true) {
                    Err(Failure::Product(error))
                        if native_refusal(
                            &error,
                            case.encapsulate,
                            fe11_sys::CKR_TEMPLATE_INCOMPLETE as u64,
                        ) =>
                    {
                        outcome::record(&mut report, Phase::Setup, &Failure::Product(error))
                            .map_err(|_| Failure::Input("kem_report"))?;
                    }
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Failure::Oracle("kem_missing_class_accepted")),
                }
            }
            "RETIRED" => f.close()?,
            "USAGE_DENIED" => {
                invoke(f, &case, &ciphertext, sender)?;
                f.deny_usage(case.encapsulate)?;
            }
            _ => (),
        }
        Ok(case)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(case) = &setup else { return Ok(()) };
        let f = fixture.as_mut().ok_or(Failure::Input("kem_fixture"))?;
        if case.state == "CAPACITY" {
            return capacity::check(
                f,
                &case.action,
                case.parameter_set
                    .ok_or(Failure::Input("kem_capacity_set"))?,
                &mut report,
            );
        }
        let before = fingerprint(f);
        let calls = module.call_counts()?;
        match case.action.as_str() {
            "public-import" => {
                let set = case.parameter_set.ok_or(Failure::Input("kem_import_parameter_set"))?;
                let width = match set {
                    n if n == fe11_sys::CKP_ML_KEM_512 as u64 => 800,
                    n if n == fe11_sys::CKP_ML_KEM_768 as u64 => 1184,
                    n if n == fe11_sys::CKP_ML_KEM_1024 as u64 => 1568,
                    _ => return Err(Failure::Input("kem_import_parameter_set")),
                };
                f.import_public(set, width)?;
                f.matching_pair()?;
            }
            "identity" => {
                // Preparation has read both parameter-set attributes and the
                // public encoding. This case exercises generation through the
                // legacy table without requiring a KEM operation interface.
                if f.pair.is_none() || !f.results.is_empty() || !f.values.is_empty() {
                    return Err(Failure::Oracle("kem_identity_ownership"));
                }
            }
            "init" => {
                if case.state == "USAGE_DENIED" {
                    match f.call(case.encapsulate, &ciphertext, false) {
                        Err(Failure::Product(error))
                            if native_refusal(
                                &error,
                                case.encapsulate,
                                fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64,
                            ) =>
                        {
                            outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                                .map_err(|_| Failure::Input("kem_report"))?;
                        }
                        Err(error) => return Err(error),
                        Ok(_) => return Err(Failure::Oracle("kem_forbidden_usage_accepted")),
                    }
                    if fingerprint(f) != before {
                        return Err(Failure::Oracle("kem_usage_refusal_changed_control"));
                    }
                    return Ok(());
                }
                let result = invoke(f, case, &ciphertext, sender);
                if f.closed {
                    retired(result, false)?;
                } else {
                    result?;
                }
            }
            "take" => {
                if before.len() < 2 {
                    return Err(Failure::Oracle("kem_owned_result_missing"));
                }
            }
            "read_after_close" => {
                f.close()?;
            }
            "logout" => {
                let result = f.session.logout().map_err(Failure::from);
                if f.closed {
                    retired(result, true)?;
                } else {
                    result?;
                    f.logged = false;
                    if f.session.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                        return Err(Failure::Oracle("kem_logout_state"));
                    }
                }
            }
            "close" => {
                let result = f.close();
                if case.state == "RETIRED" {
                    retired(result, false)?;
                } else {
                    result?;
                }
            }
            _ => return Err(Failure::Input("kem_action")),
        }
        if (case.action == "take" || case.state == "RETIRED") && module.call_counts()? != calls {
            return Err(Failure::Oracle("kem_local_action_dispatched"));
        }
        let after = fingerprint(f);
        if after.len() < before.len() || after[..before.len()] != before {
            return Err(Failure::Oracle("kem_owned_result_changed"));
        }
        Ok(())
    })();
    let mut cleanup = fixture.as_mut().map_or_else(Vec::new, Fixture::cleanup);
    drop(fixture);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
