// SPDX-License-Identifier: Apache-2.0
//! Exact digest dispatch and explicit closure of idle, active and completed owners.
use super::{module_controls, Budgets, Configuration, Failure, Report};
use crate::object_owner::Owner;
use fe11::*;
use std::{
    collections::BTreeMap,
    io::{self, Write},
};

fn limits() -> InputLimits {
    InputLimits {
        maximum_parts: 3,
        maximum_total_bytes: 3,
    }
}

fn answer(value: &NativeDigest) -> std::result::Result<(), Failure> {
    let expected = crate::arguments::hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if value.as_bytes() != expected {
        return Err(Failure::Oracle("owner_digest_answer"));
    }
    Ok(())
}

fn exact_calls(
    module: &Module,
    mut before: BTreeMap<&'static str, u64>,
    calls: &[&'static str],
) -> std::result::Result<(), Failure> {
    for call in calls {
        let old = before.get(call).copied().unwrap_or(0);
        before.insert(
            call,
            old.checked_add(1)
                .ok_or(Failure::Oracle("counter_overflow"))?,
        );
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("owner_native_dispatch"));
    }
    Ok(())
}

fn completed(
    module: &Module,
    owner: &Owner,
    eager: bool,
) -> std::result::Result<NativeDigest, Failure> {
    let before = module.call_counts()?;
    let value = match owner {
        Owner::Session(s) => {
            let value =
                s.digest_native(NativeDigestAlgorithm::Sha256, &[b"a", b"b", b"c"], limits())?;
            exact_calls(
                module,
                before,
                &[
                    "C_DigestInit",
                    "C_DigestUpdate",
                    "C_DigestUpdate",
                    "C_DigestUpdate",
                    "C_DigestFinal",
                ],
            )?;
            value
        }
        Owner::Advanced(s) => {
            let mut ticket =
                s.digest_native(NativeDigestAlgorithm::Sha256, &[b"a", b"b", b"c"], limits())?;
            if eager {
                exact_calls(
                    module,
                    before,
                    &[
                        "C_DigestInit",
                        "C_DigestUpdate",
                        "C_DigestUpdate",
                        "C_DigestUpdate",
                        "C_DigestFinal",
                    ],
                )?;
            } else {
                exact_calls(module, before, &["C_DigestInit"])?;
                for function in ["C_DigestUpdate", "C_DigestUpdate", "C_DigestUpdate"] {
                    let before = module.call_counts()?;
                    if s.next_native_function(&ticket)? != Some(function) {
                        return Err(Failure::Oracle("digest_next_update"));
                    }
                    exact_calls(module, before.clone(), &[])?;
                    if !matches!(s.poll(&mut ticket)?, OperationProgress::Ready) {
                        return Err(Failure::Oracle("digest_update_published_early"));
                    }
                    exact_calls(module, before, &[function])?;
                }
            }
            let before = module.call_counts()?;
            let expected = if eager { None } else { Some("C_DigestFinal") };
            if s.next_native_function(&ticket)? != expected {
                return Err(Failure::Oracle("digest_next_final_or_publication"));
            }
            exact_calls(module, before.clone(), &[])?;
            let value = match s.poll(&mut ticket)? {
                OperationProgress::NativeDigest(value) => value,
                _ => return Err(Failure::Oracle("digest_final_publication")),
            };
            exact_calls(module, before, if eager { &[] } else { &["C_DigestFinal"] })?;
            value
        }
    };
    answer(&value)?;
    Ok(value)
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    action: &str,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut owner = None;
    let mut ticket = None;
    let mut output = None;
    let mut closed = false;
    let setup = (|| -> std::result::Result<(&str, bool), Failure> {
        let (kind, state) = action
            .strip_prefix("owner-")
            .and_then(|s| s.split_once('-'))
            .ok_or(Failure::Input("owner_progress_selector"))?;
        if !matches!(kind, "session" | "eager" | "cooperative")
            || !matches!(state, "idle" | "active" | "completed")
        {
            return Err(Failure::Input("owner_progress_selector"));
        }
        let mut budgets = Budgets::ordinary();
        budgets.sessions = 1;
        module = Some(config.open(&budgets)?);
        let m = module.as_ref().ok_or(Failure::Input("owner_module"))?;
        owner = Some(Owner::open(m, config, kind != "session")?);
        if let Some(Owner::Advanced(s)) = &mut owner {
            s.set_pacing(if kind == "eager" {
                OperationPacing::Eager
            } else {
                OperationPacing::Cooperative
            })?;
            s.set_validation_capture(ValidationCaptureMode::Disabled)?;
        }
        Ok((state, kind == "eager"))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((state, eager)) = setup.as_ref() else {
            return Ok(());
        };
        let m = module.as_ref().ok_or(Failure::Input("owner_module"))?;
        let o = owner.as_ref().ok_or(Failure::Input("owner_session"))?;
        if *state == "active" {
            ticket = Some(match o {
                Owner::Session(s) => s.begin_native_digest(NativeDigestAlgorithm::Sha256)?,
                Owner::Advanced(s) => s.begin_native_digest(NativeDigestAlgorithm::Sha256)?,
            });
            let t = ticket.as_mut().ok_or(Failure::Input("owner_ticket"))?;
            for part in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
                match o {
                    Owner::Session(s) => s.digest_update(t, part, limits())?,
                    Owner::Advanced(s) => s.digest_update(t, part, limits())?,
                }
            }
        } else if *state == "completed" {
            output = Some(completed(m, o, *eager)?);
        }
        let before = m.call_counts()?;
        let mut failures = o.close(None);
        if !failures.is_empty() {
            return Err(failures.remove(0));
        }
        closed = true;
        exact_calls(m, before, &["C_CloseSession"])?;
        let resources = m.resource_status()?;
        if resources.usage != SessionUsage::default() || !resources.tokens.is_empty() {
            return Err(Failure::Oracle("owner_close_retained_credit"));
        }
        if let Some(value) = &output {
            answer(value)?;
        }
        Ok(())
    })();
    drop(ticket);
    let mut cleanup = Vec::new();
    if !closed {
        if let Some(o) = &owner {
            cleanup.extend(o.close(None));
        }
    }
    drop(owner);
    if let Some(m) = &module {
        if let Err(e) = m.close() {
            cleanup.push(e.into());
        }
    }
    drop(module);
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
