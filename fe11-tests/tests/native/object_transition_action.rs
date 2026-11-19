// SPDX-License-Identifier: Apache-2.0
//! Object actions preserve exact native refusals and local lifetime diagnoses.
use super::{
    credentials::Credentials,
    object_transition_fixture::{check, find, label_template, limits, read, Case, Fixture},
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

fn raw(f: &mut Fixture, action: &str) -> std::result::Result<(), Failure> {
    match action {
        "read" => {
            read(f.peer()?, f.object()?, &f.label)?;
        }
        "search" => {
            find(f.peer()?, &f.label)?;
        }
        "copy" => {
            f.copied = Some(f.peer()?.copy_native_object(
                f.object()?,
                &label_template(&f.copy_label),
                limits(1, f.copy_label.len()),
            )?);
        }
        "mutate" => f.peer()?.set_native_attributes(
            f.object()?,
            &label_template(&f.changed),
            limits(1, f.changed.len()),
        )?,
        "destroy" => f.peer()?.destroy_native_object(f.object()?)?,
        "use" => {
            mac(f)?;
        }
        _ => return Err(Failure::Input("object_action")),
    }
    Ok(())
}
fn mac(f: &Fixture) -> std::result::Result<NativeMac, Failure> {
    Ok(f.peer()?.compute_native_mac(
        f.object()?,
        NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
        MessageRoute::Single,
        &[b"abc"],
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
        32,
        None,
    )?)
}
fn local<W: Write>(
    f: &mut Fixture,
    action: &str,
    reason: RejectionReason,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match raw(f, action) {
        Err(Failure::Product(error @ Error::Rejected(_))) if matches!(&error, Error::Rejected(actual) if *actual == reason) => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error),
        Ok(()) => Err(Failure::Oracle("object_expected_local_refusal")),
    }
}
fn native<W: Write>(
    f: &mut Fixture,
    action: &str,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let function = match action {
        "read" => "C_GetAttributeValue",
        "copy" => "C_CopyObject",
        "mutate" => "C_SetAttributeValue",
        "destroy" => "C_DestroyObject",
        "use" => "C_SignInit",
        _ => return Err(Failure::Input("object_native_action")),
    };
    let expected = if action == "use" {
        fe11_sys::CKR_KEY_HANDLE_INVALID
    } else {
        fe11_sys::CKR_OBJECT_HANDLE_INVALID
    } as u64;
    match raw(f, action) {
        Err(Failure::Product(error @ Error::Native { .. })) if matches!(&error, Error::Native { function: actual, code, .. } if *actual == function && *code == expected) => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error),
        Ok(()) => Err(Failure::Oracle("object_expected_native_refusal")),
    }
}
pub fn execute<W: Write>(
    f: &mut Fixture,
    module: &Module,
    case: &Case,
    pins: &Credentials,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let reason = if case.state == "RUNTIME_RETIRED" {
        Some(RejectionReason::ModuleLifecycle(
            ModuleLifecycleRejection::ModuleClosed,
        ))
    } else if case.action != "search" && case.state == "DESTROYED" {
        Some(RejectionReason::ObjectReferences(
            ObjectReferencesRejection::ForeignOrStaleNativeObject,
        ))
    } else if case.action != "search" && case.state == "CREATOR_CLOSED" && !case.token {
        Some(RejectionReason::ObjectCreation(
            ObjectCreationRejection::CreatingSessionClosed,
        ))
    } else {
        None
    };
    if let Some(reason) = reason {
        // The independent observer also verifies absence of native calls. The
        // public counter remains useful for active runtimes, without requiring
        // diagnostic access to a module that has already been closed.
        let before = if f.module_closed {
            None
        } else {
            Some(module.call_counts()?)
        };
        local(f, &case.action, reason, report)?;
        if let Some(before) = before {
            if module.call_counts()? != before {
                return Err(Failure::Oracle("object_local_refusal_dispatched"));
            }
        }
        return Ok(());
    }
    let hidden = case.private && matches!(case.state.as_str(), "LOGGED_OUT" | "PERSISTENT_HIDDEN");
    if hidden && case.action != "search" {
        return native(f, &case.action, report);
    }
    match case.action.as_str() {
        "search" => {
            let expected = usize::from(
                !(hidden
                    || case.state == "DESTROYED"
                    || (case.state == "CREATOR_CLOSED" && !case.token)),
            );
            let found = find(f.peer()?, &f.label)?;
            if found.len() != expected {
                return Err(Failure::Oracle("object_search_cardinality"));
            }
            if let Some(object) = found.first() {
                check(&read(f.peer()?, object, &f.label)?, &f.label)?;
            }
            if hidden {
                f.login(pins)?;
                let found = find(f.peer()?, &f.label)?;
                if found.len() != usize::from(case.token) {
                    return Err(Failure::Oracle("object_relogin_visibility"));
                }
                if let Some(object) = found.first() {
                    check(&read(f.peer()?, object, &f.label)?, &f.label)?;
                }
            }
        }
        "read" => check(&read(f.peer()?, f.object()?, &f.label)?, &f.label)?,
        "copy" => {
            raw(f, "copy")?;
            let copy = f
                .copied
                .as_ref()
                .ok_or(Failure::Input("object_copy_reference"))?;
            check(&read(f.peer()?, copy, &f.copy_label)?, &f.copy_label)?;
            check(&read(f.peer()?, f.object()?, &f.label)?, &f.label)?;
            if find(f.peer()?, &f.copy_label)?.len() != 1 || find(f.peer()?, &f.label)?.len() != 1 {
                return Err(Failure::Oracle("object_copy_independence"));
            }
        }
        "mutate" => {
            raw(f, "mutate")?;
            // A successful mutation retires the old descriptive identity. Its
            // refusal is not a native failure; observe the changed object using
            // a new search result, without renewing the old reference.
            let before = module.call_counts()?;
            local(
                f,
                "read",
                RejectionReason::ObjectReferences(
                    ObjectReferencesRejection::ForeignOrStaleNativeObject,
                ),
                report,
            )?;
            if module.call_counts()? != before {
                return Err(Failure::Oracle("object_mutated_alias_dispatched"));
            }
            if !find(f.peer()?, &f.label)?.is_empty() {
                return Err(Failure::Oracle("object_mutated_search"));
            }
            let changed = find(f.peer()?, &f.changed)?;
            if changed.len() != 1 {
                return Err(Failure::Oracle("object_mutated_search"));
            }
            check(&read(f.peer()?, &changed[0], &f.changed)?, &f.changed)?;
        }
        "destroy" => {
            raw(f, "destroy")?;
            if !find(f.peer()?, &f.label)?.is_empty() {
                return Err(Failure::Oracle("object_destroy_search"));
            }
            let before = module.call_counts()?;
            local(
                f,
                "read",
                RejectionReason::ObjectReferences(
                    ObjectReferencesRejection::ForeignOrStaleNativeObject,
                ),
                report,
            )?;
            if module.call_counts()? != before {
                return Err(Failure::Oracle("object_destroyed_read_dispatched"));
            }
        }
        "use" => {
            if mac(f)?.as_bytes() != case.expected_mac {
                return Err(Failure::Oracle("object_mac_bytes"));
            }
        }
        _ => return Err(Failure::Input("object_action")),
    }
    Ok(())
}
