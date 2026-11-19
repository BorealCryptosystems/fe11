// SPDX-License-Identifier: Apache-2.0
//! Read caller-selected metadata and distinguish observations from dispatches.
use super::{configuration::Budgets, outcome::Failure};
use fe11::*;

fn rejected<T>(value: Result<T>, expected: RejectionReason) -> std::result::Result<bool, Failure> {
    match value {
        Err(Error::Rejected(actual)) if actual == expected => Ok(true),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("declaration_refusal_missing")),
    }
}

pub fn check(module: &Module, action: &str) -> std::result::Result<(), Failure> {
    let mut expected_calls = module.call_counts()?;
    let budgets = Budgets::ordinary();
    let expected_sessions = SessionLimit {
        total: budgets.sessions,
        read_write: budgets.sessions,
    };
    let matches = match action {
        "metadata_counts" => {
            module.library_info()?;
            let count = expected_calls.entry("C_GetInfo").or_default();
            *count = count
                .checked_add(1)
                .ok_or(Failure::Input("counter_overflow"))?;
            true
        }
        "metadata_objects" => {
            let value = module.object_limits();
            value.object_references.is_none()
                && value.managed_references.is_none()
                && value.destination_reservations.is_none()
        }
        "metadata_resources" => {
            // These are the caller's discovery/session allowances, not the
            // separate symmetric buffer budget or a native allocation count.
            let value = module.resource_limits();
            value.slots == budgets.slots
                && value.mechanisms == budgets.mechanisms
                && value.discovery_attempts == budgets.discovery_attempts
                && value.sessions == budgets.sessions
        }
        "metadata_sessions" => module.session_limits() == expected_sessions,
        "metadata_policy" => {
            let value = module.session_policy();
            value.module_read_write == budgets.sessions
                && value.default_token == expected_sessions
                && value.tokens.is_empty()
                && value.announced_limits == AnnouncedSessionLimits::Ignore
        }
        "standard_attribute_declaration" => {
            // SAFETY: CKA_LABEL is a standard flat byte string. This declaration
            // uses that exact ABI; no extension object is used for a native call.
            let result = unsafe {
                module
                    .declare_attribute_extension(fe11_sys::CKA_LABEL as u64, AttributeLayout::Bytes)
            };
            rejected(
                result,
                RejectionReason::AttributeValues(
                    AttributeValuesRejection::StandardAttributeLayoutCannotBeOverridden,
                ),
            )?
        }
        "digest_key_declaration" => {
            // SAFETY: CKM_SHA256 is the standard parameterless digest ABI on
            // either selected interface. The conservative mutation flag cannot
            // introduce a pointer or native call; no request uses this contract.
            let result = unsafe {
                module.declare_mechanism_extension(
                    fe11_sys::CKM_SHA256 as u64,
                    (3, 2),
                    ExtensionOperation::Digest,
                    true,
                )
            };
            rejected(
                result,
                RejectionReason::MechanismExtensions(
                    MechanismExtensionsRejection::DigestExtensionHasNoKey,
                ),
            )?
        }
        _ => return Err(Failure::Input("metadata_action")),
    };
    if !matches {
        return Err(Failure::Oracle("metadata_contract"));
    }
    if module.call_counts()? != expected_calls {
        return Err(Failure::Oracle("metadata_dispatch_count"));
    }
    Ok(())
}
