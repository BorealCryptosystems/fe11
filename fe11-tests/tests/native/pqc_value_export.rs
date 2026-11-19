// SPDX-License-Identifier: Apache-2.0
//! Explicit private VALUE reads use published test keys and native permissions.
use super::super::{
    object_owner::Owner,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::io::Write;

pub(super) fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    expected: &[u8],
    sensitive: bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let read = |attribute, capacity| match owner {
        Owner::Session(session) => {
            session.read_flat_attribute(key, attribute, FlatAttributeReadPlan::Buffer { capacity })
        }
        Owner::Advanced(session) => {
            session.read_flat_attribute(key, attribute, FlatAttributeReadPlan::Buffer { capacity })
        }
    };
    for (attribute, expected) in [
        (StandardAttribute::SENSITIVE, sensitive),
        (StandardAttribute::EXTRACTABLE, true),
    ] {
        let value = read(attribute, 1)?;
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) || value.boolean()? != expected {
            return Err(Failure::Oracle("private_export_permission_readback"));
        }
    }
    // One bounded value call: no size query, representation fallback or retry.
    let value = read(StandardAttribute::VALUE, expected.len())?;
    let code = if sensitive {
        fe11_sys::CKR_ATTRIBUTE_SENSITIVE as u64
    } else {
        0
    };
    if value.calls != (AttributeReadCalls::Direct { code }) {
        return Err(Failure::Oracle("private_export_native_status"));
    }
    report
        .observation(
            Phase::Body,
            "private_export_native_code",
            Producer::Native,
            Observation::Number(code),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    match value.value {
        FlatAttributeValue::Available(bytes) if !sensitive && bytes.as_bytes() == expected => {
            Ok(())
        }
        FlatAttributeValue::Unavailable(AttributeUnavailableCause::Sensitive) if sensitive => {
            Ok(())
        }
        _ => Err(Failure::Oracle("private_export_exact_value_or_sensitive")),
    }
}
