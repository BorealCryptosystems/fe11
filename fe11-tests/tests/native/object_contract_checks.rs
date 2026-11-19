// SPDX-License-Identifier: Apache-2.0
//! Keep exact native diagnostics separate from unavailable attribute contents.
use super::super::{
    outcome,
    report::{Phase, Report},
};
use super::{attr, limits, Failure, LABEL, VALUE};
use fe11::*;
use std::io::Write;

fn read(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    capacity: usize,
) -> Result<FlatAttributeObservation> {
    session.read_flat_attribute(
        object,
        attribute,
        FlatAttributeReadPlan::Buffer { capacity },
    )
}
fn bytes(value: &FlatAttributeObservation, expected: &[u8]) -> std::result::Result<(), Failure> {
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("attribute_native_success_code"));
    }
    match &value.value {
        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected => Ok(()),
        _ => Err(Failure::Oracle("attribute_exact_bytes")),
    }
}
fn unsigned(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    expected: u64,
) -> std::result::Result<(), Failure> {
    let value = read(
        session,
        object,
        attribute,
        std::mem::size_of::<fe11_sys::CK_ULONG>(),
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) || value.unsigned()? != expected {
        return Err(Failure::Oracle("attribute_exact_unsigned"));
    }
    Ok(())
}
fn refused<T, W: Write>(
    value: Result<T>,
    function: &'static str,
    expected: u64,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match value {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function && code == expected => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("expected_native_object_refusal")),
    }
}
fn mac(
    session: &Session,
    object: &NativeObjectRef,
    algorithm: NativeMacAlgorithm,
) -> Result<NativeMac> {
    session.compute_native_mac(
        object,
        NativeMacParameters::Full(algorithm),
        MessageRoute::Single,
        &[b"abc"],
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
        32,
        None,
    )
}
fn batch(
    session: &Session,
    object: &NativeObjectRef,
    mixed: bool,
) -> std::result::Result<(), Failure> {
    let request = |attribute: StandardAttribute, capacity| FlatAttributeRequest {
        attribute: attribute.into(),
        plan: FlatAttributeReadPlan::Buffer { capacity },
    };
    let mut requests = vec![request(
        StandardAttribute::LABEL,
        if mixed { LABEL.len() } else { 0 },
    )];
    if mixed {
        requests.push(request(StandardAttribute::VALUE, VALUE.len()));
    }
    requests.push(request(StandardAttribute::APPLICATION, 8));
    let result = session.read_flat_attributes(object, &requests, 64)?;
    match result.calls() {
        AttributeBatchCalls::One(call)
            if call.attribute_count == requests.len()
                && (call.code == fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID as u64
                    || (mixed && call.code == fe11_sys::CKR_ATTRIBUTE_SENSITIVE as u64)) =>
        {
            ()
        }
        _ => return Err(Failure::Oracle("attribute_mixed_native_code_and_count")),
    }
    if result.len() != requests.len() {
        return Err(Failure::Oracle("attribute_mixed_count"));
    }
    let mut entries = result.iter();
    let first = entries
        .next()
        .ok_or(Failure::Oracle("attribute_mixed_label_absent"))?;
    // A batch error applies to the entire call, not to the valid label. Its
    // bytes stay available even though the aggregate code is not CKR_OK.
    match &first.value {
        FlatAttributeValue::Available(bytes)
            if bytes.as_bytes() == if mixed { LABEL } else { &[] } =>
        {
            ()
        }
        _ => return Err(Failure::Oracle("attribute_mixed_label_bytes")),
    }
    for entry in entries {
        if !matches!(
            entry.value,
            FlatAttributeValue::Unavailable(AttributeUnavailableCause::Unspecified)
        ) {
            return Err(Failure::Oracle("attribute_mixed_unavailable_cause"));
        }
    }
    Ok(())
}

fn refresh(
    session: &Session,
    objects: &mut [NativeObjectRef],
    label: &[u8],
) -> std::result::Result<(), Failure> {
    // A nonempty attribute mutation retires the old view even when the module
    // reports a possibly partial refusal. Search only the one isolated object;
    // a fresh reference is required for readback and explicit destruction.
    let mut found = super::super::object_transition_fixture::find(session, label)?;
    if found.len() != 1 || objects.len() != 1 {
        return Err(Failure::Oracle("object_mutation_exact_refresh"));
    }
    objects[0] = found
        .pop()
        .ok_or(Failure::Oracle("object_mutation_refresh_absent"))?;
    Ok(())
}

pub(super) fn execute<W: Write>(
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    action: &str,
    expected_mac: &[u8],
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let object = objects
        .first()
        .ok_or(Failure::Input("object_contract_reference"))?;
    match action {
        "length-only" => {
            let value = session.read_flat_attribute(
                object,
                StandardAttribute::VALUE,
                FlatAttributeReadPlan::LengthOnly,
            )?;
            if value.calls != (AttributeReadCalls::Size { code: 0 })
                || !matches!(value.value, FlatAttributeValue::SizeKnown { required: 16 })
            {
                return Err(Failure::Oracle("attribute_length_without_value"));
            }
        }
        "allocation-limits" => {
            for maximum_bytes in [3, 4, 5] {
                let value = session.read_flat_attribute(
                    object,
                    StandardAttribute::LABEL,
                    FlatAttributeReadPlan::Value { maximum_bytes },
                )?;
                if maximum_bytes == 3 {
                    if value.calls != (AttributeReadCalls::Size { code: 0 })
                        || !matches!(
                            value.value,
                            FlatAttributeValue::AllocationLimit {
                                required: 4,
                                maximum_bytes: 3
                            }
                        )
                    {
                        return Err(Failure::Oracle(
                            "attribute_query_preserves_allocation_limit",
                        ));
                    }
                } else {
                    if value.calls
                        != (AttributeReadCalls::Value {
                            size_code: 0,
                            code: 0,
                        })
                    {
                        return Err(Failure::Oracle("attribute_explicit_bounded_read_calls"));
                    }
                    match &value.value {
                        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == LABEL => {}
                        _ => return Err(Failure::Oracle("attribute_bounded_exact_bytes")),
                    }
                }
            }
        }
        "empty" => {
            bytes(&read(session, object, StandardAttribute::LABEL, 0)?, &[])?;
            bytes(&read(session, object, StandardAttribute::VALUE, 0)?, &[])?;
        }
        "short" => {
            let value = read(session, object, StandardAttribute::VALUE, 15)?;
            if value.calls
                != (AttributeReadCalls::Direct {
                    code: fe11_sys::CKR_BUFFER_TOO_SMALL as u64,
                })
                || !matches!(
                    value.value,
                    FlatAttributeValue::BufferTooSmall {
                        supplied: 15,
                        required: None
                    }
                )
            {
                return Err(Failure::Oracle(
                    "attribute_short_buffer_and_native_sentinel",
                ));
            }
        }
        "oversized" => bytes(&read(session, object, StandardAttribute::VALUE, 17)?, VALUE)?,
        "sensitive" | "unknown" => {
            let sensitive = action == "sensitive";
            let value = read(
                session,
                object,
                if sensitive {
                    StandardAttribute::VALUE
                } else {
                    StandardAttribute::APPLICATION
                },
                16,
            )?;
            let code = if sensitive {
                fe11_sys::CKR_ATTRIBUTE_SENSITIVE
            } else {
                fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID
            } as u64;
            let cause = if sensitive {
                AttributeUnavailableCause::Sensitive
            } else {
                AttributeUnavailableCause::Unsupported
            };
            if value.calls != (AttributeReadCalls::Direct { code })
                || !matches!(value.value, FlatAttributeValue::Unavailable(actual) if actual == cause)
            {
                return Err(Failure::Oracle("attribute_unavailable_exact_cause"));
            }
        }
        "mixed" | "unavailable" => batch(session, object, action == "mixed")?,
        "order" => {
            for key in objects.iter() {
                unsigned(
                    session,
                    key,
                    StandardAttribute::CLASS,
                    fe11_sys::CKO_SECRET_KEY as u64,
                )?;
                unsigned(
                    session,
                    key,
                    StandardAttribute::KEY_TYPE,
                    fe11_sys::CKK_GENERIC_SECRET as u64,
                )?;
                bytes(
                    &read(session, key, StandardAttribute::LABEL, LABEL.len())?,
                    LABEL,
                )?;
                bytes(
                    &read(session, key, StandardAttribute::VALUE, VALUE.len())?,
                    VALUE,
                )?;
                // HMAC-MD5 admits the fixed 16-byte template value. This is a
                // deterministic equality witness, not a recommended application
                // algorithm or a security-strength assertion.
                if mac(session, key, NativeMacAlgorithm::MD5_HMAC)?.as_bytes() != expected_mac {
                    return Err(Failure::Oracle("template_order_hmac_value"));
                }
            }
        }
        "copy-refusal" => {
            let result = session.copy_native_object(object, &[], limits(0));
            if let Ok(created) = result {
                objects.push(created);
                return Err(Failure::Oracle("noncopyable_object_copied"));
            }
            refused(
                result,
                "C_CopyObject",
                fe11_sys::CKR_ACTION_PROHIBITED as u64,
                report,
            )?;
            bytes(
                &read(session, object, StandardAttribute::VALUE, VALUE.len())?,
                VALUE,
            )?;
        }
        "read-only" => {
            for (attribute, changed, original) in [
                (
                    StandardAttribute::CLASS,
                    fe11_sys::CKO_DATA,
                    fe11_sys::CKO_SECRET_KEY,
                ),
                (
                    StandardAttribute::KEY_TYPE,
                    fe11_sys::CKK_AES,
                    fe11_sys::CKK_GENERIC_SECRET,
                ),
            ] {
                refused(
                    session.set_native_attributes(
                        &objects[0],
                        &[attr(
                            attribute,
                            AttributeInputValue::Unsigned(changed as u64),
                        )],
                        limits(1),
                    ),
                    "C_SetAttributeValue",
                    fe11_sys::CKR_ATTRIBUTE_READ_ONLY as u64,
                    report,
                )?;
                refresh(session, objects, LABEL)?;
                unsigned(session, &objects[0], attribute, original as u64)?;
            }
        }
        "size" => {
            // The pinned recipe reports the native all-ones value. Preserve it;
            // it is neither the key size nor a locally invented DER length.
            let expected = fe11_sys::CK_UNAVAILABLE_INFORMATION as u64;
            if session.managed_object_size(object)? != expected {
                return Err(Failure::Oracle("object_size_native_value"));
            }
            session.set_native_attributes(
                object,
                &[attr(
                    StandardAttribute::LABEL,
                    AttributeInputValue::Bytes(b"changed"),
                )],
                limits(1),
            )?;
            refresh(session, objects, b"changed")?;
            if session.managed_object_size(&objects[0])? != expected {
                return Err(Failure::Oracle("object_size_after_mutation"));
            }
            bytes(
                &read(session, &objects[0], StandardAttribute::LABEL, 7)?,
                b"changed",
            )?;
        }
        "allowed" => {
            let value = read(
                session,
                object,
                StandardAttribute::ALLOWED_MECHANISMS,
                std::mem::size_of::<fe11_sys::CK_ULONG>(),
            )?;
            if value.calls != (AttributeReadCalls::Direct { code: 0 })
                || value.unsigned_values()?.collect::<Vec<_>>() != super::ALLOWED
            {
                return Err(Failure::Oracle("allowed_mechanisms_exact_readback"));
            }
            if mac(session, object, NativeMacAlgorithm::SHA256_HMAC)?.as_bytes() != expected_mac {
                return Err(Failure::Oracle("allowed_mechanism_hmac"));
            }
            refused(
                mac(session, object, NativeMacAlgorithm::SHA_1_HMAC),
                "C_SignInit",
                fe11_sys::CKR_MECHANISM_INVALID as u64,
                report,
            )?;
        }
        _ => return Err(Failure::Input("object_contract_action")),
    }
    Ok(())
}
