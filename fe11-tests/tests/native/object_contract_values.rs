// SPDX-License-Identifier: Apache-2.0
//! Exact data values, copy independence and imported-key history attributes.
use super::{
    attr, limits, outcome, template, Failure, Observation, Phase, Producer, Report, VALUE,
};
use fe11::*;
use std::io::Write;

pub(super) const ACTIONS: &[&str] = &[
    "data-session-public",
    "data-session-private",
    "data-token-public",
    "data-token-private",
    "data-empty-session-public",
    "data-empty-session-private",
    "data-empty-token-public",
    "data-empty-token-private",
    "data-value-read-only",
    "copy-token",
    "import-copy-history",
    "date-fields",
    "missing-class",
    "missing-key-type",
    "missing-value",
];

fn read(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    capacity: usize,
) -> std::result::Result<FlatAttributeObservation, Failure> {
    let value = session.read_flat_attribute(
        object,
        attribute,
        FlatAttributeReadPlan::Buffer { capacity },
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("object_field_native_code"));
    }
    Ok(value)
}

fn bytes(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    expected: &[u8],
) -> std::result::Result<(), Failure> {
    match read(session, object, attribute, expected.len())?.value {
        FlatAttributeValue::Available(value) if value.as_bytes() == expected => Ok(()),
        _ => Err(Failure::Oracle("object_field_bytes")),
    }
}

fn boolean(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    expected: bool,
) -> std::result::Result<(), Failure> {
    if read(session, object, attribute, 1)?.boolean()? != expected {
        return Err(Failure::Oracle("object_field_boolean"));
    }
    Ok(())
}

fn unsigned(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    expected: u64,
) -> std::result::Result<(), Failure> {
    if read(
        session,
        object,
        attribute,
        std::mem::size_of::<fe11_sys::CK_ULONG>(),
    )?
    .unsigned()?
        != expected
    {
        return Err(Failure::Oracle("object_field_unsigned"));
    }
    Ok(())
}

fn mac(
    session: &Session,
    object: &NativeObjectRef,
    expected: &[u8],
) -> std::result::Result<(), Failure> {
    // HMAC-MD5 accepts the fixed 16-byte public fixture key. This checks exact
    // object continuity, not an application's choice of security strength.
    let value = session.compute_native_mac(
        object,
        NativeMacParameters::Full(NativeMacAlgorithm::MD5_HMAC),
        MessageRoute::Single,
        &[b"abc"],
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
        16,
        None,
    )?;
    if value.as_bytes() != expected {
        return Err(Failure::Oracle("copied_object_independent_mac"));
    }
    Ok(())
}

pub(super) fn execute<W: Write>(
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    action: &str,
    expected_mac: &[u8],
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if action.starts_with("data-") {
        let token = action.contains("-token-");
        let private = action.ends_with("-private");
        let empty = action.starts_with("data-empty-");
        let value: &[u8] = if empty { &[] } else { VALUE };
        let application: &[u8] = if empty { &[] } else { b"application\0\xc3\xa9" };
        let fields = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(token),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(private),
            ),
            attr(
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(super::LABEL),
            ),
            attr(
                StandardAttribute::APPLICATION,
                AttributeInputValue::Bytes(application),
            ),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(value)),
            attr(
                StandardAttribute::MODIFIABLE,
                AttributeInputValue::Boolean(true),
            ),
        ];
        objects.push(session.create_native_object(&fields, limits(fields.len()))?);
        unsigned(
            session,
            &objects[0],
            StandardAttribute::CLASS,
            fe11_sys::CKO_DATA as u64,
        )?;
        boolean(session, &objects[0], StandardAttribute::TOKEN, token)?;
        boolean(session, &objects[0], StandardAttribute::PRIVATE, private)?;
        bytes(
            session,
            &objects[0],
            StandardAttribute::APPLICATION,
            application,
        )?;
        bytes(session, &objects[0], StandardAttribute::VALUE, value)?;
        if action == "data-value-read-only" {
            let changed = b"changed\0\xfe";
            let mutation = session.set_native_attributes(
                &objects[0],
                &[attr(
                    StandardAttribute::VALUE,
                    AttributeInputValue::Bytes(changed),
                )],
                limits(1),
            );
            // A possibly partial mutation retires the old observation even on
            // native refusal. Refresh before examining its result so cleanup
            // never depends on the outcome of the assertion below.
            // Refresh only
            // this exclusively owned object's label; no new object is adopted
            // from an unrelated namespace for deletion.
            let mut found = super::super::object_transition_fixture::find(session, super::LABEL)?;
            if found.len() != 1 {
                return Err(Failure::Oracle("mutated_data_exact_population"));
            }
            objects[0] = found.pop().ok_or(Failure::Oracle("mutated_data_absent"))?;
            match mutation {
                Err(
                    error @ Error::Native {
                        function: "C_SetAttributeValue",
                        code,
                        ..
                    },
                ) if code == fe11_sys::CKR_ATTRIBUTE_READ_ONLY as u64 => {
                    outcome::record(report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                }
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(Failure::Oracle("data_value_not_read_only")),
            }
            bytes(session, &objects[0], StandardAttribute::VALUE, value)?;
            bytes(session, &objects[0], StandardAttribute::LABEL, super::LABEL)?;
            bytes(
                session,
                &objects[0],
                StandardAttribute::APPLICATION,
                application,
            )?;
            unsigned(
                session,
                &objects[0],
                StandardAttribute::CLASS,
                fe11_sys::CKO_DATA as u64,
            )?;
        }
        return Ok(());
    }
    let mut fields = template(action);
    if action.starts_with("missing-") {
        let missing = match action {
            "missing-class" => StandardAttribute::CLASS,
            "missing-key-type" => StandardAttribute::KEY_TYPE,
            "missing-value" => StandardAttribute::VALUE,
            _ => return Err(Failure::Input("missing_attribute_action")),
        };
        fields.retain(|field| field.attribute != missing);
        return match session.create_native_object(&fields, limits(fields.len())) {
            Err(
                error @ Error::Native {
                    function: "C_CreateObject",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_TEMPLATE_INCOMPLETE as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))
            }
            Err(error) => Err(error.into()),
            Ok(object) => {
                objects.push(object);
                Err(Failure::Oracle("required_attribute_not_rejected"))
            }
        };
    }
    if action == "date-fields" {
        fields.extend([
            attr(
                StandardAttribute::START_DATE,
                AttributeInputValue::Date(*b"20260101"),
            ),
            attr(
                StandardAttribute::END_DATE,
                AttributeInputValue::Date(*b"20271231"),
            ),
        ]);
    }
    objects.push(session.create_native_object(&fields, limits(fields.len()))?);
    match action {
        "copy-token" => {
            let copied = session.copy_native_object(
                &objects[0],
                &[attr(
                    StandardAttribute::TOKEN,
                    AttributeInputValue::Boolean(true),
                )],
                limits(1),
            )?;
            objects.push(copied);
            for (object, token) in objects.iter().zip([false, true]) {
                boolean(session, object, StandardAttribute::TOKEN, token)?;
                boolean(session, object, StandardAttribute::PRIVATE, false)?;
                unsigned(
                    session,
                    object,
                    StandardAttribute::CLASS,
                    fe11_sys::CKO_SECRET_KEY as u64,
                )?;
                unsigned(
                    session,
                    object,
                    StandardAttribute::KEY_TYPE,
                    fe11_sys::CKK_GENERIC_SECRET as u64,
                )?;
                bytes(session, object, StandardAttribute::LABEL, super::LABEL)?;
                bytes(session, object, StandardAttribute::VALUE, VALUE)?;
                mac(session, object, expected_mac)?;
            }
        }
        "import-copy-history" => {
            let changes = [
                attr(
                    StandardAttribute::SENSITIVE,
                    AttributeInputValue::Boolean(true),
                ),
                attr(
                    StandardAttribute::EXTRACTABLE,
                    AttributeInputValue::Boolean(false),
                ),
            ];
            let copied =
                session.copy_native_object(&objects[0], &changes, limits(changes.len()))?;
            objects.push(copied);
            for (object, sensitive) in objects.iter().zip([false, true]) {
                for attribute in [
                    StandardAttribute::LOCAL,
                    StandardAttribute::ALWAYS_SENSITIVE,
                    StandardAttribute::NEVER_EXTRACTABLE,
                ] {
                    boolean(session, object, attribute, false)?;
                }
                boolean(session, object, StandardAttribute::SENSITIVE, sensitive)?;
                boolean(session, object, StandardAttribute::EXTRACTABLE, !sensitive)?;
                mac(session, object, expected_mac)?;
            }
        }
        "date-fields" => {
            for (attribute, expected) in [
                (StandardAttribute::START_DATE, *b"20260101"),
                (StandardAttribute::END_DATE, *b"20271231"),
            ] {
                if read(session, &objects[0], attribute, 8)?.date()? != expected {
                    return Err(Failure::Oracle("object_date_exact_bytes"));
                }
            }
        }
        _ => return Err(Failure::Input("object_value_action")),
    }
    report
        .observation(
            Phase::Body,
            "object_value_contract",
            Producer::TestOracle,
            Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("report_write"))
}
