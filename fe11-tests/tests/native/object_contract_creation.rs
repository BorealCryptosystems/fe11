// SPDX-License-Identifier: Apache-2.0
//! Creation templates: identical duplicates, conflicts and unsupported classes.
//!
//! PKCS#11 section 4.1.1 distinguishes equal duplicate attributes (success or
//! TEMPLATE_INCONSISTENT) from conflicting values (TEMPLATE_INCONSISTENT).
//! A successful duplicate must retain the exact original attribute values.
use super::{
    attr, limits, outcome, template, Failure, Observation, Phase, Producer, Report, VALUE,
};
use fe11::*;
use std::io::Write;

pub(super) const ACTIONS: &[&str] = &[
    "creation-same-class",
    "creation-same-value",
    "creation-conflicting-class",
    "creation-conflicting-value",
    "creation-public-secret-type",
    "creation-secret-rsa-type",
    "creation-mechanism-class",
];
const OTHER_VALUE: &[u8] = &[
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

fn fields(action: &str) -> Vec<AttributeInput<'static>> {
    let mut fields = template("creation");
    match action {
        "creation-same-class" => fields.push(attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
        )),
        "creation-same-value" => fields.push(attr(
            StandardAttribute::VALUE,
            AttributeInputValue::Bytes(VALUE),
        )),
        "creation-conflicting-class" => fields.push(attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
        )),
        "creation-conflicting-value" => fields.push(attr(
            StandardAttribute::VALUE,
            AttributeInputValue::Bytes(OTHER_VALUE),
        )),
        "creation-public-secret-type" => {
            // Both integers are standard values, but generic-secret key type
            // cannot describe a public key. No attribute is duplicated here.
            fields[0].value = AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64);
        }
        "creation-secret-rsa-type" => {
            for field in &mut fields {
                if field.attribute == StandardAttribute::KEY_TYPE {
                    field.value = AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64);
                }
            }
        }
        "creation-mechanism-class" => {
            // Mechanism objects have no caller-settable MECHANISM_TYPE.
            // Submit only the common object attributes, never secret-key fields
            // or a write to that read-only attribute (section 4.12.2 / 4.13.2).
            fields = vec![
                attr(
                    StandardAttribute::CLASS,
                    AttributeInputValue::Unsigned(fe11_sys::CKO_MECHANISM as u64),
                ),
                attr(
                    StandardAttribute::TOKEN,
                    AttributeInputValue::Boolean(false),
                ),
                attr(
                    StandardAttribute::PRIVATE,
                    AttributeInputValue::Boolean(false),
                ),
                attr(
                    StandardAttribute::LABEL,
                    AttributeInputValue::Bytes(super::LABEL),
                ),
            ];
        }
        _ => unreachable!("fixture action validated before template construction"),
    }
    fields
}

fn readback(session: &Session, object: &NativeObjectRef) -> std::result::Result<(), Failure> {
    for (attribute, expected) in [
        (StandardAttribute::CLASS, fe11_sys::CKO_SECRET_KEY as u64),
        (
            StandardAttribute::KEY_TYPE,
            fe11_sys::CKK_GENERIC_SECRET as u64,
        ),
    ] {
        let value = session.read_flat_attribute(
            object,
            attribute,
            FlatAttributeReadPlan::Buffer {
                capacity: std::mem::size_of::<fe11_sys::CK_ULONG>(),
            },
        )?;
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) || value.unsigned()? != expected
        {
            return Err(Failure::Oracle("duplicate_attribute_identity"));
        }
    }
    let value = session.read_flat_attribute(
        object,
        StandardAttribute::VALUE,
        FlatAttributeReadPlan::Buffer {
            capacity: VALUE.len(),
        },
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("duplicate_attribute_read_code"));
    }
    match value.value {
        FlatAttributeValue::Available(bytes) if bytes.as_bytes() == VALUE => Ok(()),
        _ => Err(Failure::Oracle("duplicate_attribute_value")),
    }
}

pub(super) fn execute<W: Write>(
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    action: &str,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let fields = fields(action);
    let result = session.create_native_object(&fields, limits(fields.len()));
    let returned = result.is_ok();
    // Retain every returned reference before any reporting/readback can fail.
    let error = match result {
        Ok(object) => {
            objects.push(object);
            None
        }
        Err(error) => Some(error),
    };
    report
        .observation(
            Phase::Body,
            "creation_object_returned",
            Producer::Native,
            Observation::Boolean(returned),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    if let Some(error) = error {
        let accepted = matches!(&error, Error::Native { function: "C_CreateObject", code, .. }
            if *code == fe11_sys::CKR_TEMPLATE_INCONSISTENT as u64
                || (action == "creation-mechanism-class"
                    && *code == fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID as u64));
        if !accepted {
            return Err(error.into());
        }
        outcome::record(report, Phase::Body, &Failure::Product(error))
            .map_err(|_| Failure::Input("report_write"))?;
        return Ok(());
    }
    if !matches!(action, "creation-same-class" | "creation-same-value") {
        return Err(Failure::Oracle(
            "inconsistent_or_unsupported_object_created",
        ));
    }
    readback(
        session,
        objects
            .last()
            .ok_or(Failure::Input("created_object_reference"))?,
    )
}
