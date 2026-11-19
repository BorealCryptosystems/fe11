// SPDX-License-Identifier: Apache-2.0
//! Generated-key protection and the normative secret-attribute read rule.
use super::super::{
    generation_fixture::{Field, Value},
    outcome::Failure,
};
use fe11::*;

fn requested(fields: &[Field], attribute: StandardAttribute) -> std::result::Result<bool, Failure> {
    match fields
        .iter()
        .find(|field| field.attribute == attribute)
        .map(|field| &field.value)
    {
        Some(Value::Boolean(value)) => Ok(*value),
        _ => Err(Failure::Input("generated_protection_boolean")),
    }
}

pub(super) fn check(
    session: &Session,
    object: &NativeObjectRef,
    fields: &[Field],
) -> std::result::Result<(), Failure> {
    // The common generation observer has already compared every requested
    // Boolean and both history attributes. This check adds the native read
    // consequence, not a policy enforced locally by the test or library.
    let sensitive = requested(fields, StandardAttribute::SENSITIVE)?;
    let extractable = requested(fields, StandardAttribute::EXTRACTABLE)?;
    let rsa = fields.iter().any(|field| {
        field.attribute == StandardAttribute::KEY_TYPE
            && matches!(field.value, Value::Unsigned(value) if value == fe11_sys::CKK_RSA as u64)
    });
    let attribute = if rsa {
        StandardAttribute::PRIVATE_EXPONENT
    } else {
        StandardAttribute::VALUE
    };
    let observation = session.read_flat_attribute(
        object,
        attribute,
        FlatAttributeReadPlan::Buffer { capacity: 16384 },
    )?;
    if sensitive || !extractable {
        if observation.calls
            != (AttributeReadCalls::Direct {
                code: fe11_sys::CKR_ATTRIBUTE_SENSITIVE as u64,
            })
            || !matches!(
                observation.value,
                FlatAttributeValue::Unavailable(AttributeUnavailableCause::Sensitive)
            )
        {
            return Err(Failure::Oracle("generated_secret_read_not_denied"));
        }
    } else {
        if observation.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("generated_exportable_read_status"));
        }
        match observation.value {
            FlatAttributeValue::Available(value) if !value.as_bytes().is_empty() => (),
            _ => return Err(Failure::Oracle("generated_exportable_read_value")),
        }
    }
    Ok(())
}
