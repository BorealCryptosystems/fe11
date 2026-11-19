// SPDX-License-Identifier: Apache-2.0
//! Read back the requested unwrapped object contract and its native origin.
use super::super::{key_wrap_fixture, object_owner::Owner, outcome::Failure};
use fe11::*;

pub(super) fn check(owner: &Owner, key: &NativeObjectRef) -> std::result::Result<(), Failure> {
    let mut fields = Vec::from(key_wrap_fixture::template());
    // Unwrapping imports material: these history attributes are set by the
    // module, independently of the caller's requested sensitivity settings.
    for attribute in [
        StandardAttribute::LOCAL,
        StandardAttribute::ALWAYS_SENSITIVE,
        StandardAttribute::NEVER_EXTRACTABLE,
    ] {
        fields.push(AttributeInput {
            attribute: attribute.into(),
            value: AttributeInputValue::Boolean(false),
        });
    }
    for field in fields {
        let attribute = StandardAttribute::from_identifier(field.attribute.identifier())
            .ok_or(Failure::Input("unwrap_attribute_identifier"))?;
        let plan = FlatAttributeReadPlan::Buffer { capacity: 8 };
        let observation = match owner {
            Owner::Session(session) => session.read_flat_attribute(key, attribute, plan),
            Owner::Advanced(session) => session.read_flat_attribute(key, attribute, plan),
        }?;
        if observation.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("unwrapped_attribute_native_code"));
        }
        let matches = match field.value {
            AttributeInputValue::Unsigned(expected) => observation.unsigned()? == expected,
            AttributeInputValue::Boolean(expected) => observation.boolean()? == expected,
            _ => return Err(Failure::Input("unwrap_attribute_representation")),
        };
        if !matches {
            return Err(Failure::Oracle("unwrapped_attribute_contract"));
        }
    }
    Ok(())
}
