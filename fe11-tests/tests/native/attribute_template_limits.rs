// SPDX-License-Identifier: Apache-2.0
//! Input graph limits use the actual graph, including children and scalar ABI widths.
use super::{attr, template, Failure, LABEL};
use fe11::*;
use std::{mem::size_of, num::NonZeroUsize};

fn limits(depth: usize, count: usize, bytes: usize) -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: depth,
        maximum_attributes: count,
        maximum_value_bytes: bytes,
    }
}
fn rejected(
    module: &Module,
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    fields: &[AttributeInput<'_>],
    bound: AttributeTemplateLimits,
    reason: AttributeValuesRejection,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    match session.create_native_object(fields, bound) {
        Err(Error::Rejected(RejectionReason::AttributeValues(actual))) if actual == reason => (),
        Err(error) => return Err(error.into()),
        Ok(object) => {
            objects.push(object);
            return Err(Failure::Oracle("input_limit_accepted"));
        }
    }
    if before != module.call_counts()? {
        return Err(Failure::Oracle("input_limit_dispatched"));
    }
    Ok(())
}
fn bytes(fields: &[AttributeInput<'_>]) -> usize {
    fields
        .iter()
        .map(|f| match &f.value {
            AttributeInputValue::Boolean(_) => 1,
            AttributeInputValue::Unsigned(_) => size_of::<fe11_sys::CK_ULONG>(),
            AttributeInputValue::Bytes(v) => v.len(),
            AttributeInputValue::Template(v) => bytes(v),
            _ => unreachable!(
                "this fixture contains Boolean, unsigned, byte and template values only"
            ),
        })
        .sum()
}

pub(super) fn check(
    module: &Module,
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    nested: bool,
) -> std::result::Result<(), Failure> {
    // Zero limits encode a genuinely empty search graph. The fresh disposable
    // token has no object; no malformed pointer or oversized slice is fabricated.
    let mut search =
        session.iter_native_objects(&[], limits(0, 0, 0), NonZeroUsize::new(1).unwrap())?;
    if search.next().transpose()?.is_some() {
        return Err(Failure::Oracle("empty_template_fresh_store"));
    }
    search.finish()?;
    let children = [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attr(StandardAttribute::LABEL, AttributeInputValue::Bytes(LABEL)),
    ];
    let mut fields = template("input-limits");
    if nested {
        fields.push(AttributeInput {
            attribute: StandardAttribute::WRAP_TEMPLATE.into(),
            value: AttributeInputValue::Template(&children),
        });
    }
    let depth = usize::from(nested);
    let count = fields.len() + if nested { children.len() } else { 0 };
    let value_bytes = bytes(&fields);
    // Each negative changes one limit only. No aggregate refusal can conceal
    // the intended count, depth or byte boundary.
    for count_limit in [0, count - 1] {
        rejected(
            module,
            session,
            objects,
            &fields,
            limits(depth, count_limit, value_bytes),
            AttributeValuesRejection::AttributeTemplateCountCeiling,
        )?;
    }
    for byte_limit in [0, value_bytes - 1] {
        rejected(
            module,
            session,
            objects,
            &fields,
            limits(depth, count, byte_limit),
            AttributeValuesRejection::AttributeTemplateValueCeiling,
        )?;
    }
    if nested {
        rejected(
            module,
            session,
            objects,
            &fields,
            limits(0, count, value_bytes),
            AttributeValuesRejection::AttributeTemplateDepthCeiling,
        )?;
    }
    for malformed in [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Bytes(&[0; 8]),
        ),
        attr(StandardAttribute::PRIVATE, AttributeInputValue::Unsigned(1)),
        attr(StandardAttribute::LABEL, AttributeInputValue::Boolean(true)),
        attr(
            StandardAttribute::START_DATE,
            AttributeInputValue::Bytes(b"20261118"),
        ),
        attr(
            StandardAttribute::WRAP_TEMPLATE,
            AttributeInputValue::Bytes(&[]),
        ),
        attr(StandardAttribute::CLASS, AttributeInputValue::Template(&[])),
    ] {
        rejected(
            module,
            session,
            objects,
            &[malformed],
            limits(1, 1, 32),
            AttributeValuesRejection::AttributeInputRepresentation,
        )?;
    }
    for bound in [
        limits(depth, count, value_bytes),
        limits(depth + 1, count + 1, value_bytes + 1),
        limits(usize::MAX, usize::MAX, usize::MAX),
    ] {
        let object = session.create_native_object(&fields, bound)?;
        objects.push(object);
        let object = objects.last().ok_or(Failure::Input("input_limit_owner"))?;
        let label = session.read_flat_attribute(
            object,
            StandardAttribute::LABEL,
            FlatAttributeReadPlan::Buffer {
                capacity: LABEL.len(),
            },
        )?;
        if label.calls != (AttributeReadCalls::Direct { code: 0 })
            || !matches!(&label.value,FlatAttributeValue::Available(v)if v.as_bytes()==LABEL)
        {
            return Err(Failure::Oracle("input_limit_valid_control"));
        }
        if nested {
            let value = session.read_template_attribute(
                object,
                StandardAttribute::WRAP_TEMPLATE,
                TemplateAttributeReadPlan::LengthOnly,
                limits(0, 1, 0),
            )?;
            if value.call().code != 0
                || !matches!(value.root().value(),TemplateAttributeValue::SizeKnown{required_bytes}if required_bytes==3*size_of::<fe11_sys::CK_ATTRIBUTE>())
            {
                return Err(Failure::Oracle("input_limit_nested_descriptor_length"));
            }
        }
    }
    Ok(())
}
