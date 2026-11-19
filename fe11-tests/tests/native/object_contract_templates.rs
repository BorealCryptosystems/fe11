// SPDX-License-Identifier: Apache-2.0
//! Nested attributes retain typed children; caller limits precede native access.
use super::{attr, template, Failure, Observation, Phase, Producer, Report, LABEL};
use fe11::*;
use std::io::Write;

fn local_refusal<T>(
    result: Result<T>,
    expected: AttributeValuesRejection,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::AttributeValues(actual))) if actual == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("template_local_limit_not_enforced")),
    }
}

fn limits(depth: usize, count: usize, bytes: usize) -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: depth,
        maximum_attributes: count,
        maximum_value_bytes: bytes,
    }
}

fn refused_creation(
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    fields: &[AttributeInput<'_>],
    bound: AttributeTemplateLimits,
    reason: AttributeValuesRejection,
) -> std::result::Result<(), Failure> {
    match session.create_native_object(fields, bound) {
        Ok(object) => {
            // A broken local guard must not also break ownership of cleanup.
            objects.push(object);
            Err(Failure::Oracle("template_creation_limit_not_enforced"))
        }
        Err(error) => local_refusal::<NativeObjectRef>(Err(error), reason),
    }
}

fn expected_length(identifier: u64) -> std::result::Result<usize, Failure> {
    match identifier {
        x if x == fe11_sys::CKA_CLASS as u64 => Ok(std::mem::size_of::<fe11_sys::CK_ULONG>()),
        x if x == fe11_sys::CKA_PRIVATE as u64 => Ok(1),
        x if x == fe11_sys::CKA_LABEL as u64 => Ok(LABEL.len()),
        _ => Err(Failure::Oracle("template_unexpected_child")),
    }
}

fn observed_values(
    tree: &TemplateAttributeTree,
    attribute: StandardAttribute,
) -> std::result::Result<(), Failure> {
    if tree.call().code != 0
        || tree.call().attribute_count != 1
        || tree.root().attribute_identifier() != attribute.identifier()
    {
        return Err(Failure::Oracle("template_native_call_and_root"));
    }
    let TemplateAttributeValue::Template(children) = tree.root().value() else {
        return Err(Failure::Oracle("template_children_unavailable"));
    };
    let mut identifiers = Vec::new();
    for child in children {
        let identifier = child.attribute_identifier();
        let TemplateAttributeValue::Flat(value) = child.value() else {
            return Err(Failure::Oracle("template_flat_child_unavailable"));
        };
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("template_child_native_code"));
        }
        match identifier {
            x if x == fe11_sys::CKA_CLASS as u64 => {
                if value.unsigned()? != fe11_sys::CKO_SECRET_KEY as u64 {
                    return Err(Failure::Oracle("template_class_value"));
                }
            }
            x if x == fe11_sys::CKA_PRIVATE as u64 => {
                if value.boolean()? {
                    return Err(Failure::Oracle("template_private_value"));
                }
            }
            x if x == fe11_sys::CKA_LABEL as u64 => match &value.value {
                FlatAttributeValue::Available(bytes) if bytes.as_bytes() == LABEL => {}
                _ => return Err(Failure::Oracle("template_binary_label_value")),
            },
            _ => return Err(Failure::Oracle("template_unexpected_child")),
        }
        identifiers.push(identifier);
    }
    identifiers.sort_unstable();
    if identifiers
        != [
            fe11_sys::CKA_CLASS as u64,
            fe11_sys::CKA_PRIVATE as u64,
            fe11_sys::CKA_LABEL as u64,
        ]
    {
        return Err(Failure::Oracle("template_exact_child_set"));
    }
    Ok(())
}

fn observe<W: Write>(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let query = session.read_template_attribute(
        object,
        attribute,
        TemplateAttributeReadPlan::LengthOnly,
        limits(0, 1, 0),
    )?;
    if query.call().code != 0
        || query.call().attribute_count != 1
        || query.root().attribute_identifier() != attribute.identifier()
        || !matches!(query.root().value(), TemplateAttributeValue::SizeKnown { required_bytes }
            if required_bytes == 3 * std::mem::size_of::<fe11_sys::CK_ATTRIBUTE>())
    {
        return Err(Failure::Oracle("template_exact_descriptor_length"));
    }
    drop(query);
    let discover = [TemplateAttributeSlot::Discover; 3];
    let tree = session.read_template_attribute(
        object,
        attribute,
        TemplateAttributeReadPlan::Slots(&discover),
        limits(1, 4, 0),
    )?;
    if tree.call().code != 0 {
        return Err(Failure::Oracle("template_discovery_native_code"));
    }
    let TemplateAttributeValue::Template(children) = tree.root().value() else {
        return Err(Failure::Oracle("template_discovery_children"));
    };
    let mut slots = Vec::new();
    for child in children {
        let identifier = child.attribute_identifier();
        let expected = expected_length(identifier)?;
        if !matches!(child.value(), TemplateAttributeValue::SizeKnown { required_bytes }
            if required_bytes == expected)
        {
            return Err(Failure::Oracle("template_discovery_exact_child_length"));
        }
        let kind = match identifier {
            x if x == fe11_sys::CKA_CLASS as u64 => StandardAttribute::CLASS,
            x if x == fe11_sys::CKA_PRIVATE as u64 => StandardAttribute::PRIVATE,
            _ => StandardAttribute::LABEL,
        };
        slots.push(TemplateAttributeSlot::Value {
            attribute: kind.into(),
            capacity: expected,
        });
    }
    if slots.len() != 3 {
        return Err(Failure::Oracle("template_discovery_count"));
    }
    drop(tree);
    let bytes = std::mem::size_of::<fe11_sys::CK_ULONG>() + 1 + LABEL.len();
    // The read plan includes its root descriptor; creation limits instead count
    // the full input template. Both count every child, not merely top-level slots.
    for (bound, reason) in [
        (
            limits(0, 4, bytes),
            AttributeValuesRejection::TemplateReadDepthLimit,
        ),
        (
            limits(1, 3, bytes),
            AttributeValuesRejection::TemplateReadDescriptorLimit,
        ),
        (
            limits(1, 4, bytes - 1),
            AttributeValuesRejection::TemplateReadValueLimit,
        ),
    ] {
        local_refusal(
            session.read_template_attribute(
                object,
                attribute,
                TemplateAttributeReadPlan::Slots(&slots),
                bound,
            ),
            reason,
        )?;
    }
    let mut failure = None;
    for bound in [limits(1, 4, bytes), limits(2, 5, bytes + 1)] {
        let values = session.read_template_attribute(
            object,
            attribute,
            TemplateAttributeReadPlan::Slots(&slots),
            bound,
        )?;
        report
            .observation(
                Phase::Body,
                "template_value_native_code",
                Producer::Native,
                Observation::Number(values.call().code),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        // A completed metadata observation permits the next independent read.
        // Keep the failed oracle; never turn a native partial refusal into a
        // successful value assertion. Unexpected product errors still abort.
        if let Err(error) = observed_values(&values, attribute) {
            match error {
                Failure::Oracle(_) => failure = Some(error),
                other => return Err(other),
            }
        }
    }
    failure.map_or(Ok(()), Err)
}

pub(super) fn execute<W: Write>(
    session: &Session,
    objects: &mut Vec<NativeObjectRef>,
    action: &str,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let attribute = match action {
        "nested-wrap" => StandardAttribute::WRAP_TEMPLATE,
        "nested-unwrap" => StandardAttribute::UNWRAP_TEMPLATE,
        _ => return Err(Failure::Input("template_action")),
    };
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
    let mut fields: Vec<AttributeInput<'_>> = template(action);
    fields.push(AttributeInput {
        attribute: attribute.into(),
        value: AttributeInputValue::Template(&children),
    });
    let count = fields.len() + children.len();
    refused_creation(
        session,
        objects,
        &fields,
        limits(0, count, 256),
        AttributeValuesRejection::AttributeTemplateDepthCeiling,
    )?;
    refused_creation(
        session,
        objects,
        &fields,
        limits(1, count - 1, 256),
        AttributeValuesRejection::AttributeTemplateCountCeiling,
    )?;
    let mut failure = None;
    for bound in [limits(1, count, 256), limits(2, count + 1, 256)] {
        let object = session.create_native_object(&fields, bound)?;
        objects.push(object);
        // Retain each creation before any fallible read so cleanup has ownership.
        let result = observe(
            session,
            objects.last().ok_or(Failure::Input("template_object"))?,
            attribute,
            report,
        );
        if let Err(error) = result {
            match error {
                Failure::Oracle(_) => failure = Some(error),
                other => return Err(other),
            }
        }
    }
    failure.map_or(Ok(()), Err)
}
