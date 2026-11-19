// SPDX-License-Identifier: Apache-2.0
//! Derivation ownership is retained before any descriptive output is inspected.
use super::{object_owner::Owner, outcome::Failure};
use fe11::*;

pub fn check(
    owner: &Owner,
    base: &NativeObjectRef,
    parameters: NativeKeyDerivation<'_>,
    expected: &[u8],
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    check_length(owner, base, parameters, expected.len(), expected, retained)
}

/// The requested template length is independent of the expected value length.
/// In particular, an explicit zero must not silently become an omitted length.
pub(super) fn check_length(
    owner: &Owner,
    base: &NativeObjectRef,
    parameters: NativeKeyDerivation<'_>,
    requested: usize,
    expected: &[u8],
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let attributes = template_attributes(requested);
    let request = GenerationTemplate {
        attributes: &attributes,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: 28,
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    };
    let created = match owner {
        Owner::Session(session) => session.derive_native_key(base, parameters, request),
        Owner::Advanced(session) => session.derive_native_key(base, parameters, request),
    }?;
    *retained = Some(created.objects);
    if created.remainder.is_some() {
        return Err(Failure::Oracle("derived_auxiliary_output"));
    }
    created.observation?;
    let objects = retained
        .as_ref()
        .ok_or(Failure::Input("derived_output_ownership"))?
        .as_slice();
    if objects.len() != 1 {
        return Err(Failure::Oracle("derived_object_count"));
    }
    let plan = FlatAttributeReadPlan::Buffer {
        capacity: expected.len(),
    };
    let observed = match owner {
        Owner::Session(session) => {
            session.read_flat_attribute(&objects[0], StandardAttribute::VALUE, plan)
        }
        Owner::Advanced(session) => {
            session.read_flat_attribute(&objects[0], StandardAttribute::VALUE, plan)
        }
    }?;
    if observed.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("derived_value_native_status"));
    }
    match observed.value {
        FlatAttributeValue::Available(value) if value.as_bytes() == expected => Ok(()),
        _ => Err(Failure::Oracle("published_derived_shared_secret")),
    }
}

/// Identical complete destination for nominal and single-fault derivation cases.
pub(super) fn template_attributes(length: usize) -> [AttributeInput<'static>; 7] {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
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
            StandardAttribute::SENSITIVE,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(true),
        ),
        attr(
            StandardAttribute::VALUE_LEN,
            AttributeInputValue::Unsigned(length as u64),
        ),
    ]
}
