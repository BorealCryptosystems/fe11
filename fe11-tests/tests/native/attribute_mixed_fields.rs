// SPDX-License-Identifier: Apache-2.0
//! Preserve ordered successes and native uncertainty in a single mixed read.
use super::attribute_value_partitions::Field;
use crate::{
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::io::Write;

pub(super) fn check<W: Write>(
    session: &Session,
    key: &NativeObjectRef,
    fields: &[Field],
    absent: StandardAttribute,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let first = fields
        .first()
        .ok_or(Failure::Input("mixed_missing_fields"))?;
    let short = fields.iter().find(|field| !field.bytes.is_empty());
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    let mut add = |id: StandardAttribute, capacity, value: Option<&[u8]>| {
        requests.push(FlatAttributeRequest {
            attribute: id.into(),
            plan: FlatAttributeReadPlan::Buffer { capacity },
        });
        expected.push(value.map(<[u8]>::to_vec));
    };
    // The first field also appears last, so order and multiplicity are observable.
    add(first.attribute, first.bytes.len(), Some(&first.bytes));
    add(absent, 1, None);
    if let Some(field) = short {
        add(field.attribute, field.bytes.len() - 1, None);
    }
    for field in fields.iter().rev() {
        add(field.attribute, field.bytes.len(), Some(&field.bytes));
    }
    let budget = requests
        .iter()
        .map(|r| match r.plan {
            FlatAttributeReadPlan::Buffer { capacity } => capacity,
            _ => 0,
        })
        .sum();
    let batch = session.read_flat_attributes(key, &requests, budget)?;
    let AttributeBatchCalls::One(call) = batch.calls() else {
        return Err(Failure::Oracle("mixed_single_native_call"));
    };
    if call.attribute_count != requests.len()
        || batch.len() != requests.len()
        || !(call.code == fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID as u64
            || short.is_some() && call.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64)
    {
        return Err(Failure::Oracle("mixed_native_status_or_count"));
    }
    let mut success = true;
    for (position, ((item, req), value)) in batch.iter().zip(requests).zip(expected).enumerate() {
        let checked = item.attribute == req.attribute
            && match value {
                Some(bytes) => matches!(&item.value, FlatAttributeValue::Available(actual)
                if actual.as_bytes() == bytes),
                // An aggregate return and an unavailable length cannot attribute
                // either individual failure to a specific native reason.
                None => matches!(
                    item.value,
                    FlatAttributeValue::Unavailable(AttributeUnavailableCause::Unspecified)
                ),
            };
        if position >= 2 + usize::from(short.is_some()) {
            let name = fields[fields.len() - 1 - (position - 2 - usize::from(short.is_some()))]
                .attribute
                .name();
            report
                .observation(
                    Phase::Body,
                    name,
                    Producer::TestOracle,
                    Observation::Boolean(checked),
                )
                .map_err(|_| Failure::Input("mixed_attribute_report"))?;
        }
        success &= checked;
    }
    if success {
        Ok(())
    } else {
        Err(Failure::Oracle("mixed_field_identity_or_value"))
    }
}
