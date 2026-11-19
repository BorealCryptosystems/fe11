// SPDX-License-Identifier: Apache-2.0
//! A zero-length CK_DATE and an eight-byte date have distinct wire values.
use super::{attr, limits, template, Failure, LABEL};
use crate::{object_owner::Owner, object_transition_fixture::find};
use fe11::*;

fn read_dates(batch: FlatAttributeBatch, start: &[u8], end: &[u8]) -> std::result::Result<(), Failure> {
    if batch.calls() != AttributeBatchCalls::One(AttributeBatchCall { code: 0, attribute_count: 2 })
        || batch.len() != 2
    {
        return Err(Failure::Oracle("date_read_contract"));
    }
    for (entry, expected) in batch.iter().zip([start, end]) {
        match &entry.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("date_read_value_or_length")),
        }
    }
    Ok(())
}

pub(super) fn check(
    module: &Module,
    owner: &Owner,
    reader: &Session,
    cleanup: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    let start = StandardAttribute::START_DATE;
    let end = StandardAttribute::END_DATE;
    let mut fields = template("dates");
    fields.extend([attr(start, AttributeInputValue::Bytes(&[])), attr(end, AttributeInputValue::Date([0; 8]))]);
    // Session objects remain owned by the creating session even on an early error.
    let object = owner.create(&fields, limits(fields.len()))?;
    let requests = [start, end].map(|attribute| FlatAttributeRequest {
        attribute: attribute.into(), plan: FlatAttributeReadPlan::Buffer { capacity: 8 },
    });
    let initial = match owner {
        Owner::Session(s) => s.read_flat_attributes(&object, &requests, 16)?,
        Owner::Advanced(s) => s.read_flat_attributes(&object, &requests, 16)?,
    };
    read_dates(initial, &[], &[0; 8])?;
    let set = |fields: &[AttributeInput<'_>]| match owner {
        Owner::Session(s) => s.set_native_attributes(&object, fields, limits(fields.len())),
        Owner::Advanced(s) => s.set_native_attributes(&object, fields, limits(fields.len())),
    };
    let before = module.call_counts()?;
    match set(&[attr(start, AttributeInputValue::Bytes(b"20261117"))]) {
        Err(Error::Rejected(RejectionReason::AttributeValues(AttributeValuesRejection::AttributeInputRepresentation))) => (),
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("untyped_nonempty_date_accepted")),
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("untyped_date_native_dispatch"));
    }
    set(&[attr(start, AttributeInputValue::Date(*b"20261117")), attr(end, AttributeInputValue::Bytes(&[]))])?;
    // The mutation retires the old view. Rediscover just the labelled object
    // on the fresh case token while the creating session still owns it.
    let mut found = find(reader, LABEL)?;
    if found.len() != 1 {
        return Err(Failure::Oracle("date_readback_object_count"));
    }
    let fresh = found.pop().ok_or(Failure::Oracle("date_readback_absent"))?;
    cleanup.push(fresh);
    let fresh = cleanup.last().ok_or(Failure::Oracle("date_cleanup_reference"))?;
    read_dates(reader.read_flat_attributes(fresh, &requests, 16)?, b"20261117", &[])
}
