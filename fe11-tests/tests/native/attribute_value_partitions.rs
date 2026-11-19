// SPDX-License-Identifier: Apache-2.0
//! Read an independently supplied attribute at its exact size and adjacent capacities.
use super::attribute_probe_object::Object;
use crate::{
    arguments::hex,
    object_owner::Owner,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub(super) struct Field {
    pub(super) attribute: StandardAttribute,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct Case<const MIXED: bool = false> {
    absent: Option<StandardAttribute>,
    object: Object,
    fields: Vec<Field>,
}

fn check_field(session: &Session, key: &NativeObjectRef, field: &Field) -> fe11::Result<bool> {
    let id = field.attribute;
    let expected = field.bytes.as_slice();
    let length = expected.len();
    let size = session.read_flat_attribute(key, id, FlatAttributeReadPlan::LengthOnly)?;
    let valid_size = size.calls == (AttributeReadCalls::Size { code: 0 })
        && matches!(size.value, FlatAttributeValue::SizeKnown { required } if required == length);
    let mut valid = valid_size;
    // A larger buffer must return only the logical value's bytes.
    for capacity in [length, length + 1] {
        let entry =
            session.read_flat_attribute(key, id, FlatAttributeReadPlan::Buffer { capacity })?;
        valid &= entry.calls == (AttributeReadCalls::Direct { code: 0 })
            && matches!(entry.value, FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected);
    }
    if let Some(capacity) = length.checked_sub(1) {
        let entry =
            session.read_flat_attribute(key, id, FlatAttributeReadPlan::Buffer { capacity })?;
        valid &= entry.calls
            == (AttributeReadCalls::Direct {
                code: fe11_sys::CKR_BUFFER_TOO_SMALL as u64,
            })
            && matches!(entry.value, FlatAttributeValue::BufferTooSmall { supplied, required }
                if supplied == capacity && required.is_none());
    }
    Ok(valid)
}

impl<const MIXED: bool> SingleKeyCase for Case<MIXED> {
    const ASSERTION: &'static str = if MIXED {
        "mixed_attribute_values_and_uncertainty"
    } else {
        "explicit_attribute_values_and_adjacent_capacities"
    };
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path)
            .and_then(|f| f.take(65537).read_to_string(&mut text))
            .map_err(|_| Failure::Input("attribute_value_file"))?;
        if text.len() > 65536 {
            return Err(Failure::Input("attribute_value_fixture_size"));
        }
        let mut lines = text.lines();
        let object = Object::read(&mut lines)?;
        let absent = if MIXED {
            let name = lines
                .next()
                .ok_or(Failure::Input("mixed_absent_selector"))?;
            Some(
                StandardAttribute::ALL
                    .iter()
                    .copied()
                    .find(|a| a.name() == name)
                    .ok_or(Failure::Input("mixed_absent_selector"))?,
            )
        } else {
            None
        };
        let mut fields = Vec::new();
        for line in lines {
            let mut parts = line.split('|');
            let name = parts.next().ok_or(Failure::Input("attribute_value_name"))?;
            let attribute = StandardAttribute::ALL
                .iter()
                .copied()
                .find(|a| a.name() == name)
                .ok_or(Failure::Input("attribute_value_selector"))?;
            let encoding = parts.next();
            let value = parts
                .next()
                .ok_or(Failure::Input("attribute_value_expected"))?;
            if parts.next().is_some()
                || fields.len() >= 40
                || fields.iter().any(|f: &Field| f.attribute == attribute)
            {
                return Err(Failure::Input("attribute_value_fields"));
            }
            let bytes = match (encoding, attribute.layout()) {
                (Some("bytes"), AttributeLayout::Bytes) => {
                    hex(value, 8192).map_err(Failure::Input)?
                }
                (Some("number"), AttributeLayout::Unsigned) => value
                    .parse::<fe11_sys::CK_ULONG>()
                    .map_err(|_| Failure::Input("attribute_native_word"))?
                    .to_ne_bytes()
                    .to_vec(),
                (Some("bool"), AttributeLayout::Boolean) => vec![u8::from(
                    value
                        .parse::<bool>()
                        .map_err(|_| Failure::Input("attribute_boolean"))?,
                )],
                _ => return Err(Failure::Input("attribute_value_representation")),
            };
            fields.push(Field { attribute, bytes });
        }
        if fields.is_empty() {
            return Err(Failure::Input("attribute_value_list"));
        }
        Ok(Self {
            object,
            fields,
            absent,
        })
    }

    fn advanced(&self) -> bool {
        false
    }

    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        self.object.import(owner)
    }

    fn check<W: Write>(
        &self,
        owner: &Owner,
        object: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let Owner::Session(session) = owner else {
            return Err(Failure::Input("session_required"));
        };
        if let Some(absent) = self.absent {
            return super::attribute_mixed_fields::check(
                session,
                object,
                &self.fields,
                absent,
                report,
            );
        }
        let mut valid = true;
        for field in &self.fields {
            let actual = check_field(session, object, field)?;
            report
                .observation(
                    Phase::Body,
                    field.attribute.name(),
                    Producer::TestOracle,
                    Observation::Boolean(actual),
                )
                .map_err(|_| Failure::Input("attribute_value_report"))?;
            valid &= actual;
        }
        if valid {
            Ok(())
        } else {
            Err(Failure::Oracle("attribute_value_partition"))
        }
    }
}
