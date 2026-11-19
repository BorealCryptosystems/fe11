// SPDX-License-Identifier: Apache-2.0
//! Attribute readback for imported private keys. Each file contains only published vector inputs.
use super::super::{
    arguments::hex,
    configuration::{Budgets, Configuration},
    generation_fixture::{Field, Value},
    module_controls,
    object_owner::Owner,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    protected: bool,
    usage: StandardAttribute,
    secret: StandardAttribute,
    fields: Vec<Field>,
}
fn id(value: &str) -> std::result::Result<StandardAttribute, Failure> {
    value
        .parse()
        .ok()
        .and_then(StandardAttribute::from_identifier)
        .ok_or(Failure::Input("private_attribute_id"))
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path)
            .and_then(|f| f.take(32769).read_to_string(&mut text))
            .map_err(|_| Failure::Input("private_attribute_file"))?;
        let mut lines = text.lines();
        if text.len() > 32768 || lines.next() != Some("imported-private-attributes") {
            return Err(Failure::Input("private_attribute_header"));
        }
        let protected = match lines.next() {
            Some("protected") => true,
            Some("readable") => false,
            _ => return Err(Failure::Input("private_export_partition")),
        };
        let usage = id(lines.next().ok_or(Failure::Input("private_usage"))?)?;
        let secret = id(lines
            .next()
            .ok_or(Failure::Input("private_value_attribute"))?)?;
        let mut fields = Vec::new();
        for line in lines {
            let mut parts = line.split('|');
            let attribute = id(parts.next().ok_or(Failure::Input("private_field"))?)?;
            let shape = parts.next();
            let data = parts.next().ok_or(Failure::Input("private_field_value"))?;
            if parts.next().is_some()
                || fields.len() >= 32
                || fields.iter().any(|f: &Field| f.attribute == attribute)
            {
                return Err(Failure::Input("private_field_arity"));
            }
            let value = match shape {
                Some("bool") => Value::Boolean(
                    data.parse()
                        .map_err(|_| Failure::Input("private_field_bool"))?,
                ),
                Some("number") => Value::Unsigned(
                    data.parse()
                        .map_err(|_| Failure::Input("private_field_ulong"))?,
                ),
                Some("bytes") => Value::Bytes(hex(data, 8192).map_err(Failure::Input)?),
                _ => return Err(Failure::Input("private_field_shape")),
            };
            fields.push(Field { attribute, value });
        }
        Ok(Self {
            protected,
            usage,
            secret,
            fields,
        })
    }
    fn field(&self, attribute: StandardAttribute) -> std::result::Result<&Value, Failure> {
        self.fields
            .iter()
            .find(|f| f.attribute == attribute)
            .map(|f| &f.value)
            .ok_or(Failure::Input("private_field_absent"))
    }
    fn observe<W: Write>(
        &self,
        session: &Session,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        for (attr, expected) in [
            (StandardAttribute::SENSITIVE, self.protected),
            (StandardAttribute::EXTRACTABLE, true),
            (self.usage, true),
        ] {
            let v = session.read_flat_attribute(
                key,
                attr,
                FlatAttributeReadPlan::Buffer { capacity: 1 },
            )?;
            if v.calls != (AttributeReadCalls::Direct { code: 0 }) || v.boolean()? != expected {
                return Err(Failure::Oracle("private_usage_or_protection_readback"));
            }
        }
        for attr in [StandardAttribute::CLASS, StandardAttribute::KEY_TYPE] {
            let Value::Unsigned(expected) = self.field(attr)? else {
                return Err(Failure::Input("private_identity_type"));
            };
            let v = session.read_flat_attribute(
                key,
                attr,
                FlatAttributeReadPlan::Buffer {
                    capacity: std::mem::size_of::<fe11_sys::CK_ULONG>(),
                },
            )?;
            if v.calls != (AttributeReadCalls::Direct { code: 0 }) || v.unsigned()? != *expected {
                return Err(Failure::Oracle("private_identity_readback"));
            }
        }
        let Value::Bytes(expected) = self.field(self.secret)? else {
            return Err(Failure::Input("private_value_type"));
        };
        let v = session.read_flat_attribute(
            key,
            self.secret,
            FlatAttributeReadPlan::Buffer {
                capacity: expected.len(),
            },
        )?;
        let code = if self.protected {
            fe11_sys::CKR_ATTRIBUTE_SENSITIVE as u64
        } else {
            0
        };
        if v.calls != (AttributeReadCalls::Direct { code }) {
            return Err(Failure::Oracle("private_value_native_code"));
        }
        match v.value {
            FlatAttributeValue::Unavailable(AttributeUnavailableCause::Sensitive)
                if self.protected =>
            {
                ()
            }
            FlatAttributeValue::Available(bytes)
                if !self.protected && bytes.as_bytes() == expected.as_slice() =>
            {
                ()
            }
            _ => return Err(Failure::Oracle("private_value_observation")),
        }
        report
            .observation(
                Phase::Body,
                "imported_private_read_code",
                Producer::Native,
                Observation::Number(code),
            )
            .map_err(|_| Failure::Input("private_attribute_report"))
    }
}
pub(super) fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut owner = None;
    let mut key = None;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("private_attribute_module"))?;
        owner = Some(Owner::open(m, config, false)?);
        let o = owner
            .as_ref()
            .ok_or(Failure::Input("private_attribute_owner"))?;
        let inputs: Vec<_> = case.fields.iter().map(Field::input).collect();
        key = Some(o.create(
            &inputs,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: inputs.len(),
                maximum_value_bytes: case.fields.iter().map(Field::bytes).sum(),
            },
        )?);
        Ok(case)
    })();
    let body = match (&setup, &owner, &key) {
        (Ok(case), Some(Owner::Session(session)), Some(key)) => {
            case.observe(session, key, &mut report)
        }
        _ => Ok(()),
    };
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |o| o.close(key.as_ref()));
    drop(key);
    drop(owner);
    if let Some(m) = module {
        if let Err(err) = m.close() {
            cleanup.push(err.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
