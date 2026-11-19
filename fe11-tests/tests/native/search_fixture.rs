// SPDX-License-Identifier: Apache-2.0
//! Three distinguishable session objects for iterator state transitions.
use super::{arguments::hex, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub before: String,
    pub action: String,
    pub label: Vec<u8>,
    pub population: u8,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(2049)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 2048 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !matches!(
                fields[0],
                "ABSENT" | "ACTIVE" | "CACHED" | "FINISHED" | "EXHAUSTED" | "CLOSED" | "DROPPED"
            )
            || !matches!(
                fields[1],
                "init" | "next" | "finish" | "logout" | "close" | "drop" | "read_published_object"
            )
        {
            return Err(Failure::Input("search_fields"));
        }
        let label = hex(fields[2], 128).map_err(Failure::Input)?;
        if label.is_empty() {
            return Err(Failure::Input("search_empty_label"));
        }
        Ok(Self {
            before: fields[0].to_owned(),
            action: fields[1].to_owned(),
            label,
            population: 3,
        })
    }
    pub fn template(&self) -> [AttributeInput<'_>; 1] {
        [AttributeInput {
            attribute: StandardAttribute::LABEL.into(),
            value: AttributeInputValue::Bytes(&self.label),
        }]
    }
    pub fn limits(&self) -> AttributeTemplateLimits {
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: 1,
            maximum_value_bytes: self.label.len(),
        }
    }
    pub fn create(&self, session: &Session, index: u8) -> Result<NativeObjectRef> {
        self.create_sized::<32>(session, index)
    }
    pub fn create_sized<const N: usize>(
        &self,
        session: &Session,
        index: u8,
    ) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let value = [index; N];
        let template = [
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
            attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
            attr(
                StandardAttribute::VERIFY,
                AttributeInputValue::Boolean(true),
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
                StandardAttribute::LABEL,
                AttributeInputValue::Bytes(&self.label),
            ),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(&value)),
        ];
        session.create_native_object(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: N + 22 + self.label.len(),
            },
        )
    }
    pub fn identity(
        &self,
        session: &Session,
        object: &NativeObjectRef,
    ) -> std::result::Result<u8, Failure> {
        self.identity_sized::<32>(session, object)
    }
    pub fn identity_sized<const N: usize>(
        &self,
        session: &Session,
        object: &NativeObjectRef,
    ) -> std::result::Result<u8, Failure> {
        let read = |attribute, capacity| -> std::result::Result<Vec<u8>, Failure> {
            let result = session.read_flat_attribute(
                object,
                attribute,
                FlatAttributeReadPlan::Buffer { capacity },
            )?;
            if result.calls != (AttributeReadCalls::Direct { code: 0 }) {
                return Err(Failure::Oracle("search_attribute_status"));
            }
            match result.value {
                FlatAttributeValue::Available(value) => Ok(value.as_bytes().to_vec()),
                _ => Err(Failure::Oracle("search_attribute_absent")),
            }
        };
        if read(StandardAttribute::LABEL, self.label.len())? != self.label {
            return Err(Failure::Oracle("search_label"));
        }
        let value = read(StandardAttribute::VALUE, N)?;
        if value.is_empty()
            || value.len() != N
            || value[0] >= self.population
            || value.iter().any(|b| *b != value[0])
        {
            return Err(Failure::Oracle("search_value"));
        }
        Ok(value[0])
    }
}
