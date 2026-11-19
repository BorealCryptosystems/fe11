// SPDX-License-Identifier: Apache-2.0
//! Change one field in an otherwise valid session-object creation template.
use super::attribute_probe_object::Object;
use crate::{
    generation_fixture::{Field, Value},
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

enum Change {
    Omit(StandardAttribute),
    Supply(Field),
    OptionalRsaCoefficient(Vec<u8>),
}

pub(super) struct Case<const OPTIONAL_RSA: bool = false> {
    object: Object,
    change: Change,
}

impl<const OPTIONAL_RSA: bool> SingleKeyCase for Case<OPTIONAL_RSA> {
    const ASSERTION: &'static str = if OPTIONAL_RSA {
        "optional_rsa_crt_import_contract"
    } else {
        "single_changed_template_native_refusal"
    };
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path)
            .and_then(|f| f.take(65537).read_to_string(&mut text))
            .map_err(|_| Failure::Input("create_template_file"))?;
        if text.len() > 65536 {
            return Err(Failure::Input("create_template_size"));
        }
        let mut lines = text.lines();
        let object = Object::read(&mut lines)?;
        let Object::FieldTemplate(fields) = &object else {
            return Err(Failure::Input("full_creation_template"));
        };
        let command = lines
            .next()
            .ok_or(Failure::Input("template_change_missing"))?;
        let (action, name) = command
            .split_once('|')
            .ok_or(Failure::Input("template_change_format"))?;
        let attr = StandardAttribute::ALL
            .iter()
            .copied()
            .find(|a| a.name() == name)
            .ok_or(Failure::Input("template_change_selector"))?;
        let present = fields.iter().any(|f| f.attribute == attr);
        // Persistence is fixed for both the valid setup and the altered template.
        if attr == StandardAttribute::TOKEN {
            return Err(Failure::Input("template_change_scope"));
        }
        let change = match action {
            "omit" if !OPTIONAL_RSA && present => Change::Omit(attr),
            "optional" if OPTIONAL_RSA && present && attr == StandardAttribute::COEFFICIENT => {
                let known = lines.next().ok_or(Failure::Input("rsa_known_signature"))?;
                let bytes = crate::arguments::hex(known, 8192).map_err(Failure::Input)?;
                if bytes.is_empty() {
                    return Err(Failure::Input("rsa_known_signature"));
                }
                Change::OptionalRsaCoefficient(bytes)
            }
            "supply" if !OPTIONAL_RSA && !present => {
                let value = match attr.layout() {
                    AttributeLayout::Boolean => Value::Boolean(false),
                    AttributeLayout::Unsigned => Value::Unsigned(1),
                    AttributeLayout::Bytes => Value::Bytes(vec![1]),
                    _ => return Err(Failure::Input("template_change_layout")),
                };
                Change::Supply(Field {
                    attribute: attr,
                    value,
                })
            }
            _ => return Err(Failure::Input("template_change_precondition")),
        };
        if lines.next().is_some() {
            return Err(Failure::Input("trailing_template_data"));
        }
        Ok(Self { object, change })
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
        _valid_object: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let Object::FieldTemplate(original) = &self.object else {
            return Err(Failure::Input("full_creation_template"));
        };
        let mut fields: Vec<&Field> = original.iter().collect();
        match &self.change {
            Change::Omit(attr) => fields.retain(|f| f.attribute != *attr),
            Change::Supply(field) => fields.push(field),
            Change::OptionalRsaCoefficient(_) => {
                fields.retain(|f| f.attribute != StandardAttribute::COEFFICIENT)
            }
        }
        let inputs: Vec<_> = fields.iter().map(|f| f.input()).collect();
        let size = fields.iter().map(|f| f.bytes()).sum();
        let result = owner.create(
            &inputs,
            AttributeTemplateLimits {
                maximum_attributes: fields.len(),
                maximum_depth: 0,
                maximum_value_bytes: size,
            },
        );
        match result {
            Err(Error::Native {
                function: "C_CreateObject",
                code,
                may_have_effect,
            }) => {
                report
                    .observation(
                        Phase::Body,
                        "creation_return",
                        Producer::Native,
                        Observation::Native {
                            function: "C_CreateObject",
                            code,
                            may_have_effect,
                        },
                    )
                    .map_err(|_| Failure::Input("creation_return_report"))?;
                let expected = match self.change {
                    Change::Omit(_) | Change::OptionalRsaCoefficient(_) => {
                        code == fe11_sys::CKR_TEMPLATE_INCOMPLETE as u64
                    }
                    Change::Supply(_) => {
                        code == fe11_sys::CKR_ATTRIBUTE_READ_ONLY as u64
                            || code == fe11_sys::CKR_TEMPLATE_INCONSISTENT as u64
                    }
                };
                if expected {
                    Ok(())
                } else {
                    Err(Failure::Oracle("changed_template_native_status"))
                }
            }
            Err(other) => Err(other.into()),
            Ok(unexpected) => {
                let Owner::Session(s) = owner else {
                    return Err(Failure::Input("creation_check_session"));
                };
                // The CRT coefficient is optional at import. A successful import
                // must retain the key identity; an incomplete template may be refused.
                let result = if let Change::OptionalRsaCoefficient(expected) = &self.change {
                    s.sign_native(
                        &unexpected,
                        NativeSignatureParameters::Parameterless(
                            NativeSignatureAlgorithm::SHA256_RSA_PKCS,
                        ),
                        MessageRoute::Single,
                        &[b"abc"],
                        InputLimits {
                            maximum_parts: 1,
                            maximum_total_bytes: 3,
                        },
                        expected.len(),
                        None,
                    )
                    .map_err(Failure::from)
                    .and_then(|value| {
                        if value.as_bytes() == expected.as_slice() {
                            Ok(())
                        } else {
                            Err(Failure::Oracle("rsa_import_known_signature"))
                        }
                    })
                } else {
                    Err(Failure::Oracle("changed_template_was_accepted"))
                };
                s.destroy_native_object(&unexpected)?;
                result
            }
        }
    }
}
