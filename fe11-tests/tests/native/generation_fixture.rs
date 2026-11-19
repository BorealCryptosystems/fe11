// SPDX-License-Identifier: Apache-2.0
//! Owned, bounded templates for independently specified generation cases.
use super::{arguments::hex, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

#[path = "generated_disabled_use.rs"]
pub(super) mod disabled_use;

pub enum Value {
    Boolean(bool),
    Unsigned(u64),
    Bytes(Vec<u8>),
}
pub struct Field {
    pub attribute: StandardAttribute,
    pub value: Value,
}
pub enum Generator {
    Single(KeyGenerator),
    Pair(KeyPairGenerator),
}
pub struct Fixture {
    pub generator: Generator,
    pub public: Vec<Field>,
    pub private: Vec<Field>,
    pub pqc_witness: Option<super::pqc_parameters::Parameters>,
    pub rsa_witness: bool,
    pub domain_witness: bool,
    pub secret_witness: bool,
    pub(super) disabled_use: Option<disabled_use::Operation>,
    pub protection_matrix: bool,
    pub lifetime: bool,
}

impl Field {
    pub fn input(&self) -> AttributeInput<'_> {
        AttributeInput {
            attribute: self.attribute.into(),
            value: match &self.value {
                Value::Boolean(v) => AttributeInputValue::Boolean(*v),
                Value::Unsigned(v) => AttributeInputValue::Unsigned(*v),
                Value::Bytes(v) => AttributeInputValue::Bytes(v),
            },
        }
    }
    pub fn bytes(&self) -> usize {
        match &self.value {
            Value::Boolean(_) => 1,
            Value::Unsigned(_) => 8,
            Value::Bytes(v) => v.len(),
        }
    }
}

pub fn request<'a>(inputs: &'a [AttributeInput<'a>], fields: &[Field]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes: inputs,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: inputs.len(),
            maximum_value_bytes: fields.iter().map(Field::bytes).sum(),
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}

impl Fixture {
    pub fn read(path: &Path, label: &[u8]) -> std::result::Result<Self, Failure> {
        Self::read_inner(path, label, false).map(|(fixture, _)| fixture)
    }

    pub fn read_negative(path: &Path, label: &[u8]) -> std::result::Result<(Self, bool), Failure> {
        Self::read_inner(path, label, true)
    }

    fn read_inner(
        path: &Path,
        label: &[u8],
        allow_negative: bool,
    ) -> std::result::Result<(Self, bool), Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(32769)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 32768 || label.len() > 128 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let mut lines = text.split_terminator('\n');
        let selector = lines.next().ok_or(Failure::Input("generator"))?;
        let (selector, disabled_use) = match selector.strip_prefix("disabled-use|") {
            Some(spec) if !allow_negative => {
                let (usage, generator) = spec.split_once('|').ok_or(Failure::Input("usage_header"))?;
                (generator, Some(disabled_use::Operation::parse(usage, generator)?))
            }
            Some(_) => return Err(Failure::Input("usage_fixture_kind")),
            None => (selector, None),
        };
        let (selector, lifetime) = match selector.strip_prefix("lifetime|") {
            Some(selector) if !allow_negative => (selector, true),
            Some(_) => return Err(Failure::Input("generation_lifetime_negative")),
            None => (selector, false),
        };
        let (selector, protection_matrix) = match selector.strip_prefix("protection|") {
            Some(selector) if !allow_negative => (selector, true),
            Some(_) => return Err(Failure::Input("generation_protection_negative")),
            None => (selector, false),
        };
        let (selector, secret_witness) = match selector.strip_prefix("secret-witness|") {
            Some(
                value @ ("CKM_AES_KEY_GEN"
                | "CKM_DES_KEY_GEN"
                | "CKM_DES2_KEY_GEN"
                | "CKM_DES3_KEY_GEN"
                | "CKM_GENERIC_SECRET_KEY_GEN"),
            ) if !allow_negative => (value, true),
            Some(_) => return Err(Failure::Input("secret_generation_witness_selector")),
            None => (selector, false),
        };
        let (selector, domain_witness) = match selector.strip_prefix("domain-witness|") {
            Some(value @ ("CKM_DSA_PARAMETER_GEN" | "CKM_DH_PKCS_PARAMETER_GEN"))
                if !allow_negative =>
            {
                (value, true)
            }
            Some(_) => return Err(Failure::Input("domain_generation_witness_selector")),
            None => (selector, false),
        };
        let (selector, rsa_witness) = match selector.strip_prefix("rsa-witness|") {
            Some("CKM_RSA_PKCS_KEY_PAIR_GEN") if !allow_negative => {
                ("CKM_RSA_PKCS_KEY_PAIR_GEN", true)
            }
            Some(_) => return Err(Failure::Input("rsa_generation_witness_selector")),
            None => (selector, false),
        };
        let (selector, pqc_witness) = match selector.strip_prefix("pqc-witness|") {
            Some(value) if !allow_negative => {
                let (name, selector) = value
                    .split_once('|')
                    .ok_or(Failure::Input("generation_witness_selector"))?;
                (
                    selector,
                    Some(super::pqc_parameters::Parameters::parse(name)?),
                )
            }
            Some(_) => return Err(Failure::Input("negative_generation_witness")),
            None => (selector, None),
        };
        // Only the negative worker accepts a mutation directive. Positive
        // generation cannot silently ignore a negative fixture's purpose.
        let (selector, key_type_mismatch) = match selector.strip_prefix("key-type-mismatch|") {
            Some(selector) if allow_negative => (selector, true),
            Some(_) => return Err(Failure::Input("negative_generation_fixture")),
            None => (selector, false),
        };
        let generator = super::generation_selectors::generator(selector)?;
        let mut public = Vec::new();
        let mut private = Vec::new();
        for line in lines {
            let parts: Vec<_> = line.split('|').collect();
            if parts.len() != 4 {
                return Err(Failure::Input("generation_field"));
            }
            let destination = match parts[0] {
                "public" => &mut public,
                "private" => &mut private,
                _ => return Err(Failure::Input("generation_owner")),
            };
            if destination.len() >= 32 {
                return Err(Failure::Input("generation_template_count"));
            }
            let attribute = super::generation_selectors::attribute(parts[1])?;
            if destination.iter().any(|f: &Field| f.attribute == attribute) {
                return Err(Failure::Input("generation_duplicate_attribute"));
            }
            let value = match parts[2] {
                "bool" if parts[3] == "true" || parts[3] == "false" => {
                    Value::Boolean(parts[3] == "true")
                }
                "integer" => Value::Unsigned(
                    parts[3]
                        .parse()
                        .map_err(|_| Failure::Input("generation_integer"))?,
                ),
                "symbol" => Value::Unsigned(super::generation_selectors::number(parts[3])?),
                "hex" => Value::Bytes(hex(parts[3], 8192).map_err(Failure::Input)?),
                "namespace" if parts[3] == "label" && attribute == StandardAttribute::LABEL => {
                    Value::Bytes(label.to_vec())
                }
                _ => return Err(Failure::Input("generation_value")),
            };
            destination.push(Field { attribute, value });
        }
        if public.is_empty() || (matches!(generator, Generator::Pair(_)) != !private.is_empty()) {
            return Err(Failure::Input("generation_template_arity"));
        }
        if let Some(operation) = disabled_use {
            if !public.iter().any(|field| {
                field.attribute == operation.attribute() && matches!(field.value, Value::Boolean(false))
            }) {
                return Err(Failure::Input("disabled_usage_attribute_missing"));
            }
        }
        Ok((
            Self {
                generator,
                public,
                private,
                pqc_witness,
                rsa_witness,
                domain_witness,
                secret_witness,
                disabled_use,
                protection_matrix,
                lifetime,
            },
            key_type_mismatch,
        ))
    }
}
