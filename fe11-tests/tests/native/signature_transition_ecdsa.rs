// SPDX-License-Identifier: Apache-2.0
//! P-256 public fixtures for raw and SHA-256 ECDSA continuations.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;

pub struct Material {
    public: Vec<u8>,
    scalar: Vec<u8>,
    sha256: bool,
}
impl Material {
    pub fn read(fields: &[&str]) -> std::result::Result<Self, Failure> {
        if fields.len() != 9
            || !matches!(fields[3], "ECDSA-P256" | "ECDSA-SHA256-P256")
            || !fields[6].is_empty()
        {
            return Err(Failure::Input("ecdsa_transition_fields"));
        }
        let material = Self {
            public: hex(fields[4], 67).map_err(Failure::Input)?,
            scalar: hex(fields[5], 32).map_err(Failure::Input)?,
            sha256: fields[3] == "ECDSA-SHA256-P256",
        };
        if material.public.len() != 67
            || material.public[..3] != [0x04, 0x41, 0x04]
            || material.scalar.len() != 32
        {
            return Err(Failure::Input("ecdsa_transition_key_width"));
        }
        Ok(material)
    }
    pub fn mechanism(&self) -> NativeSignatureParameters<'_> {
        NativeSignatureParameters::Parameterless(if self.sha256 {
            NativeSignatureAlgorithm::ECDSA_SHA256
        } else {
            NativeSignatureAlgorithm::ECDSA
        })
    }
    pub fn import(&self, owner: &Owner, sign: bool, allowed: bool) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(if sign {
                    fe11_sys::CKO_PRIVATE_KEY
                } else {
                    fe11_sys::CKO_PUBLIC_KEY
                } as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_EC as u64),
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
                if sign {
                    StandardAttribute::SIGN
                } else {
                    StandardAttribute::VERIFY
                },
                AttributeInputValue::Boolean(allowed),
            ),
            attr(
                StandardAttribute::EC_PARAMS,
                AttributeInputValue::Bytes(&[
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                ]),
            ),
            attr(
                if sign {
                    StandardAttribute::VALUE
                } else {
                    StandardAttribute::EC_POINT
                },
                AttributeInputValue::Bytes(if sign { &self.scalar } else { &self.public }),
            ),
        ];
        owner.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 96,
            },
        )
    }
}
