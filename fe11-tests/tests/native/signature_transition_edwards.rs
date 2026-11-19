// SPDX-License-Identifier: Apache-2.0
//! Public Ed25519 seed and point with an external-message, absent-context profile.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;

pub struct Material {
    public: Vec<u8>,
    seed: Vec<u8>,
}
impl Material {
    pub fn read(fields: &[&str]) -> std::result::Result<Self, Failure> {
        if fields.len() != 9 || fields[3] != "ED-25519" || !fields[6].is_empty() {
            return Err(Failure::Input("edwards_transition_fields"));
        }
        let material = Self {
            public: hex(fields[4], 32).map_err(Failure::Input)?,
            seed: hex(fields[5], 32).map_err(Failure::Input)?,
        };
        if material.public.len() != 32 || material.seed.len() != 32 {
            return Err(Failure::Input("edwards_transition_key_width"));
        }
        Ok(material)
    }
    pub fn mechanism(&self) -> NativeSignatureParameters<'_> {
        NativeSignatureParameters::EdDsa(Some(NativeEdDsaParameters {
            prehash: false,
            context: None,
        }))
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
                AttributeInputValue::Unsigned(fe11_sys::CKK_EC_EDWARDS as u64),
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
                AttributeInputValue::Bytes(&[0x06, 0x03, 0x2b, 0x65, 0x70]),
            ),
            // Edwards points use the raw RFC8032 representation, not EC-point DER.
            attr(
                if sign {
                    StandardAttribute::VALUE
                } else {
                    StandardAttribute::EC_POINT
                },
                AttributeInputValue::Bytes(if sign { &self.seed } else { &self.public }),
            ),
        ];
        owner.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 56,
            },
        )
    }
}
