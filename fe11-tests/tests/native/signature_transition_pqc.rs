// SPDX-License-Identifier: Apache-2.0
//! Deterministic external-message PQC material for the shared ticket protocol.
use super::{arguments::hex, object_owner::Owner, outcome::Failure, pqc_parameters::Parameters};
use fe11::*;

pub struct Material {
    pub parameters: Parameters,
    public: Vec<u8>,
    private: Vec<u8>,
    context: Vec<u8>,
}
impl Material {
    pub fn read(fields: &[&str]) -> std::result::Result<Self, Failure> {
        if fields.len() != 9 || !matches!(fields[3], "ML-DSA-44" | "SLH-DSA-SHA2-128s") {
            return Err(Failure::Input("pqc_transition_fields"));
        }
        let parameters = Parameters::parse(fields[3])?;
        let material = Self {
            public: hex(fields[4], parameters.public_bytes).map_err(Failure::Input)?,
            private: hex(fields[5], parameters.private_bytes).map_err(Failure::Input)?,
            context: hex(fields[6], 255).map_err(Failure::Input)?,
            parameters,
        };
        if material.public.len() != material.parameters.public_bytes
            || material.private.len() != material.parameters.private_bytes
        {
            return Err(Failure::Input("pqc_transition_key_width"));
        }
        Ok(material)
    }
    pub fn mechanism(&self) -> NativeSignatureParameters<'_> {
        NativeSignatureParameters::PqcPure {
            family: self.parameters.family,
            parameters: Some(NativePqcContext {
                hedging: PqcHedging::DeterministicRequired,
                context: Some(&self.context),
            }),
        }
    }
    pub fn import(&self, owner: &Owner, sign: bool, allowed: bool) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let value = if sign { &self.private } else { &self.public };
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
                AttributeInputValue::Unsigned(self.parameters.key_type),
            ),
            attr(
                StandardAttribute::PARAMETER_SET,
                AttributeInputValue::Unsigned(self.parameters.set),
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
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(value)),
        ];
        owner.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: value.len() + 27,
            },
        )
    }
}
