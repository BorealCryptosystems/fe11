// SPDX-License-Identifier: Apache-2.0
//! Explicit native verification and public-key import for published vectors.
use super::object_owner::Owner;
use fe11::*;

impl Owner {
    pub fn import_ec_public(&self, parameters: &[u8], point: &[u8]) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
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
                StandardAttribute::VERIFY,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::EC_PARAMS,
                AttributeInputValue::Bytes(parameters),
            ),
            attr(
                StandardAttribute::EC_POINT,
                AttributeInputValue::Bytes(point),
            ),
        ];
        self.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 19 + parameters.len() + point.len(),
            },
        )
    }

    pub fn import_rsa_public(&self, modulus: &[u8], exponent: &[u8]) -> Result<NativeObjectRef> {
        self.import_rsa_public_usage(modulus, exponent, StandardAttribute::VERIFY)
    }

    pub fn import_rsa_public_usage(
        &self,
        modulus: &[u8],
        exponent: &[u8],
        usage: StandardAttribute,
    ) -> Result<NativeObjectRef> {
        self.import_rsa_public_usage_enabled(modulus, exponent, usage, true)
    }

    pub fn import_rsa_public_usage_enabled(
        &self,
        modulus: &[u8],
        exponent: &[u8],
        usage: StandardAttribute,
        enabled: bool,
    ) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_RSA as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(usage, AttributeInputValue::Boolean(enabled)),
            attr(
                StandardAttribute::MODULUS,
                AttributeInputValue::Bytes(modulus),
            ),
            attr(
                StandardAttribute::PUBLIC_EXPONENT,
                AttributeInputValue::Bytes(exponent),
            ),
        ];
        self.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 19 + modulus.len() + exponent.len(),
            },
        )
    }

    pub fn verify_signature(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeSignatureAlgorithm,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        let parameters = NativeSignatureParameters::Parameterless(algorithm);
        self.verify_parameters(key, parameters, route, parts, signature, limits)
    }

    pub fn verify_parameters(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        match self {
            Self::Session(session) => {
                session.verify_native(key, parameters, route, parts, signature, limits, None)
            }
            Self::Advanced(session) => {
                session.verify_native(key, parameters, route, parts, signature, limits, None)
            }
        }
    }
}
