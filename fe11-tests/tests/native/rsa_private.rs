// SPDX-License-Identifier: Apache-2.0
//! Import the eight integer components of a published RSA test key.
use super::object_owner::Owner;
use fe11::*;

impl Owner {
    pub fn import_rsa_private(
        &self,
        key: &[Vec<u8>],
        usage: StandardAttribute,
    ) -> Result<NativeObjectRef> {
        self.import_rsa_private_usage(key, usage, true)
    }

    pub fn import_rsa_private_usage(
        &self,
        key: &[Vec<u8>],
        usage: StandardAttribute,
        enabled: bool,
    ) -> Result<NativeObjectRef> {
        // The fixture parsers establish eight nonempty, bounded components.
        let attributes = [
            StandardAttribute::MODULUS,
            StandardAttribute::PUBLIC_EXPONENT,
            StandardAttribute::PRIVATE_EXPONENT,
            StandardAttribute::PRIME_1,
            StandardAttribute::PRIME_2,
            StandardAttribute::EXPONENT_1,
            StandardAttribute::EXPONENT_2,
            StandardAttribute::COEFFICIENT,
        ];
        assert_eq!(
            key.len(),
            attributes.len(),
            "validated RSA fixture components"
        );
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let mut template = vec![
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
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
        ];
        for (attribute, value) in attributes.into_iter().zip(key) {
            template.push(attr(attribute, AttributeInputValue::Bytes(value)));
        }
        self.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 19 + key.iter().map(Vec::len).sum::<usize>(),
            },
        )
    }
}
