// SPDX-License-Identifier: Apache-2.0
//! Public DSA domain and key imports; no private scalar is needed for a KAT.
use super::object_owner::Owner;
use fe11::*;

impl Owner {
    pub fn import_dsa_public(
        &self,
        prime: &[u8],
        subprime: &[u8],
        base: &[u8],
        value: &[u8],
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
                AttributeInputValue::Unsigned(fe11_sys::CKK_DSA as u64),
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
            attr(StandardAttribute::PRIME, AttributeInputValue::Bytes(prime)),
            attr(
                StandardAttribute::SUBPRIME,
                AttributeInputValue::Bytes(subprime),
            ),
            attr(StandardAttribute::BASE, AttributeInputValue::Bytes(base)),
            attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(value)),
        ];
        self.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 19 + prime.len() + subprime.len() + base.len() + value.len(),
            },
        )
    }
}
