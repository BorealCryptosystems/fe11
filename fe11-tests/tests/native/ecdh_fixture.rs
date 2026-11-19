// SPDX-License-Identifier: Apache-2.0
//! Exact public ECDH vectors: private scalar, native peer point and shared secret.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub parameters: Vec<u8>,
    pub private: Vec<u8>,
    pub peer: Vec<u8>,
    pub expected: Vec<u8>,
}

impl Vector {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 5 || !matches!(fields[0], "session" | "advanced") {
            return Err(Failure::Input("ecdh_fields"));
        }
        let value = Self {
            advanced: fields[0] == "advanced",
            parameters: hex(fields[1], 64).map_err(Failure::Input)?,
            private: hex(fields[2], 128).map_err(Failure::Input)?,
            peer: hex(fields[3], 256).map_err(Failure::Input)?,
            expected: hex(fields[4], 128).map_err(Failure::Input)?,
        };
        if value.parameters.is_empty()
            || value.private.is_empty()
            || value.peer.is_empty()
            || value.expected.is_empty()
        {
            return Err(Failure::Input("ecdh_dimensions"));
        }
        Ok(value)
    }

    pub fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        self.import_usage(owner, true)
    }
}

impl super::derived_value_case::DerivedValueCase for Vector {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Vector::read(path)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        Vector::import(self, owner)
    }
    fn parameters(&self) -> NativeKeyDerivation<'_> {
        NativeKeyDerivation::Ecdh {
            kdf: fe11_sys::CKD_NULL as u64,
            cofactor: false,
            peer_public: &self.peer,
            shared_data: None,
        }
    }
    fn expected(&self) -> &[u8] {
        &self.expected
    }
}

impl Vector {
    pub(super) fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
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
                StandardAttribute::DERIVE,
                AttributeInputValue::Boolean(allowed),
            ),
            attr(
                StandardAttribute::EC_PARAMS,
                AttributeInputValue::Bytes(&self.parameters),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&self.private),
            ),
        ];
        owner.create(
            &template,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: template.len(),
                maximum_value_bytes: 19 + self.parameters.len() + self.private.len(),
            },
        )
    }
}
