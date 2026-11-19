// SPDX-License-Identifier: Apache-2.0
//! Public RFC 3394 vectors and explicit, extractable session-key templates.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub unwrap: bool,
    pub valid: bool,
    pub kek: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub check: Option<String>,
}

impl Vector {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 16384 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(fields.len(), 6 | 7) {
            return Err(Failure::Input("vector_fields"));
        }
        let advanced = match fields[0] {
            "session" => false,
            "advanced" => true,
            _ => return Err(Failure::Input("wrap_owner")),
        };
        let unwrap = match fields[1] {
            "unwrap" => true,
            "wrap" => false,
            _ => return Err(Failure::Input("wrap_direction")),
        };
        let valid = match fields[2] {
            "valid" => true,
            "invalid" if unwrap => false,
            _ => return Err(Failure::Input("wrap_oracle")),
        };
        let check = if fields.len() == 7 {
            let permitted = if unwrap {
                fields[6] == "attributes"
            } else {
                matches!(
                    fields[6],
                    "nonextractable" | "untrusted" | "capacity" | "kwp-absent"
                )
            };
            if !valid || !permitted {
                return Err(Failure::Input("wrap_policy_check"));
            }
            Some(fields[6].into())
        } else {
            None
        };
        let kek = hex(fields[3], 32).map_err(Failure::Input)?;
        if !matches!(kek.len(), 16 | 24 | 32) {
            return Err(Failure::Input("wrap_key_length"));
        }
        Ok(Self {
            advanced,
            unwrap,
            valid,
            kek,
            plaintext: hex(fields[4], 4096).map_err(Failure::Input)?,
            ciphertext: hex(fields[5], 4104).map_err(Failure::Input)?,
            check,
        })
    }
}

pub fn parameters(explicit: bool) -> NativeTransportParameters<'static> {
    NativeTransportParameters::Fixed {
        mechanism: NativeTransportMechanism::AES_KEY_WRAP,
        bytes: if explicit { Some(&[0xa6; 8]) } else { None },
    }
}

pub fn template() -> [AttributeInput<'static>; 8] {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    [
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
        attr(
            StandardAttribute::SENSITIVE,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(true),
        ),
        attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
        attr(
            StandardAttribute::VERIFY,
            AttributeInputValue::Boolean(true),
        ),
    ]
}

pub fn limits(count: usize, bytes: usize) -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: 0,
        maximum_attributes: count,
        maximum_value_bytes: bytes + 32,
    }
}

pub fn import_target(owner: &Owner, bytes: &[u8]) -> Result<NativeObjectRef> {
    import_target_checked(owner, bytes, None)
}

pub fn import_target_checked(
    owner: &Owner,
    bytes: &[u8],
    check: Option<&str>,
) -> Result<NativeObjectRef> {
    let mut attributes = Vec::from(template());
    if check == Some("nonextractable") {
        for field in &mut attributes {
            if field.attribute == StandardAttribute::EXTRACTABLE {
                field.value = AttributeInputValue::Boolean(false);
            }
        }
    }
    if check == Some("untrusted") {
        attributes.push(AttributeInput {
            attribute: StandardAttribute::WRAP_WITH_TRUSTED.into(),
            value: AttributeInputValue::Boolean(true),
        });
    }
    attributes.push(AttributeInput {
        attribute: StandardAttribute::VALUE.into(),
        value: AttributeInputValue::Bytes(bytes),
    });
    owner.create(&attributes, limits(attributes.len(), bytes.len()))
}

pub fn destroy(owner: &Owner, object: &NativeObjectRef) -> Result<()> {
    match owner {
        Owner::Session(session) => session.destroy_native_object(object),
        Owner::Advanced(session) => session.destroy_native_object(object),
    }
}
