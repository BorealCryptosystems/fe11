// SPDX-License-Identifier: Apache-2.0
//! Bounded, explicitly owned object templates shared by attribute observations.
use crate::{
    arguments::hex, generation_fixture::{Field, Value}, key_wrap_fixture,
    object_owner::Owner, outcome::Failure,
};
use fe11::*;
use std::str::Lines;

pub(super) enum Object {
    FieldTemplate(Vec<Field>),
    Data,
    Aes,
    Secret,
    TypedSecret { key_type: fe11_sys::CK_KEY_TYPE, value: Vec<u8>, mac: bool },
    PublicRsa(Vec<Vec<u8>>),
    PrivateRsa(Vec<Vec<u8>>),
}

impl Object {
    pub(super) fn read(lines: &mut Lines<'_>) -> std::result::Result<Self, Failure> {
        Ok(match lines.next() {
            Some("template") => {
                let mut fields = Vec::new();
                loop {
                    let line = lines.next().ok_or(Failure::Input("missing_attribute_separator"))?;
                    if line == "attributes" { break; }
                    let mut parts = line.split('|');
                    let attribute = parts.next().and_then(|id| id.parse::<u64>().ok())
                        .and_then(StandardAttribute::from_identifier)
                        .ok_or(Failure::Input("template_field_id"))?;
                    let encoding = parts.next();
                    let data = parts.next().ok_or(Failure::Input("template_field_value"))?;
                    if fields.len() >= 32 || parts.next().is_some()
                        || fields.iter().any(|f: &Field| f.attribute == attribute) {
                        return Err(Failure::Input("invalid_template_fields"));
                    }
                    let value = match encoding {
                        Some("bool") => Value::Boolean(data.parse()
                            .map_err(|_| Failure::Input("template_boolean"))?),
                        Some("number") => Value::Unsigned(data.parse()
                            .map_err(|_| Failure::Input("template_unsigned"))?),
                        Some("bytes") => Value::Bytes(hex(data, 8192).map_err(Failure::Input)?),
                        _ => return Err(Failure::Input("template_encoding")),
                    };
                    fields.push(Field { attribute, value });
                }
                // The fixture owns a disposable session object on every branch.
                if !fields.iter().any(|f| f.attribute == StandardAttribute::TOKEN
                    && matches!(f.value, Value::Boolean(false))) {
                    return Err(Failure::Input("expected_session_object"));
                }
                Object::FieldTemplate(fields)
            }
            Some("data") => Object::Data,
            Some("aes") => Object::Aes,
            Some("generic") => Object::Secret,
            Some(kind @ ("rsa-public" | "rsa-private")) => {
                let count = if kind == "rsa-public" { 2 } else { 8 };
                let mut parts = Vec::with_capacity(count);
                for _ in 0..count {
                    let part = hex(lines.next().ok_or(Failure::Input("rsa_part"))?, 256)
                        .map_err(Failure::Input)?;
                    if part.is_empty() { return Err(Failure::Input("empty_rsa_part")); }
                    parts.push(part);
                }
                if count == 2 { Object::PublicRsa(parts) } else { Object::PrivateRsa(parts) }
            }
            Some(kind) => {
                // Explicit key type matters even when several algorithms share
                // the same object-class implementation and attribute table.
                let (key_type, length, mac) = match kind {
                    "CKK_MD5_HMAC" => (fe11_sys::CKK_MD5_HMAC, 16, true),
                    "CKK_SHA_1_HMAC" => (fe11_sys::CKK_SHA_1_HMAC, 20, true),
                    "CKK_SHA224_HMAC" => (fe11_sys::CKK_SHA224_HMAC, 28, true),
                    "CKK_SHA256_HMAC" => (fe11_sys::CKK_SHA256_HMAC, 32, true),
                    "CKK_SHA384_HMAC" => (fe11_sys::CKK_SHA384_HMAC, 48, true),
                    "CKK_SHA512_HMAC" => (fe11_sys::CKK_SHA512_HMAC, 64, true),
                    "CKK_SHA3_224_HMAC" => (fe11_sys::CKK_SHA3_224_HMAC, 28, true),
                    "CKK_SHA3_256_HMAC" => (fe11_sys::CKK_SHA3_256_HMAC, 32, true),
                    "CKK_SHA3_384_HMAC" => (fe11_sys::CKK_SHA3_384_HMAC, 48, true),
                    "CKK_SHA3_512_HMAC" => (fe11_sys::CKK_SHA3_512_HMAC, 64, true),
                    "CKK_DES" => (fe11_sys::CKK_DES, 8, false),
                    "CKK_DES2" => (fe11_sys::CKK_DES2, 16, false),
                    "CKK_DES3" => (fe11_sys::CKK_DES3, 24, false),
                    _ => return Err(Failure::Input("attribute_fixture_class")),
                };
                let value = hex(lines.next().ok_or(Failure::Input("missing_key_value"))?, length)
                    .map_err(Failure::Input)?;
                if value.len() != length { return Err(Failure::Input("typed_secret_size")); }
                Object::TypedSecret { key_type, value, mac }
            }
            None => return Err(Failure::Input("attribute_fixture_class")),
        })
    }

    pub(super) fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        let known = b"0123456789abcdef";
        Ok(match self {
            Object::FieldTemplate(fields) => {
                let inputs: Vec<_> = fields.iter().map(Field::input).collect();
                owner.create(&inputs, AttributeTemplateLimits {
                    maximum_attributes: fields.len(),
                    maximum_depth: 0,
                    maximum_value_bytes: fields.iter().map(Field::bytes).sum(),
                })?
            }
            Object::Data => {
                let attrs = [
                    AttributeInput { attribute: StandardAttribute::CLASS.into(), value: AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64) },
                    AttributeInput { attribute: StandardAttribute::PRIVATE.into(), value: AttributeInputValue::Boolean(false) },
                    AttributeInput { attribute: StandardAttribute::TOKEN.into(), value: AttributeInputValue::Boolean(false) },
                    AttributeInput { attribute: StandardAttribute::VALUE.into(), value: AttributeInputValue::Bytes(known) },
                ];
                owner.create(&attrs, key_wrap_fixture::limits(attrs.len(), known.len()))?
            }
            Object::Aes => owner.import_secret(known, fe11_sys::CKK_AES,
                [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT])?,
            Object::Secret => owner.import_secret(known, fe11_sys::CKK_GENERIC_SECRET,
                [StandardAttribute::SIGN, StandardAttribute::VERIFY])?,
            Object::TypedSecret { key_type, value, mac } => owner.import_secret(value, *key_type,
                if *mac { [StandardAttribute::SIGN, StandardAttribute::VERIFY] }
                else { [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT] })?,
            Object::PublicRsa(parts) => owner.import_rsa_public_usage_enabled(
                &parts[0], &parts[1], StandardAttribute::VERIFY, true)?,
            Object::PrivateRsa(parts) => owner.import_rsa_private(parts, StandardAttribute::SIGN)?,
        })
    }

}
