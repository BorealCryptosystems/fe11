// SPDX-License-Identifier: Apache-2.0
//! Requested generation attributes and normative creation history, read explicitly.
use super::{
    generation_fixture::{Field, Value},
    outcome::Failure,
};
use fe11::*;

fn read(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
    capacity: usize,
) -> std::result::Result<FlatAttributeObservation, Failure> {
    let value = session.read_flat_attribute(
        object,
        attribute,
        FlatAttributeReadPlan::Buffer { capacity },
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generated_attribute_native_status"));
    }
    Ok(value)
}

fn unsigned_bytes(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len())..]
}

pub fn check(
    session: &Session,
    object: &NativeObjectRef,
    fields: &[Field],
    mechanism: u64,
) -> std::result::Result<(), Failure> {
    for field in fields {
        let value = read(session, object, field.attribute, field.bytes())?;
        let equal = match &field.value {
            Value::Boolean(expected) => value.boolean()? == *expected,
            Value::Unsigned(expected) => value.unsigned()? == *expected,
            Value::Bytes(expected) => match value.value {
                FlatAttributeValue::Available(bytes) => {
                    // PKCS#11 big integers can omit redundant leading zeroes.
                    // OIDs, labels and every other byte string remain exact.
                    if [
                        StandardAttribute::PRIME,
                        StandardAttribute::SUBPRIME,
                        StandardAttribute::BASE,
                        StandardAttribute::PUBLIC_EXPONENT,
                    ]
                    .contains(&field.attribute)
                    {
                        unsigned_bytes(bytes.as_bytes()) == unsigned_bytes(expected)
                    } else {
                        bytes.as_bytes() == expected
                    }
                }
                _ => false,
            },
        };
        if !equal {
            return Err(Failure::Oracle("generated_attribute_value"));
        }
    }
    let class = read(session, object, StandardAttribute::CLASS, 8)?.unsigned()?;
    if class != fe11_sys::CKO_DOMAIN_PARAMETERS as u64 {
        if !read(session, object, StandardAttribute::LOCAL, 1)?.boolean()?
            || read(session, object, StandardAttribute::KEY_GEN_MECHANISM, 8)?.unsigned()?
                != mechanism
        {
            return Err(Failure::Oracle("generated_key_origin"));
        }
    }
    if class == fe11_sys::CKO_SECRET_KEY as u64 || class == fe11_sys::CKO_PRIVATE_KEY as u64 {
        let sensitive = read(session, object, StandardAttribute::SENSITIVE, 1)?.boolean()?;
        let extractable = read(session, object, StandardAttribute::EXTRACTABLE, 1)?.boolean()?;
        if read(session, object, StandardAttribute::ALWAYS_SENSITIVE, 1)?.boolean()? != sensitive
            || read(session, object, StandardAttribute::NEVER_EXTRACTABLE, 1)?.boolean()?
                == extractable
        {
            return Err(Failure::Oracle("generated_key_history"));
        }
    }
    Ok(())
}
