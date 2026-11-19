// SPDX-License-Identifier: Apache-2.0
//! Store an exact GOST secret-key object and exercise its disabled MAC mechanism.
use super::{attr, limits, template, Failure};
use fe11::*;

// RFC 4357 section 10.2, id-Gost28147-89-CryptoPro-A-ParamSet.
const ENCRYPTION_PARAMS: &[u8] = &[6, 7, 42, 133, 3, 2, 2, 31, 1];
const PUBLIC_BYTES: &[u8] = b"0123456789abcdef0123456789abcdef";

pub(super) fn check(session: &Session, owned: &mut Vec<NativeObjectRef>) -> std::result::Result<(), Failure> {
    let mut fields = template("gost-secret-storage");
    for field in &mut fields {
        if field.attribute == StandardAttribute::KEY_TYPE {
            field.value = AttributeInputValue::Unsigned(fe11_sys::CKK_GOST28147 as u64);
        } else if field.attribute == StandardAttribute::VALUE {
            field.value = AttributeInputValue::Bytes(PUBLIC_BYTES);
        }
    }
    fields.push(attr(StandardAttribute::GOST28147_PARAMS, AttributeInputValue::Bytes(ENCRYPTION_PARAMS)));
    owned.push(session.create_native_object(&fields, limits(fields.len()))?);
    let key = owned.last().ok_or(Failure::Oracle("gost_secret_owner"))?;
    let width = std::mem::size_of::<fe11_sys::CK_ULONG>();
    let read = |attribute, capacity| -> std::result::Result<FlatAttributeObservation, Failure> {
        let entry = session.read_flat_attribute(key, attribute, FlatAttributeReadPlan::Buffer {capacity})?;
        if entry.calls != (AttributeReadCalls::Direct {code: 0}) {
            return Err(Failure::Oracle("gost_secret_read"));
        }
        Ok(entry)
    };
    if read(StandardAttribute::CLASS, width)?.unsigned()? != fe11_sys::CKO_SECRET_KEY as u64
        || read(StandardAttribute::KEY_TYPE, width)?.unsigned()? != fe11_sys::CKK_GOST28147 as u64
        || !read(StandardAttribute::SIGN, 1)?.boolean()?
        || !read(StandardAttribute::VERIFY, 1)?.boolean()?
    {
        return Err(Failure::Oracle("gost_secret_identity_or_usage"));
    }
    for (attribute, expected) in [(StandardAttribute::VALUE, PUBLIC_BYTES),
        (StandardAttribute::GOST28147_PARAMS, ENCRYPTION_PARAMS)] {
        match read(attribute, expected.len())?.value {
            FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("gost_secret_readback")),
        }
    }
    // This fixture is selected only for the configuration without GOST mechanisms.
    // Object storage succeeds independently of whether the provider can use the key.
    let result = session.compute_native_mac(
        key, NativeMacParameters::GostR3411 { oid: Some(crate::absent_mechanism_fixture::DIGEST_OID) },
        MessageRoute::Single, &[b"abc"], InputLimits {maximum_parts: 1, maximum_total_bytes: 3}, 32, None);
    match result {
        Err(Error::Native {function: "C_SignInit", code, ..}) if code == fe11_sys::CKR_MECHANISM_INVALID as u64 => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("unexpected_gost_mac_success")),
    }
}
