// SPDX-License-Identifier: Apache-2.0
//! Dedicated HMAC object types retain their exact imported representation.
use super::{Failure, Owner};
use fe11::*;

pub(super) fn for_algorithm(
    algorithm: NativeMacAlgorithm,
) -> std::result::Result<fe11_sys::CK_KEY_TYPE, Failure> {
    Ok(match algorithm {
        NativeMacAlgorithm::MD5_HMAC => fe11_sys::CKK_MD5_HMAC,
        NativeMacAlgorithm::SHA_1_HMAC => fe11_sys::CKK_SHA_1_HMAC,
        NativeMacAlgorithm::SHA224_HMAC => fe11_sys::CKK_SHA224_HMAC,
        NativeMacAlgorithm::SHA256_HMAC => fe11_sys::CKK_SHA256_HMAC,
        NativeMacAlgorithm::SHA384_HMAC => fe11_sys::CKK_SHA384_HMAC,
        NativeMacAlgorithm::SHA512_HMAC => fe11_sys::CKK_SHA512_HMAC,
        NativeMacAlgorithm::SHA3_224_HMAC => fe11_sys::CKK_SHA3_224_HMAC,
        NativeMacAlgorithm::SHA3_256_HMAC => fe11_sys::CKK_SHA3_256_HMAC,
        NativeMacAlgorithm::SHA3_384_HMAC => fe11_sys::CKK_SHA3_384_HMAC,
        NativeMacAlgorithm::SHA3_512_HMAC => fe11_sys::CKK_SHA3_512_HMAC,
        _ => return Err(Failure::Input("dedicated_hmac_key_type")),
    })
}

pub(super) fn check(
    owner: &Owner,
    key: &NativeObjectRef,
    algorithm: NativeMacAlgorithm,
    bytes: &[u8],
) -> std::result::Result<(), Failure> {
    let read = |attribute, capacity| -> std::result::Result<FlatAttributeObservation, Failure> {
        let plan = FlatAttributeReadPlan::Buffer { capacity };
        let value = match owner {
            Owner::Session(session) => session.read_flat_attribute(key, attribute, plan)?,
            Owner::Advanced(session) => session.read_flat_attribute(key, attribute, plan)?,
        };
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("dedicated_hmac_read_code"));
        }
        Ok(value)
    };
    let width = std::mem::size_of::<fe11_sys::CK_ULONG>();
    for (attribute, expected) in [
        (StandardAttribute::CLASS, fe11_sys::CKO_SECRET_KEY as u64),
        (
            StandardAttribute::KEY_TYPE,
            for_algorithm(algorithm)? as u64,
        ),
        (StandardAttribute::VALUE_LEN, bytes.len() as u64),
    ] {
        if read(attribute, width)?.unsigned()? != expected {
            return Err(Failure::Oracle("dedicated_hmac_unsigned_attribute"));
        }
    }
    for (attribute, expected) in [
        (StandardAttribute::TOKEN, false),
        (StandardAttribute::PRIVATE, false),
        (StandardAttribute::SIGN, true),
        (StandardAttribute::VERIFY, true),
    ] {
        if read(attribute, 1)?.boolean()? != expected {
            return Err(Failure::Oracle("dedicated_hmac_boolean_attribute"));
        }
    }
    Ok(())
}
