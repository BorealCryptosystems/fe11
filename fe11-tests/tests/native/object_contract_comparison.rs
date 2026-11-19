// SPDX-License-Identifier: Apache-2.0
//! Compare managed and flat reads of the same exact native object reference.
use super::{Failure, LABEL, VALUE};
use fe11::*;

fn flat(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
) -> Result<FlatAttributeObservation> {
    session.read_flat_attribute(
        object,
        attribute,
        FlatAttributeReadPlan::Buffer { capacity: 64 },
    )
}

pub(super) fn execute(
    session: &Session,
    object: &NativeObjectRef,
    sensitive: bool,
) -> std::result::Result<(), Failure> {
    let mut admission = super::super::object_fixture::public_key_options(b"comparison").admission;
    admission.observation.private = false;
    admission.observation.token = false;
    admission.observation.verify = false;
    // Reuse the exact creation reference: no search can substitute another key.
    let managed = session.observe_native_object(
        object,
        ManagedClass::SecretKey,
        admission,
        ContentObservation::NotRequested,
    )?;
    let plan = AttributeReadPlan {
        maximum_bytes: 64,
        clarification: AttributeClarification::BatchOnly,
    };
    let values =
        session.managed_attributes(&managed, &[Attribute::Class, Attribute::Label], plan)?;
    let class = fe11_sys::CKO_SECRET_KEY.to_ne_bytes();
    for (index, attribute, expected) in [
        (0, StandardAttribute::CLASS, class.as_slice()),
        (1, StandardAttribute::LABEL, LABEL),
    ] {
        let native = flat(session, object, attribute)?;
        if native.calls != (AttributeReadCalls::Direct { code: 0 })
            || !matches!(&native.value, FlatAttributeValue::Available(bytes) if bytes.as_bytes() == expected)
            || !matches!(&values[index], AttributeValue::Available(bytes) if bytes == expected)
        {
            return Err(Failure::Oracle("managed_native_metadata_identity"));
        }
    }
    let content =
        session.observe_managed_content(&managed, ContentReadPlan::Value { maximum_bytes: 64 })?;
    let native = flat(session, object, StandardAttribute::VALUE)?;
    if sensitive {
        if !matches!(content, ProtectedContent::Unavailable { attribute, cause: AttributeUnavailableCause::Sensitive } if attribute == fe11_sys::CKA_VALUE as u64)
            || !matches!(
                native.value,
                FlatAttributeValue::Unavailable(AttributeUnavailableCause::Sensitive)
            )
            || native.calls
                != (AttributeReadCalls::Direct {
                    code: fe11_sys::CKR_ATTRIBUTE_SENSITIVE as u64,
                })
        {
            return Err(Failure::Oracle("managed_native_sensitive_value_identity"));
        }
    } else if !matches!(content, ProtectedContent::Available(bytes) if bytes.as_slice() == VALUE)
        || !matches!(native.value, FlatAttributeValue::Available(bytes) if bytes.as_bytes() == VALUE)
        || native.calls != (AttributeReadCalls::Direct { code: 0 })
    {
        return Err(Failure::Oracle("managed_native_content_identity"));
    }
    // BatchOnly deliberately keeps an aggregate metadata refusal indeterminate,
    // even for one field. The individual flat read establishes its exact cause.
    let missing = session.managed_attributes(&managed, &[Attribute::Modulus], plan)?;
    let native = flat(session, object, StandardAttribute::MODULUS)?;
    if !matches!(missing.as_slice(), [AttributeValue::Indeterminate])
        || !matches!(
            native.value,
            FlatAttributeValue::Unavailable(AttributeUnavailableCause::Unsupported)
        )
        || native.calls
            != (AttributeReadCalls::Direct {
                code: fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID as u64,
            })
    {
        return Err(Failure::Oracle("managed_native_unsupported_identity"));
    }
    Ok(())
}
