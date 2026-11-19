// SPDX-License-Identifier: Apache-2.0
//! Read a real DH domain before importing and using its private key.
use super::super::{
    configuration::Configuration, derived_value, derived_value_case::DerivedValueCase,
    dh_fixture::Vector, module_controls, object_owner::Owner, outcome::Failure, report::Report,
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

fn read(
    owner: &Owner,
    key: &NativeObjectRef,
    attribute: StandardAttribute,
    capacity: usize,
) -> std::result::Result<FlatAttributeObservation, Failure> {
    let plan = FlatAttributeReadPlan::Buffer { capacity };
    let value = match owner {
        Owner::Session(s) => s.read_flat_attribute(key, attribute, plan),
        Owner::Advanced(s) => s.read_flat_attribute(key, attribute, plan),
    }?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("dh_domain_read_status"));
    }
    Ok(value)
}

fn import_parameters(owner: &Owner, v: &Vector, public_key: bool) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let mut fields = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(if public_key { fe11_sys::CKO_PUBLIC_KEY } else { fe11_sys::CKO_DOMAIN_PARAMETERS } as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(fe11_sys::CKK_DH as u64),
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
            StandardAttribute::PRIME,
            AttributeInputValue::Bytes(&v.prime),
        ),
        attr(StandardAttribute::BASE, AttributeInputValue::Bytes(&v.base)),
    ];
    if public_key {
        fields.push(attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(&v.peer)));
    }
    owner.create(
        &fields,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: fields.len(),
            maximum_value_bytes: 32 + v.prime.len() + v.base.len() + if public_key { v.peer.len() } else { 0 },
        },
    )
}

fn body(
    owner: &Owner,
    v: &mut Vector,
    public_key: bool,
    objects: &mut Vec<NativeObjectRef>,
    derived: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    objects.push(import_parameters(owner, v, public_key)?);
    for (attribute, wanted) in [
        (
            StandardAttribute::CLASS,
            if public_key { fe11_sys::CKO_PUBLIC_KEY } else { fe11_sys::CKO_DOMAIN_PARAMETERS } as u64,
        ),
        (StandardAttribute::KEY_TYPE, fe11_sys::CKK_DH as u64),
    ] {
        if read(
            owner,
            &objects[0],
            attribute,
            std::mem::size_of::<fe11_sys::CK_ULONG>(),
        )?
        .unsigned()?
            != wanted
        {
            return Err(Failure::Oracle("dh_domain_class_and_type"));
        }
    }
    for (attribute, bytes) in [
        (StandardAttribute::PRIME, &mut v.prime),
        (StandardAttribute::BASE, &mut v.base),
    ] {
        let result = read(owner, &objects[0], attribute, bytes.len())?;
        match result.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == bytes.as_slice() => {
                *bytes = value.as_bytes().to_vec();
            }
            _ => return Err(Failure::Oracle("dh_domain_parameter_bytes")),
        }
    }
    if public_key {
        // PKCS #3 takes the peer value as mechanism bytes. Read those bytes
        // from the imported public object before invoking the private key.
        let peer = read(owner, &objects[0], StandardAttribute::VALUE, v.peer.len())?;
        match peer.value {
            FlatAttributeValue::Available(bytes) if bytes.as_bytes() == v.peer => {
                v.peer = bytes.as_bytes().to_vec();
            }
            _ => return Err(Failure::Oracle("dh_imported_peer_value")),
        }
    }
    // The imported key consumes the bytes read above, not an unobserved
    // parallel copy. The shared-secret oracle remains the published vector.
    objects.push(v.import(owner)?);
    derived_value::check(owner, &objects[1], v.parameters(), v.expected(), derived)
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    public_key: bool,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = Vec::new();
    let mut derived = None;
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let v = Vector::read(path)?;
        owner = Some(Owner::open(&module, config, v.advanced())?);
        Ok(v)
    })();
    let (setup_result, checked) = match setup {
        Ok(mut v) => (
            Ok(()),
            body(
                owner.as_ref().expect("owner established"),
                &mut v,
                public_key,
                &mut objects,
                &mut derived,
            ),
        ),
        Err(error) => (Err(error), Ok(())),
    };
    let mut cleanup = Vec::new();
    if let Some(active) = &owner {
        // Retain the derived set before observing it and attempt every cleanup
        // independently, even if an earlier destroy was refused.
        let derived_keys = derived.as_ref().map_or(&[][..], |set| set.as_slice());
        for key in derived_keys.iter().chain(objects.iter().rev()) {
            let result = match active {
                Owner::Session(s) => s.destroy_native_object(key),
                Owner::Advanced(s) => s.destroy_native_object(key),
            };
            if let Err(error) = result {
                cleanup.push(error.into());
            }
        }
        cleanup.extend(active.close(None));
    }
    drop(derived);
    drop(objects);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup_result, checked, cleanup)
}
