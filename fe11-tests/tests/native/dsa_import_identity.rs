// SPDX-License-Identifier: Apache-2.0
//! Domain and key identities remain exact across import, readback and use.
use super::super::{
    classical_sign_fixture::Vector, classical_sign_operation, configuration::Configuration,
    module_controls, object_owner::Owner, outcome::Failure, report::Report,
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
        return Err(Failure::Oracle("dsa_identity_native_read_code"));
    }
    Ok(value)
}

fn exact_bytes(
    owner: &Owner,
    key: &NativeObjectRef,
    attribute: StandardAttribute,
    expected: &[u8],
) -> std::result::Result<Vec<u8>, Failure> {
    match read(owner, key, attribute, expected.len())?.value {
        FlatAttributeValue::Available(value) if value.as_bytes() == expected => {
            Ok(value.as_bytes().to_vec())
        }
        _ => Err(Failure::Oracle("dsa_identity_parameter_bytes")),
    }
}

fn class(
    owner: &Owner,
    key: &NativeObjectRef,
    expected: fe11_sys::CK_OBJECT_CLASS,
) -> std::result::Result<(), Failure> {
    for (attribute, wanted) in [
        (StandardAttribute::CLASS, expected as u64),
        (StandardAttribute::KEY_TYPE, fe11_sys::CKK_DSA as u64),
    ] {
        if read(
            owner,
            key,
            attribute,
            std::mem::size_of::<fe11_sys::CK_ULONG>(),
        )?
        .unsigned()?
            != wanted
        {
            return Err(Failure::Oracle("dsa_identity_class_and_type"));
        }
    }
    Ok(())
}

fn domain(owner: &Owner, v: &Vector) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let mut fields = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_DOMAIN_PARAMETERS as u64),
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
    ];
    for (attribute, bytes) in [
        StandardAttribute::PRIME,
        StandardAttribute::SUBPRIME,
        StandardAttribute::BASE,
    ]
    .into_iter()
    .zip(&v.parameters)
    {
        fields.push(attr(attribute, AttributeInputValue::Bytes(bytes)));
    }
    owner.create(
        &fields,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: fields.len(),
            maximum_value_bytes: 32 + v.parameters.iter().take(3).map(Vec::len).sum::<usize>(),
        },
    )
}

fn body(
    owner: &Owner,
    v: &mut Vector,
    objects: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    objects.push(domain(owner, v)?);
    class(owner, &objects[0], fe11_sys::CKO_DOMAIN_PARAMETERS)?;
    // Subsequent imports use the bytes actually read from the domain object,
    // after comparison to the published values. A parallel fixture value alone
    // would not demonstrate that this domain can feed the public key routes.
    for (i, attribute) in [
        StandardAttribute::PRIME,
        StandardAttribute::SUBPRIME,
        StandardAttribute::BASE,
    ]
    .into_iter()
    .enumerate()
    {
        v.parameters[i] = exact_bytes(owner, &objects[0], attribute, &v.parameters[i])?;
    }
    objects.push(classical_sign_operation::import_usage(
        owner, v, false, true,
    )?);
    class(owner, &objects[1], fe11_sys::CKO_PUBLIC_KEY)?;
    for (attribute, expected) in [
        StandardAttribute::PRIME,
        StandardAttribute::SUBPRIME,
        StandardAttribute::BASE,
        StandardAttribute::VALUE,
    ]
    .into_iter()
    .zip(&v.parameters)
    {
        exact_bytes(owner, &objects[1], attribute, expected)?;
    }
    objects.push(classical_sign_operation::import(owner, v)?);
    class(owner, &objects[2], fe11_sys::CKO_PRIVATE_KEY)?;
    for (attribute, expected) in [
        StandardAttribute::PRIME,
        StandardAttribute::SUBPRIME,
        StandardAttribute::BASE,
    ]
    .into_iter()
    .zip(&v.parameters)
    {
        exact_bytes(owner, &objects[2], attribute, expected)?;
    }
    let parts = [v.input.as_slice()];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: v.input.len(),
    };
    owner.verify_parameters(
        &objects[1],
        NativeSignatureParameters::Parameterless(v.algorithm),
        MessageRoute::Single,
        &parts,
        &v.signature,
        limits,
    )?;
    classical_sign_operation::check(owner, &objects[2], v)?;
    // The shared signer writes only the public signature for the independent
    // reference process. Bound that file before reading and verifying it here.
    let path = Path::new("public-classical-signatures.bin");
    let metadata = path
        .symlink_metadata()
        .map_err(|_| Failure::Input("signature_metadata"))?;
    if !metadata.is_file() || metadata.len() != 40 {
        return Err(Failure::Oracle("dsa_signature_output_width"));
    }
    let signature = std::fs::read(path).map_err(|_| Failure::Input("signature_read"))?;
    owner.verify_parameters(
        &objects[1],
        NativeSignatureParameters::Parameterless(v.algorithm),
        MessageRoute::Single,
        &parts,
        &signature,
        limits,
    )?;
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = Vec::new();
    let setup = (|| -> std::result::Result<Vector, Failure> {
        let v = Vector::read(path)?;
        if v.ecdsa
            || v.algorithm != NativeSignatureAlgorithm::DSA
            || v.multipart
            || v.width != 20
            || v.parameters[0].len() != 128
            || v.parameters[1].len() != 20
        {
            return Err(Failure::Input("dsa_1024_160_identity_fixture"));
        }
        owner = Some(Owner::open(&module, config, v.advanced)?);
        Ok(v)
    })();
    let (setup_result, checked) = match setup {
        Ok(mut v) => (
            Ok(()),
            body(
                owner.as_ref().expect("owner established"),
                &mut v,
                &mut objects,
            ),
        ),
        Err(error) => (Err(error), Ok(())),
    };
    let mut cleanup = Vec::new();
    if let Some(active) = &owner {
        // Retain each created handle before any read or later creation. One
        // destroy failure must not suppress destruction of the other objects.
        for key in objects.iter().rev() {
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
    drop(objects);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup_result, checked, cleanup)
}
