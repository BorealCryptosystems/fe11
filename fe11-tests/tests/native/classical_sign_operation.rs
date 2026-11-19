// SPDX-License-Identifier: Apache-2.0
//! Exact private-key imports and bounded public signature outputs.
use super::{classical_sign_fixture::Vector, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::OpenOptions, io::Write};

pub fn import(owner: &Owner, v: &Vector) -> Result<NativeObjectRef> {
    import_usage(owner, v, true, true)
}

/// Change only the requested usage; the key material stays the published fixture.
pub fn import_usage(
    owner: &Owner,
    v: &Vector,
    sign: bool,
    allowed: bool,
) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let mut template = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(if sign {
                fe11_sys::CKO_PRIVATE_KEY
            } else {
                fe11_sys::CKO_PUBLIC_KEY
            } as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(if v.ecdsa {
                fe11_sys::CKK_EC
            } else {
                fe11_sys::CKK_DSA
            } as u64),
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
            if sign {
                StandardAttribute::SIGN
            } else {
                StandardAttribute::VERIFY
            },
            AttributeInputValue::Boolean(allowed),
        ),
        attr(
            if !sign && v.ecdsa {
                StandardAttribute::EC_POINT
            } else {
                StandardAttribute::VALUE
            },
            AttributeInputValue::Bytes(&v.parameters[if sign { 4 } else { 3 }]),
        ),
    ];
    if v.ecdsa {
        template.push(attr(
            StandardAttribute::EC_PARAMS,
            AttributeInputValue::Bytes(&v.parameters[0]),
        ));
    } else {
        for (attribute, value) in [
            StandardAttribute::PRIME,
            StandardAttribute::SUBPRIME,
            StandardAttribute::BASE,
        ]
        .into_iter()
        .zip(&v.parameters)
        {
            template.push(attr(attribute, AttributeInputValue::Bytes(value)));
        }
    }
    owner.create(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: 19 + v.parameters.iter().map(Vec::len).sum::<usize>(),
        },
    )
}

pub fn check(owner: &Owner, key: &NativeObjectRef, v: &Vector) -> std::result::Result<(), Failure> {
    let mut offset = 0;
    let parts: Vec<_> = v
        .lengths
        .iter()
        .map(|n| {
            let part = &v.input[offset..offset + n];
            offset += n;
            part
        })
        .collect();
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: v.input.len(),
    };
    let routes =
        &[MessageRoute::Single, MessageRoute::Multipart][..if v.multipart { 2 } else { 1 }];
    let mut signatures = Vec::new();
    for &route in routes {
        let parameters = NativeSignatureParameters::Parameterless(v.algorithm);
        let signature = match owner {
            Owner::Session(s) => {
                s.sign_native(key, parameters, route, &parts, limits, 2 * v.width, None)
            }
            Owner::Advanced(s) => {
                s.sign_native(key, parameters, route, &parts, limits, 2 * v.width, None)
            }
        }?;
        if signature.as_bytes().len() != 2 * v.width {
            return Err(Failure::Oracle("classical_signature_width"));
        }
        signatures.extend_from_slice(signature.as_bytes());
    }
    // Only public signatures cross to the independent reference process.
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open("public-classical-signatures.bin")
        .map_err(|_| Failure::Input("signature_output_create"))?;
    output
        .write_all(&signatures)
        .map_err(|_| Failure::Input("signature_output_write"))?;
    output
        .flush()
        .map_err(|_| Failure::Input("signature_output_flush"))?;
    Ok(())
}
