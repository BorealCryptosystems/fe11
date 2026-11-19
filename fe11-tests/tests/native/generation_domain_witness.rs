// SPDX-License-Identifier: Apache-2.0
//! Generated domain bytes feed real key generation and native key use.
use super::super::{
    generation_fixture::{Field, Value},
    outcome::Failure,
};
use fe11::*;

fn attr(attribute: StandardAttribute, value: AttributeInputValue<'_>) -> AttributeInput<'_> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}

fn request<'a>(fields: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes: fields,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: fields.len(),
            maximum_value_bytes: 2048,
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}

fn read(
    session: &Session,
    object: &NativeObjectRef,
    attribute: StandardAttribute,
) -> std::result::Result<Vec<u8>, Failure> {
    let value = session.read_flat_attribute(
        object,
        attribute,
        FlatAttributeReadPlan::Buffer { capacity: 512 },
    )?;
    if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generated_domain_read_status"));
    }
    match value.value {
        FlatAttributeValue::Available(bytes) => Ok(bytes.as_bytes().to_vec()),
        _ => Err(Failure::Oracle("generated_domain_value_unavailable")),
    }
}

fn retain<T>(
    created: CreatedObjects<T>,
    retained: &mut Vec<CreatedObjectSet>,
    count: usize,
) -> std::result::Result<Vec<NativeObjectRef>, Failure> {
    retained.push(created.objects);
    if created.remainder.is_some() {
        return Err(Failure::Oracle("generated_domain_auxiliary_owner"));
    }
    created.observation?;
    let objects = retained
        .last()
        .ok_or(Failure::Input("generated_domain_ownership"))?
        .as_slice();
    if objects.len() != count {
        return Err(Failure::Oracle("generated_domain_output_count"));
    }
    Ok(objects.to_vec())
}

fn pair(
    session: &Session,
    parameters: &[(StandardAttribute, Vec<u8>)],
    dsa: bool,
    retained: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<Vec<NativeObjectRef>, Failure> {
    let key_type = if dsa {
        fe11_sys::CKK_DSA
    } else {
        fe11_sys::CKK_DH
    };
    let mut public = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(key_type as u64),
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
            if dsa {
                StandardAttribute::VERIFY
            } else {
                StandardAttribute::DERIVE
            },
            AttributeInputValue::Boolean(true),
        ),
    ];
    public.extend(
        parameters
            .iter()
            .map(|(attribute, bytes)| attr(*attribute, AttributeInputValue::Bytes(bytes))),
    );
    let private = [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(key_type as u64),
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
            if dsa {
                StandardAttribute::SIGN
            } else {
                StandardAttribute::DERIVE
            },
            AttributeInputValue::Boolean(true),
        ),
    ];
    let generator = if dsa {
        KeyPairGenerator::DSA_KEY_PAIR_GEN
    } else {
        KeyPairGenerator::DH_PKCS_KEY_PAIR_GEN
    };
    let objects = retain(
        session.generate_native_key_pair(generator, request(&public), request(&private))?,
        retained,
        2,
    )?;
    for (object, class) in objects
        .iter()
        .zip([fe11_sys::CKO_PUBLIC_KEY, fe11_sys::CKO_PRIVATE_KEY])
    {
        for (attribute, expected) in [
            (StandardAttribute::CLASS, class),
            (StandardAttribute::KEY_TYPE, key_type),
        ] {
            if read(session, object, attribute)? != expected.to_ne_bytes() {
                return Err(Failure::Oracle("generated_domain_pair_identity"));
            }
        }
        for (attribute, expected) in parameters {
            if read(session, object, *attribute)? != *expected {
                return Err(Failure::Oracle("generated_domain_pair_parameter_identity"));
            }
        }
    }
    Ok(objects)
}

fn derive(
    session: &Session,
    private: &NativeObjectRef,
    peer: &[u8],
    width: usize,
    retained: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<AttributeBytes, Failure> {
    let attributes = super::super::derived_value::template_attributes(width);
    let objects = retain(
        session.derive_native_key(
            private,
            NativeKeyDerivation::DhPkcs { peer_public: peer },
            request(&attributes),
        )?,
        retained,
        1,
    )?;
    let observed = session.read_flat_attribute(
        &objects[0],
        StandardAttribute::VALUE,
        FlatAttributeReadPlan::Buffer { capacity: width },
    )?;
    if observed.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generated_dh_secret_read_status"));
    }
    match observed.value {
        FlatAttributeValue::Available(value) if value.as_bytes().len() == width => Ok(value),
        _ => Err(Failure::Oracle("generated_dh_secret_width")),
    }
}

pub(super) fn check(
    session: &Session,
    domain: &NativeObjectRef,
    fields: &[Field],
    dsa: bool,
) -> std::result::Result<(), Failure> {
    let bits = fields
        .iter()
        .find_map(|field| match (&field.attribute, &field.value) {
            (attribute, Value::Unsigned(value)) if *attribute == StandardAttribute::PRIME_BITS => {
                Some(*value)
            }
            _ => None,
        })
        .ok_or(Failure::Input("generated_domain_requested_bits"))?;
    if ![512, 1024].contains(&bits) {
        return Err(Failure::Input("generated_domain_fixture_size"));
    }
    let mut parameters = Vec::new();
    let names: &[StandardAttribute] = if dsa {
        &[
            StandardAttribute::PRIME,
            StandardAttribute::SUBPRIME,
            StandardAttribute::BASE,
        ]
    } else {
        &[StandardAttribute::PRIME, StandardAttribute::BASE]
    };
    for attribute in names {
        parameters.push((*attribute, read(session, domain, *attribute)?));
    }
    let prime = &parameters[0].1;
    if prime.len() != (bits / 8) as usize
        || prime[0] & 0x80 == 0
        || parameters.iter().any(|(_, bytes)| bytes.is_empty())
        || (dsa && parameters[1].1.len() != 20)
    {
        return Err(Failure::Oracle("generated_domain_parameter_dimensions"));
    }
    let mut retained = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        let first = pair(session, &parameters, dsa, &mut retained)?;
        if dsa {
            let message = [0x5au8; 20];
            let parts = [message.as_slice()];
            let limits = InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: message.len(),
            };
            let mechanism =
                || NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::DSA);
            let signature = session.sign_native(
                &first[1],
                mechanism(),
                MessageRoute::Single,
                &parts,
                limits,
                40,
                None,
            )?;
            if signature.as_bytes().len() != 40 {
                return Err(Failure::Oracle("generated_dsa_signature_width"));
            }
            session.verify_native(
                &first[0],
                mechanism(),
                MessageRoute::Single,
                &parts,
                signature.as_bytes(),
                limits,
                None,
            )?;
        } else {
            let second = pair(session, &parameters, false, &mut retained)?;
            let public_a = read(session, &first[0], StandardAttribute::VALUE)?;
            let public_b = read(session, &second[0], StandardAttribute::VALUE)?;
            let a = derive(session, &first[1], &public_b, prime.len(), &mut retained)?;
            let b = derive(session, &second[1], &public_a, prime.len(), &mut retained)?;
            if a.as_bytes() != b.as_bytes() {
                return Err(Failure::Oracle("generated_dh_bidirectional_agreement"));
            }
        }
        Ok(())
    })();
    // Every returned set is retained before a fallible observation. Attempt all
    // destructions even when the witness fails; never substitute a searched key.
    let mut cleanup = None;
    for objects in &retained {
        for object in objects.as_slice() {
            if let Err(error) = session.destroy_native_object(object) {
                if cleanup.is_none() {
                    cleanup = Some(Failure::from(error));
                }
            }
        }
    }
    body?;
    if let Some(error) = cleanup {
        return Err(error);
    }
    Ok(())
}
