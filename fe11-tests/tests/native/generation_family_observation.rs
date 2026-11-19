// SPDX-License-Identifier: Apache-2.0
//! Independent peer observations of generated object identities and requests.
use super::{
    generation_family_spec as spec,
    generation_fixture::{Field, Value},
    generation_observation,
    outcome::Failure,
};
use fe11::*;

const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub fn check(
    session: &Session,
    object: &NativeObjectRef,
    label: &str,
    route: &str,
) -> std::result::Result<u64, Failure> {
    let observed = session.read_flat_attribute(
        object,
        StandardAttribute::CLASS,
        FlatAttributeReadPlan::Buffer { capacity: 8 },
    )?;
    if observed.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generation_peer_class_status"));
    }
    let class = observed.unsigned()?;
    let private = class == fe11_sys::CKO_PRIVATE_KEY as u64;
    let public = class == fe11_sys::CKO_PUBLIC_KEY as u64;
    if (spec::count(route) == 1 && class != fe11_sys::CKO_SECRET_KEY as u64)
        || (spec::count(route) == 2 && !private && !public)
    {
        return Err(Failure::Oracle("generated_family_object_class"));
    }
    let unsigned = |attribute, value| Field {
        attribute,
        value: Value::Unsigned(value),
    };
    let bytes = |attribute, value: &[u8]| Field {
        attribute,
        value: Value::Bytes(value.to_vec()),
    };
    let boolean = |attribute, value| Field {
        attribute,
        value: Value::Boolean(value),
    };
    let key_type = match route {
        "typed_generate_hkdf_key" => fe11_sys::CKK_GENERIC_SECRET,
        "typed_generate_montgomery_key" => fe11_sys::CKK_EC_MONTGOMERY,
        "typed_generate_rsa_key_encryption_pair" => fe11_sys::CKK_RSA,
        "typed_generate_pqc_key_pair" => fe11_sys::CKK_ML_DSA,
        "typed_generate_kem_key_pair" => fe11_sys::CKK_ML_KEM,
        _ => fe11_sys::CKK_EC,
    };
    let mut fields = vec![
        unsigned(StandardAttribute::CLASS, class),
        unsigned(StandardAttribute::KEY_TYPE, key_type as u64),
        bytes(StandardAttribute::ID, label.as_bytes()),
        bytes(StandardAttribute::LABEL, label.as_bytes()),
        boolean(StandardAttribute::TOKEN, true),
        boolean(StandardAttribute::PRIVATE, false),
    ];
    if !public {
        fields.push(boolean(StandardAttribute::SENSITIVE, true));
        fields.push(boolean(StandardAttribute::EXTRACTABLE, false));
    }
    match route {
        "typed_generate_hkdf_key" => {
            fields.push(unsigned(StandardAttribute::VALUE_LEN, 32));
            fields.push(boolean(StandardAttribute::DERIVE, true));
        }
        "typed_generate_agreement_key" | "typed_generate_transport_agreement_key" => {
            fields.push(bytes(StandardAttribute::EC_PARAMS, P256));
            fields.push(boolean(StandardAttribute::DERIVE, true));
        }
        "typed_generate_montgomery_key" => {
            fields.push(bytes(
                StandardAttribute::EC_PARAMS,
                MontgomeryDomain::Curve25519.parameters_der(),
            ));
            fields.push(boolean(StandardAttribute::DERIVE, true));
        }
        "typed_generate_classical_key_pair" | "typed_generate_transport_signing_key_pair" => {
            fields.push(bytes(StandardAttribute::EC_PARAMS, P256));
            fields.push(boolean(
                if public {
                    StandardAttribute::VERIFY
                } else {
                    StandardAttribute::SIGN
                },
                true,
            ));
        }
        "typed_generate_rsa_key_encryption_pair" => {
            fields.push(bytes(StandardAttribute::PUBLIC_EXPONENT, &[1, 0, 1]));
            if public {
                fields.push(unsigned(StandardAttribute::MODULUS_BITS, 2048));
            }
            fields.push(boolean(
                if public {
                    StandardAttribute::WRAP
                } else {
                    StandardAttribute::UNWRAP
                },
                true,
            ));
        }
        "typed_generate_pqc_key_pair" => {
            fields.push(unsigned(
                StandardAttribute::PARAMETER_SET,
                fe11_sys::CKP_ML_DSA_44 as u64,
            ));
            fields.push(boolean(
                if public {
                    StandardAttribute::VERIFY
                } else {
                    StandardAttribute::SIGN
                },
                true,
            ));
        }
        "typed_generate_kem_key_pair" => {
            fields.push(unsigned(
                StandardAttribute::PARAMETER_SET,
                fe11_sys::CKP_ML_KEM_512 as u64,
            ));
            fields.push(boolean(
                if public {
                    StandardAttribute::ENCAPSULATE
                } else {
                    StandardAttribute::DECAPSULATE
                },
                true,
            ));
        }
        _ => return Err(Failure::Input("generation_family_observation")),
    }
    generation_observation::check(session, object, &fields, spec::mechanism(route))?;
    Ok(class)
}
