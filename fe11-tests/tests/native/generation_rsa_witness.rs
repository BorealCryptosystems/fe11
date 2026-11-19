// SPDX-License-Identifier: Apache-2.0
//! Generated RSA modulus identity and signature usability, independently checked.
use super::super::{
    generation_fixture::{Field, Value},
    outcome::Failure,
};
use fe11::*;
use std::{fs::OpenOptions, io::Write};

pub(super) fn check(
    session: &Session,
    public: &NativeObjectRef,
    private: &NativeObjectRef,
    fields: &[Field],
) -> std::result::Result<(), Failure> {
    let bits = fields
        .iter()
        .find_map(|field| {
            if field.attribute != StandardAttribute::MODULUS_BITS {
                return None;
            }
            match field.value {
                Value::Unsigned(n) => Some(n),
                _ => None,
            }
        })
        .ok_or(Failure::Input("generated_rsa_requested_bits"))?;
    if ![512, 1024, 2048, 3072, 4096, 16384].contains(&bits) {
        return Err(Failure::Input("generated_rsa_fixture_size"));
    }
    let width = (bits / 8) as usize;
    let read = session.read_flat_attribute(
        public,
        StandardAttribute::MODULUS,
        FlatAttributeReadPlan::Buffer { capacity: width },
    )?;
    if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generated_rsa_modulus_status"));
    }
    let FlatAttributeValue::Available(modulus) = read.value else {
        return Err(Failure::Oracle("generated_rsa_modulus_unavailable"));
    };
    if modulus.as_bytes().len() != width || modulus.as_bytes()[0] & 0x80 == 0 {
        return Err(Failure::Oracle("generated_rsa_modulus_bits"));
    }
    let parameters =
        || NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS);
    let parts = [b"abc".as_slice()];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    let signature = session.sign_native(
        private,
        parameters(),
        MessageRoute::Single,
        &parts,
        limits,
        width,
        None,
    )?;
    if signature.as_bytes().len() != width {
        return Err(Failure::Oracle("generated_rsa_signature_width"));
    }
    session.verify_native(
        public,
        parameters(),
        MessageRoute::Single,
        &parts,
        signature.as_bytes(),
        limits,
        None,
    )?;
    // Only the public modulus and signature cross into the independent checker.
    // The generated private attributes never leave the module through this path.
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open("public-generated-rsa.bin")
        .map_err(|_| Failure::Input("generated_rsa_output_create"))?;
    output
        .write_all(modulus.as_bytes())
        .and_then(|_| output.write_all(signature.as_bytes()))
        .and_then(|_| output.flush())
        .map_err(|_| Failure::Input("generated_rsa_output_write"))?;
    Ok(())
}
