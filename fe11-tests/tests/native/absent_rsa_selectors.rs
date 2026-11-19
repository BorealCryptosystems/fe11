// SPDX-License-Identifier: Apache-2.0
//! A public RSA test key reaches each unavailable native initializer.
use super::{refusal, Failure, Owner, Report};
use crate::arguments::hex;
use fe11::*;
use fe11_sys::*;
use std::io::Write;

// The components are from the shipped Wycheproof RSA-2048 wrapping fixture.
// Its first two lines describe the envelope; lines three through ten are the
// modulus, public exponent, private exponent and five CRT components.
const VECTOR: &str = include_str!(
    "../vectors/rsa-wrap-negatives/1f5104a065ddd49f3f26e84dfeb7172b567e4c1694abd94f0eade14eacd0d1a1.txt"
);

pub(super) fn import(owner: &Owner, family: &str) -> std::result::Result<NativeObjectRef, Failure> {
    let parts = VECTOR
        .lines()
        .skip(2)
        .take(8)
        .map(|field| hex(field, 256).map_err(Failure::Input))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if parts.len() != 8 || parts[0].len() != 256 || parts.iter().any(Vec::is_empty) {
        return Err(Failure::Input("rsa_fixture_components"));
    }
    match family {
        "rsa-wrap" => Ok(owner.import_rsa_public_usage_enabled(
            &parts[0], &parts[1], StandardAttribute::WRAP, true,
        )?),
        "rsa-sign" => Ok(owner.import_rsa_private(&parts, StandardAttribute::SIGN)?),
        "rsa-encrypt" => Ok(owner.import_rsa_public_usage_enabled(
            &parts[0],
            &parts[1],
            StandardAttribute::ENCRYPT,
            true,
        )?),
        _ => Err(Failure::Input("rsa_selector_family")),
    }
}

pub(super) fn observe<W: Write>(
    session: &Session,
    key: &NativeObjectRef,
    family: &str,
    number: CK_MECHANISM_TYPE,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let message = [0x35_u8; 20];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: message.len(),
    };
    if family == "rsa-encrypt" {
        let params = match number {
            CKM_RSA_PKCS_TPM_1_1 => NativeRsaCipherParameters::Tpm11Pkcs1,
            CKM_RSA_PKCS_OAEP_TPM_1_1 => NativeRsaCipherParameters::Tpm11Oaep,
            _ => return Err(Failure::Input("rsa_cipher_selector")),
        };
        return refusal(
            session.encrypt_native_rsa(key, params, &message, 256, limits),
            "C_EncryptInit",
            report,
        );
    }
    let algorithm = NativeSignatureAlgorithm::ALL
        .iter()
        .find(|v| v.mechanism_number() == number as u64)
        .ok_or(Failure::Input("rsa_signature_selector"))?;
    refusal(
        session.sign_native(
            key,
            NativeSignatureParameters::Parameterless(*algorithm),
            MessageRoute::Single,
            &[&message],
            limits,
            256,
            None,
        ),
        "C_SignInit",
        report,
    )
}
