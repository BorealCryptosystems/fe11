// SPDX-License-Identifier: Apache-2.0
//! Native usability of a freshly generated secret key, not a known-answer claim.
//! The random key remains inside the provider; no exported key bytes are logged.
use super::super::outcome::Failure;
use fe11::*;

pub(super) fn check(
    session: &Session,
    key: &NativeObjectRef,
    generator: u64,
) -> std::result::Result<(), Failure> {
    if generator == fe11_sys::CKM_GENERIC_SECRET_KEY_GEN as u64 {
        let parameters = || NativeMacParameters::Full(NativeMacAlgorithm::MD5_HMAC);
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let parts = [b"abc".as_slice()];
        let mac = session.compute_native_mac(
            key,
            parameters(),
            MessageRoute::Single,
            &parts,
            limits,
            16,
            None,
        )?;
        if mac.as_bytes().len() != 16 {
            return Err(Failure::Oracle("generated_secret_mac_width"));
        }
        session.verify_native_mac(
            key,
            parameters(),
            MessageRoute::Single,
            &parts,
            mac.as_bytes(),
            limits,
            None,
        )?;
        return Ok(());
    }
    let (parameters, width) = match generator {
        n if n == fe11_sys::CKM_AES_KEY_GEN as u64 => {
            (CipherParameters::Aes(AesCipherParameters::Ecb), 16)
        }
        n if n == fe11_sys::CKM_DES_KEY_GEN as u64 => (CipherParameters::DesEcb, 8),
        n if n == fe11_sys::CKM_DES2_KEY_GEN as u64 || n == fe11_sys::CKM_DES3_KEY_GEN as u64 => {
            (CipherParameters::Des3Ecb, 8)
        }
        _ => return Err(Failure::Input("generated_secret_witness_mechanism")),
    };
    let input = [0x42; 16];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: width,
    };
    let encrypted = session.encrypt_cipher(
        CipherKeyReference::Secret(key),
        parameters,
        MessageRoute::Single,
        &[&input[..width]],
        limits,
    )?;
    if encrypted.as_bytes().len() != width {
        return Err(Failure::Oracle("generated_secret_cipher_width"));
    }
    let plain = session.decrypt_cipher(
        CipherKeyReference::Secret(key),
        parameters,
        MessageRoute::Single,
        &[encrypted.as_bytes()],
        limits,
    )?;
    if plain.as_bytes() != &input[..width] {
        return Err(Failure::Oracle("generated_secret_cipher_roundtrip"));
    }
    Ok(())
}
