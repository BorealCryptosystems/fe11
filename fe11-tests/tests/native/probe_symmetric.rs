// SPDX-License-Identifier: Apache-2.0
//! Real symmetric-cipher and MAC availability witnesses with public fixture keys.
use super::{
    native_support::{required, status},
    outcome::Failure,
    probe_session::ProbeSession,
    probe_template::Template,
};
use fe11_sys::*;
use std::ptr;

pub(super) fn run(owner: &mut ProbeSession, name: &str) -> Result<(), Failure> {
    let (key_type, mechanism, key_length, output_length, mac) = match name {
        "aes" => (CKK_AES, CKM_AES_ECB, 16, 16, false),
        "des" => (CKK_DES, CKM_DES_ECB, 8, 8, false),
        "des2" => (CKK_DES2, CKM_DES3_ECB, 16, 8, false),
        "des3" => (CKK_DES3, CKM_DES3_ECB, 24, 8, false),
        "hmac" => (CKK_GENERIC_SECRET, CKM_SHA256_HMAC, 32, 32, true),
        "cmac" => (CKK_AES, CKM_AES_CMAC, 16, 16, true),
        _ => return Err(Failure::Input("probe_symmetric_algorithm")),
    };
    // Public test material only. The DES bytes have odd parity and three
    // distinct component keys; the source buffer is not an operational secret.
    let bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        0x23, 0x45,
    ];
    let mut template = Template::new()
        .unsigned(CKA_CLASS, CKO_SECRET_KEY)
        .unsigned(CKA_KEY_TYPE, key_type)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, true)
        .boolean(CKA_SENSITIVE, true)
        .boolean(CKA_EXTRACTABLE, false)
        .bytes(CKA_LABEL, b"recipe-symmetric")
        .bytes(CKA_VALUE, &bytes[..key_length]);
    template = if mac {
        template.boolean(CKA_SIGN, true).boolean(CKA_VERIFY, true)
    } else {
        template
            .boolean(CKA_ENCRYPT, true)
            .boolean(CKA_DECRYPT, true)
    };
    let create = required(owner.functions()?.C_CreateObject)?;
    let session = owner.handle()?;
    let mut key = CK_INVALID_HANDLE;
    template.with_native(|attributes| {
        // SAFETY: owned, typed template values remain live through the synchronous
        // import; the handle output is read only after CKR_OK.
        status("C_CreateObject", unsafe {
            create(
                session,
                attributes.as_mut_ptr(),
                attributes.len() as CK_ULONG,
                &mut key,
            )
        })
    })?;
    owner.retain(key)?;
    let mut mechanism = CK_MECHANISM {
        mechanism,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut message = vec![0x42; if mac { 32 } else { output_length }];
    let mut output = vec![0u8; output_length];
    let mut length = output.len() as CK_ULONG;
    if mac {
        let initialize = required(owner.functions()?.C_SignInit)?;
        let sign = required(owner.functions()?.C_Sign)?;
        let verify_initialize = required(owner.functions()?.C_VerifyInit)?;
        let verify = required(owner.functions()?.C_Verify)?;
        // SAFETY: live owned key; exact fixed MAC capacity and writable length.
        status("C_SignInit", unsafe {
            initialize(session, &mut mechanism, key)
        })?;
        status("C_Sign", unsafe {
            sign(
                session,
                message.as_mut_ptr(),
                message.len() as CK_ULONG,
                output.as_mut_ptr(),
                &mut length,
            )
        })?;
        if length as usize != output_length {
            return Err(Failure::Oracle("probe_mac_length"));
        }
        status("C_VerifyInit", unsafe {
            verify_initialize(session, &mut mechanism, key)
        })?;
        // SAFETY: exact MAC bytes/length from the completed sign, same live inputs.
        status("C_Verify", unsafe {
            verify(
                session,
                message.as_mut_ptr(),
                message.len() as CK_ULONG,
                output.as_mut_ptr(),
                length,
            )
        })?;
    } else {
        let initialize = required(owner.functions()?.C_EncryptInit)?;
        let encrypt = required(owner.functions()?.C_Encrypt)?;
        let decrypt_initialize = required(owner.functions()?.C_DecryptInit)?;
        let decrypt = required(owner.functions()?.C_Decrypt)?;
        // SAFETY: exactly one unpadded ECB block and matching output capacity.
        status("C_EncryptInit", unsafe {
            initialize(session, &mut mechanism, key)
        })?;
        status("C_Encrypt", unsafe {
            encrypt(
                session,
                message.as_mut_ptr(),
                message.len() as CK_ULONG,
                output.as_mut_ptr(),
                &mut length,
            )
        })?;
        if length as usize != output_length {
            return Err(Failure::Oracle("probe_cipher_length"));
        }
        let mut plaintext = vec![0u8; message.len()];
        let mut plain_length = plaintext.len() as CK_ULONG;
        status("C_DecryptInit", unsafe {
            decrypt_initialize(session, &mut mechanism, key)
        })?;
        // SAFETY: exact completed ciphertext, distinct writable plaintext buffer.
        status("C_Decrypt", unsafe {
            decrypt(
                session,
                output.as_mut_ptr(),
                length,
                plaintext.as_mut_ptr(),
                &mut plain_length,
            )
        })?;
        if plain_length as usize != message.len() || plaintext != message {
            return Err(Failure::Oracle("probe_cipher_round_trip"));
        }
    }
    Ok(())
}
