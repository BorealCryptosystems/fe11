// SPDX-License-Identifier: Apache-2.0
//! OAEP label, decoding, and retained-output contracts with public RSA keys.
use super::super::{
    outcome,
    report::{Phase, Report},
};
use super::{Failure, Owner, Vector};
use fe11::*;
use std::io::Write;

fn limits(length: usize) -> InputLimits {
    InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: length,
    }
}

fn decrypt(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    input: &[u8],
) -> Result<ExtensionResult> {
    match owner {
        Owner::Session(session) => session.decrypt_native_rsa(
            key,
            vector.parameters(),
            input,
            vector.key[0].len(),
            limits(input.len()),
            None,
        ),
        Owner::Advanced(session) => session.decrypt_native_rsa(
            key,
            vector.parameters(),
            input,
            vector.key[0].len(),
            limits(input.len()),
            None,
        ),
    }
}

fn poll(owner: &Owner, ticket: &mut OperationTicket) -> Result<OperationProgress> {
    match owner {
        Owner::Session(session) => session.poll_cipher(ticket),
        Owner::Advanced(session) => session.poll(ticket),
    }
}
fn resize(owner: &Owner, ticket: &OperationTicket, capacity: usize) -> Result<()> {
    match owner {
        Owner::Session(session) => session.resize_cipher_output(ticket, capacity),
        Owner::Advanced(session) => session.resize_cipher_output(ticket, capacity),
    }
}

fn encrypt(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    continuation: bool,
) -> std::result::Result<ExtensionResult, Failure> {
    let width = vector.key[0].len();
    if !continuation {
        return Ok(match owner {
            Owner::Session(session) => session.encrypt_native_rsa(
                key,
                vector.parameters(),
                &vector.plaintext,
                width,
                limits(vector.plaintext.len()),
            ),
            Owner::Advanced(session) => session.encrypt_native_rsa(
                key,
                vector.parameters(),
                &vector.plaintext,
                width,
                limits(vector.plaintext.len()),
            ),
        }?);
    }
    // The typed RSA entry takes an explicit buffer, not a NULL length query.
    // A zero-capacity buffer obtains the native required width; a second short
    // buffer must retain that width and the same Init/input owner.
    let mut ticket = match owner {
        Owner::Session(session) => session.begin_encrypt_native_rsa(
            key,
            vector.parameters(),
            &vector.plaintext,
            0,
            limits(vector.plaintext.len()),
        ),
        Owner::Advanced(session) => session.begin_encrypt_native_rsa(
            key,
            vector.parameters(),
            &vector.plaintext,
            0,
            limits(vector.plaintext.len()),
        ),
    }?;
    for capacity in [0, width - 1] {
        if capacity != 0 {
            resize(owner, &ticket, capacity)?;
        }
        match poll(owner, &mut ticket)? {
            OperationProgress::CipherBufferRequired(request)
                if request.function == "C_Encrypt"
                    && request.required == width
                    && request.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64 =>
            {
                ()
            }
            _ => return Err(Failure::Oracle("oaep_retained_required_width")),
        }
    }
    resize(owner, &ticket, width)?;
    match poll(owner, &mut ticket)? {
        OperationProgress::ExtensionEncrypted(value) if value.as_bytes().len() == width => {
            Ok(value)
        }
        _ => Err(Failure::Oracle("oaep_continuation_ciphertext")),
    }
}

pub(super) fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let contract = vector
        .contract
        .as_deref()
        .ok_or(Failure::Input("oaep_contract_missing"))?;
    if matches!(contract, "wrong-key" | "wrong-label" | "altered" | "length") {
        if vector.valid {
            return Err(Failure::Input("oaep_negative_requires_invalid"));
        }
        // C_Decrypt permits either diagnostic for an inappropriate ciphertext
        // length (PKCS#11 2.40 section 5.9 and 3.x section 5.10.2). A decoding
        // failure with the correct length still requires DATA_INVALID here.
        return match vector.decrypt(owner, key) {
            Err(
                error @ Error::Native {
                    function: "C_Decrypt",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64
                || (contract == "length"
                    && code == fe11_sys::CKR_ENCRYPTED_DATA_LEN_RANGE as u64) =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("invalid_oaep_contract_accepted")),
        };
    }
    if !vector.valid {
        return Err(Failure::Input("oaep_positive_requires_valid"));
    }
    // Exact independent fixture first: a roundtrip alone could conceal a shared
    // encoding error between encryption and decryption in the target module.
    let known = vector.decrypt(owner, key)?;
    if known.as_bytes() != vector.plaintext {
        return Err(Failure::Oracle("oaep_known_plaintext"));
    }
    let public = owner.import_rsa_public_usage(
        &vector.key[0],
        &vector.key[1],
        StandardAttribute::ENCRYPT,
    )?;
    let result = (|| -> std::result::Result<(), Failure> {
        let ciphertext = encrypt(owner, &public, vector, contract == "continuation")?;
        if ciphertext.as_bytes().len() != vector.key[0].len() {
            return Err(Failure::Oracle("oaep_ciphertext_width"));
        }
        let plaintext = decrypt(owner, key, vector, ciphertext.as_bytes())?;
        if plaintext.as_bytes() != vector.plaintext {
            return Err(Failure::Oracle("oaep_roundtrip_plaintext"));
        }
        Ok(())
    })();
    // Retain the public key until both operations have returned. Always attempt
    // destruction, even when an assertion fails; cleanup remains a separate phase.
    let destroyed = match owner {
        Owner::Session(session) => session.destroy_native_object(&public),
        Owner::Advanced(session) => session.destroy_native_object(&public),
    };
    if let Err(error) = destroyed {
        cleanup.push(error.into());
    }
    result
}
