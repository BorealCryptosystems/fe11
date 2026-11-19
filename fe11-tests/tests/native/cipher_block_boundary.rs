// SPDX-License-Identifier: Apache-2.0
//! Fixed-input preparation and caller-fed block boundaries have distinct oracles.
use super::{hex, outcome, Failure, Owner, Phase, Report, Vector};
use fe11::*;
use std::io::Write;

#[derive(Clone, Copy)]
enum Route {
    Single,
    Multipart,
    Stream,
}
#[derive(Clone, Copy)]
enum Expected {
    Exact,
    LocalLength,
    NativeLength,
    Padding,
}
pub(super) struct Case {
    route: Route,
    expected: Expected,
    control_input: Vec<u8>,
    control_output: Vec<u8>,
}
impl Case {
    pub(super) fn read(f: &[&str]) -> std::result::Result<Self, Failure> {
        if !matches!(
            f[0],
            "CKM_AES_ECB"
                | "CKM_AES_CBC"
                | "CKM_AES_CBC_PAD"
                | "CKM_DES_ECB"
                | "CKM_DES_CBC"
                | "CKM_DES_CBC_PAD"
                | "CKM_DES3_ECB"
                | "CKM_DES3_CBC"
                | "CKM_DES3_CBC_PAD"
        ) {
            return Err(Failure::Input("block_boundary_mechanism"));
        }
        let route = match f[8] {
            "single" => Route::Single,
            "multipart" => Route::Multipart,
            "stream" if f[1] == "advanced" => Route::Stream,
            _ => return Err(Failure::Input("block_boundary_route")),
        };
        let expected = match f[9] {
            "exact" => Expected::Exact,
            "local-length" if !matches!(route, Route::Stream) && !f[0].ends_with("_PAD") => {
                Expected::LocalLength
            }
            "native-length" if matches!(route, Route::Stream) && !f[0].ends_with("_PAD") => {
                Expected::NativeLength
            }
            "padding" if f[0].ends_with("_PAD") && f[2] == "decrypt" => Expected::Padding,
            _ => return Err(Failure::Input("block_boundary_expected")),
        };
        let control_input = hex(f[10], 64).map_err(Failure::Input)?;
        let control_output = hex(f[11], 64).map_err(Failure::Input)?;
        if control_input.is_empty() || control_output.is_empty() {
            return Err(Failure::Input("block_boundary_control"));
        }
        Ok(Self {
            route,
            expected,
            control_input,
            control_output,
        })
    }
}

fn invoke(
    owner: &Owner,
    key: &NativeObjectRef,
    v: &Vector,
    route: Route,
    parts: &[&[u8]],
) -> std::result::Result<Vec<u8>, Failure> {
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: parts.iter().map(|p| p.len()).sum(),
    };
    if !matches!(route, Route::Stream) {
        let route = if matches!(route, Route::Single) {
            MessageRoute::Single
        } else {
            MessageRoute::Multipart
        };
        return if v.encrypt {
            Ok(owner
                .encrypt(key, v.parameters, route, parts, limits)?
                .as_bytes()
                .to_vec())
        } else {
            Ok(owner
                .decrypt(key, v.parameters, route, parts, limits)?
                .as_bytes()
                .to_vec())
        };
    }
    let Owner::Advanced(session) = owner else {
        return Err(Failure::Input("block_stream_owner"));
    };
    // Native Update may publish unauthenticated chunks. This fixture never
    // takes those chunks: only the final full result is a plaintext oracle.
    let output = CipherOutputPlan::Buffer {
        capacity: limits
            .maximum_total_bytes
            .checked_add(32)
            .ok_or(Failure::Input("block_capacity_overflow"))?,
    };
    let mut ticket = if v.encrypt {
        session.begin_encrypt_stream(CipherKeyReference::Secret(key), v.parameters, output)?
    } else {
        session.begin_decrypt_stream(CipherKeyReference::Secret(key), v.parameters, output)?
    };
    for part in parts {
        if !matches!(
            session.cipher_update(&mut ticket, part, limits)?,
            OperationProgress::Ready
        ) {
            return Err(Failure::Oracle("block_update_boundary"));
        }
    }
    match session.finish_cipher_stream(&mut ticket)? {
        OperationProgress::CipherEncrypted(value) if v.encrypt => Ok(value.as_bytes().to_vec()),
        OperationProgress::CipherDecrypted(value) if !v.encrypt => Ok(value.as_bytes().to_vec()),
        _ => Err(Failure::Oracle("block_final_result")),
    }
}

pub(super) fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    v: &Vector,
    c: &Case,
    parts: &[&[u8]],
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let result = invoke(owner, key, v, c.route, parts);
    // AES has a specialized preparation path; DES/3DES use the fixed-block
    // contract. Require the exact public diagnostic of the selected path.
    let length_reason = if matches!(v.parameters, CipherParameters::Aes(_)) {
        SymmetricParametersRejection::AesInputIsNotBlockAligned
    } else {
        SymmetricParametersRejection::BlockCipherInputLength
    };
    let error = match (c.expected, result) {
        (Expected::Exact, Ok(value)) if value == v.expected => return Ok(()),
        (Expected::LocalLength, Err(Failure::Product(error)))
            if if v.encrypt {
                matches!(&error, Error::Rejected(RejectionReason::SymmetricParameters(actual)) if *actual == length_reason)
            } else {
                matches!(&error, Error::InvalidCiphertext)
            } =>
        {
            error
        }
        (
            Expected::NativeLength,
            Err(Failure::Product(error @ Error::Native { function, code, .. })),
        ) if (function, code)
            == if v.encrypt {
                ("C_EncryptFinal", fe11_sys::CKR_DATA_LEN_RANGE as u64)
            } else {
                (
                    "C_DecryptFinal",
                    fe11_sys::CKR_ENCRYPTED_DATA_LEN_RANGE as u64,
                )
            } =>
        {
            error
        }
        (
            Expected::Padding,
            Err(Failure::Product(error @ Error::Native { function, code, .. })),
        ) if code == fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64
            && function
                == if matches!(c.route, Route::Single) {
                    "C_Decrypt"
                } else {
                    "C_DecryptFinal"
                } =>
        {
            error
        }
        (_, Err(error)) => return Err(error),
        _ => return Err(Failure::Oracle("block_boundary_result")),
    };
    outcome::record(report, Phase::Body, &Failure::Product(error))
        .map_err(|_| Failure::Input("report_write"))?;
    // The successful control uses the same session and key after the error.
    // Its bytes were computed independently; no round trip defines correctness.
    if invoke(owner, key, v, Route::Single, &[&c.control_input])? != c.control_output {
        return Err(Failure::Oracle("block_same_session_control"));
    }
    Ok(())
}
