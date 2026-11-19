// SPDX-License-Identifier: Apache-2.0
//! Distinguish malformed DER from a decoded but mathematically invalid signature.
use super::{api, Component, Failure};
use std::mem::size_of;

pub(super) fn unknown_scheme(
    component: &Component,
    request: &api::VerificationRequest,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Failure> {
    let probe = component
        .table
        .probe
        .ok_or(Failure::Oracle("engine_probe_entry"))?;
    let verify = component
        .table
        .verify
        .ok_or(Failure::Oracle("engine_verify_entry"))?;
    let invalid = api::VerificationRequest {
        scheme: u32::MAX,
        ..*request
    };
    for (parameters, expected) in [
        (request, api::status::OK),
        (&invalid, api::status::INVALID_REQUEST),
        (request, api::status::OK),
    ] {
        let mut verdict = 2;
        // SAFETY: only the scalar scheme differs. All buffers belong to the
        // same live public fixture and are disjoint from the writable result.
        let (prepared, completed) = unsafe {
            (
                probe(parameters, size_of::<api::VerificationRequest>()),
                verify(
                    parameters,
                    size_of::<api::VerificationRequest>(),
                    api::Bytes::from_slice(message),
                    api::Bytes::from_slice(signature),
                    &mut verdict,
                ),
            )
        };
        if prepared != expected
            || completed != expected
            || (expected == api::status::OK && verdict != 1)
        {
            return Err(Failure::Oracle("engine_unknown_scheme_status"));
        }
    }
    Ok(())
}

pub(super) fn check(
    component: &Component,
    request: &api::VerificationRequest,
    message: &[u8],
    valid: &[u8],
    selector: &str,
) -> Result<(), Failure> {
    let probe = component
        .table
        .probe
        .ok_or(Failure::Oracle("engine_probe_entry"))?;
    let verify = component
        .table
        .verify
        .ok_or(Failure::Oracle("engine_verify_entry"))?;
    // SAFETY: request and all borrowed descriptors remain live through each
    // synchronous call, and Component retains the selected function image.
    let prepared = unsafe { probe(request, size_of::<api::VerificationRequest>()) };
    if prepared != api::status::OK {
        return Err(Failure::Oracle("engine_format_preparation"));
    }
    let call = |signature: &[u8]| {
        let mut verdict = 2;
        // SAFETY: immutable input slices and request are live and disjoint from
        // the initialized exclusive scalar. No native pointer escapes the call.
        let status = unsafe {
            verify(
                request,
                size_of::<api::VerificationRequest>(),
                api::Bytes::from_slice(message),
                api::Bytes::from_slice(signature),
                &mut verdict,
            )
        };
        (status, verdict)
    };
    if call(valid) != (api::status::OK, 1) {
        return Err(Failure::Oracle("engine_format_valid_control"));
    }
    if valid.len() < 3 || valid[0] != 0x30 {
        return Err(Failure::Input("engine_format_der_control"));
    }
    let mut malformed = valid.to_vec();
    match selector {
        "empty" => malformed.clear(),
        "truncated" => {
            malformed.pop();
        }
        "trailing" => malformed.push(0),
        "wrong-tag" => malformed[0] = 0x31,
        "nonminimal-length" => {
            if valid[1] < 0x80 {
                malformed.insert(1, 0x81);
            } else if valid[1] == 0x81 {
                malformed[1] = 0x82;
                malformed.insert(2, 0);
            } else {
                return Err(Failure::Input("engine_format_length_form"));
            }
        }
        "zero-scalars" => malformed = vec![0x30, 6, 2, 1, 0, 2, 1, 0],
        _ => return Err(Failure::Input("engine_format_selector")),
    }
    let (status, verdict) = call(&malformed);
    if matches!(selector, "zero-scalars" | "empty") {
        if (status, verdict) != (api::status::OK, 0) {
            return Err(Failure::Oracle("engine_format_invalid_verdict"));
        }
    } else if status != api::status::ENGINE_FAILURE {
        // A malformed signature does not produce a mathematical validity
        // verdict in this component. Do not interpret output after failure.
        return Err(Failure::Oracle("engine_format_decode_status"));
    }
    if call(valid) != (api::status::OK, 1) {
        return Err(Failure::Oracle("engine_format_valid_after_refusal"));
    }
    Ok(())
}
