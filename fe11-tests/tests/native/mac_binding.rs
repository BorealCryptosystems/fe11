// SPDX-License-Identifier: Apache-2.0
//! A MAC binds both the message and key; a terminal refusal permits fresh use.
use super::{refusal, Failure, Owner, Report, Vector};
use fe11::*;
use std::io::Write;

/// A genuinely absent GENERAL selector must reach the native Init with its
/// caller-selected scalar. A full MAC with a truncated result is not a substitute.
pub(super) fn general<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let parts = [vector.message.as_slice()];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: vector.message.len(),
    };
    for route in [MessageRoute::Single, MessageRoute::Multipart] {
        let parameters = || NativeMacParameters::General {
            algorithm: vector.algorithm,
            output_bytes: vector.width as u64,
        };
        let signed = match owner {
            Owner::Session(s) => {
                s.compute_native_mac(key, parameters(), route, &parts, limits, vector.width, None)
            }
            Owner::Advanced(s) => {
                s.compute_native_mac(key, parameters(), route, &parts, limits, vector.width, None)
            }
        };
        refusal(
            signed.map(|_| ()),
            "C_SignInit",
            &[fe11_sys::CKR_MECHANISM_INVALID as u64],
            report,
        )?;
        // This is only a verification operand: the absent selector must fail
        // at Init, before Verify can inspect it. It is not credited as a valid
        // truncated MAC or as evidence of native truncation support.
        let expected = &vector.tag[..vector.width];
        let verified = match owner {
            Owner::Session(s) => {
                s.verify_native_mac(key, parameters(), route, &parts, expected, limits, None)
            }
            Owner::Advanced(s) => {
                s.verify_native_mac(key, parameters(), route, &parts, expected, limits, None)
            }
        };
        refusal(
            verified,
            "C_VerifyInit",
            &[fe11_sys::CKR_MECHANISM_INVALID as u64],
            report,
        )?;
    }
    Ok(())
}

pub(super) fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    other_key: &NativeObjectRef,
    vector: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut changed = vector.message.clone();
    let first = changed
        .first_mut()
        .ok_or(Failure::Input("mac_binding_nonempty_message"))?;
    *first ^= 1;
    let mut original_parts = Vec::with_capacity(vector.lengths.len());
    let mut changed_parts = Vec::with_capacity(vector.lengths.len());
    let mut offset = 0;
    for length in &vector.lengths {
        original_parts.push(&vector.message[offset..offset + length]);
        changed_parts.push(&changed[offset..offset + length]);
        offset += length;
    }
    let single = [vector.message.as_slice()];
    let changed_single = [changed.as_slice()];
    let limits = InputLimits {
        maximum_parts: original_parts.len(),
        maximum_total_bytes: vector.message.len(),
    };
    for route in [MessageRoute::Single, MessageRoute::Multipart] {
        let (input, altered) = if route == MessageRoute::Single {
            (single.as_slice(), changed_single.as_slice())
        } else {
            (original_parts.as_slice(), changed_parts.as_slice())
        };
        let terminal = if route == MessageRoute::Single {
            "C_Verify"
        } else {
            "C_VerifyFinal"
        };
        // The published answer, rather than another module operation, is the
        // authority for both native computation and subsequent verification.
        let mac = owner.compute(key, vector.algorithm, route, input, limits, vector.width)?;
        if mac.as_bytes() != vector.tag
            || mac.mechanism_number() != vector.algorithm.mechanism_number()
        {
            return Err(Failure::Oracle("mac_binding_published_answer"));
        }
        owner.verify(key, vector.algorithm, route, input, &vector.tag, limits)?;
        owner.verify(key, vector.algorithm, route, input, mac.as_bytes(), limits)?;
        refusal(
            owner.verify(key, vector.algorithm, route, altered, &vector.tag, limits),
            terminal,
            &[fe11_sys::CKR_SIGNATURE_INVALID as u64],
            report,
        )?;
        owner.verify(key, vector.algorithm, route, input, &vector.tag, limits)?;
        refusal(
            owner.verify(
                other_key,
                vector.algorithm,
                route,
                input,
                &vector.tag,
                limits,
            ),
            terminal,
            &[fe11_sys::CKR_SIGNATURE_INVALID as u64],
            report,
        )?;
        // Reuse the same session after both failures. No new session, key or
        // hidden fallback substitutes for the owner that saw the refusals.
        let recovered = owner.compute(key, vector.algorithm, route, input, limits, vector.width)?;
        if recovered.as_bytes() != vector.tag {
            return Err(Failure::Oracle("mac_binding_recovery_answer"));
        }
    }
    Ok(())
}
