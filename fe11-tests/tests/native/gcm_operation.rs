// SPDX-License-Identifier: Apache-2.0
//! Classic single/multipart GCM checks with no plaintext credited after refusal.
use super::{
    gcm_fixture::Vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

pub fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    v: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let mut offset = 0;
    let parts: Vec<_> = v
        .lengths
        .iter()
        .map(|n| {
            let part = &v.input[offset..offset + n];
            offset += n;
            part
        })
        .collect();
    let limits = InputLimits {
        maximum_parts: parts.len(),
        // AEAD budgets authenticated plaintext plus AAD, excluding tag framing.
        maximum_total_bytes: v
            .input
            .len()
            .saturating_sub(if v.encrypt {
                0
            } else {
                (v.tag_bits / 8) as usize
            })
            .checked_add(v.aad.len())
            .ok_or(Failure::Input("gcm_input_budget_overflow"))?,
    };
    for route in [MessageRoute::Single, MessageRoute::Multipart] {
        let result = invoke(owner, key, v, route, &parts, limits);
        match result {
            Ok(value) if v.valid && value == v.expected => (),
            Err(Failure::Product(Error::InvalidCiphertext)) if v.shorter_than_tag => (),
            Err(Failure::Product(error @ Error::Native { function, code, .. }))
                if !v.valid
                    && !v.shorter_than_tag
                    && code == fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64
                    && function
                        == if route == MessageRoute::Single {
                            "C_Decrypt"
                        } else {
                            "C_DecryptFinal"
                        } =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("gcm_known_answer_or_authentication")),
        }
        if v.reuse_after_refusal {
            // This fixture changes the final tag bit of a recorded valid KAT.
            // Reverse only that mutation and explicitly start a new operation
            // on the same owner and key after the authentication refusal.
            let mut restored = v.input.clone();
            *restored.last_mut().ok_or(Failure::Input("gcm_reuse_tag"))? ^= 1;
            let restored_parts = [restored.as_slice()];
            if invoke(owner, key, v, route, &restored_parts, limits)? != v.expected {
                return Err(Failure::Oracle("gcm_restart_known_answer"));
            }
        }
    }
    Ok(())
}

fn invoke(
    owner: &Owner,
    key: &NativeObjectRef,
    v: &Vector,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
) -> std::result::Result<Vec<u8>, Failure> {
    match (owner, v.encrypt) {
        (Owner::Session(s), true) => s
            .encrypt_classic_aead(key, v.parameters(), route, parts, limits)
            .map(|x| x.as_bytes().to_vec())
            .map_err(Failure::from),
        (Owner::Advanced(s), true) => advanced(s, key, v, route, parts, limits),
        (Owner::Session(s), false) => s
            .decrypt_classic_aead(key, v.parameters(), route, parts, limits)
            .map(|x| x.as_bytes().to_vec())
            .map_err(Failure::from),
        (Owner::Advanced(s), false) => advanced(s, key, v, route, parts, limits),
    }
}

// Advanced owners expose a ticket, not the synchronous session facade.
// The default pacing completes finite input during this poll; no retry or
// output-buffer adjustment is hidden by the known-answer case.
fn advanced(
    session: &AdvancedSession,
    key: &NativeObjectRef,
    v: &Vector,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
) -> std::result::Result<Vec<u8>, Failure> {
    let mut ticket = if v.encrypt {
        session.start_encrypt_classic_aead(
            key,
            v.parameters(),
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
        )?
    } else {
        session.start_decrypt_classic_aead(
            key,
            v.parameters(),
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
        )?
    };
    match session.poll(&mut ticket)? {
        OperationProgress::ClassicAeadEncrypted(value) if v.encrypt => {
            Ok(value.as_bytes().to_vec())
        }
        OperationProgress::ClassicAeadDecrypted(value) if !v.encrypt => {
            Ok(value.as_bytes().to_vec())
        }
        _ => Err(Failure::Oracle("expected_completed_classic_aead")),
    }
}
