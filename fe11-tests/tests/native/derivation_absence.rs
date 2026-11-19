// SPDX-License-Identifier: Apache-2.0
//! Derive a short generic secret with an absent mechanism and a valid base key.
use super::{derived_value, template, Failure, Owner};
use crate::{
    outcome,
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;

#[path = "tls_derivation_absence.rs"]
pub(super) mod tls;

pub(super) fn parameters(
    action: &str,
) -> std::result::Result<NativeKeyDerivation<'static>, Failure> {
    if let Some(variant) = action.strip_prefix("handshake-") {
        return tls::parameters(variant);
    }
    match action {
        "extract-first" => Ok(NativeKeyDerivation::Extract { start_bit: 0 }),
        "xor-block" => Ok(NativeKeyDerivation::XorData { data: &[0x39; 32] }),
        _ => {
            let number: u64 = action
                .strip_prefix("hash-")
                .ok_or(Failure::Input("derivation_name"))?
                .parse()
                .map_err(|_| Failure::Input("derivation_number"))?;
            let hash = KeyDerivationHash::ALL
                .iter()
                .copied()
                .find(|h| h.mechanism_number() == number)
                .ok_or(Failure::Input("derivation_hash"))?;
            Ok(NativeKeyDerivation::Hash(hash))
        }
    }
}

pub(super) fn check<W: Write>(
    owner: &Owner,
    base: &NativeObjectRef,
    action: &str,
    retained: &mut Option<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    // SSL and TLS master secrets have exactly 48 bytes. Digest, extraction,
    // XOR and exporter fixtures request a short generic-secret result.
    let bytes = if action.starts_with("handshake-") && action.contains("master") {
        48
    } else {
        16
    };
    check_request(owner, base, parameters(action)?, bytes, retained, report)
}

pub(super) fn check_request<W: Write>(
    owner: &Owner,
    base: &NativeObjectRef,
    params: NativeKeyDerivation<'_>,
    bytes: usize,
    retained: &mut Option<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let fields = derived_value::template_attributes(bytes);
    let request = template(&fields);
    let result = match owner {
        Owner::Session(s) => s.derive_native_key(base, params, request),
        Owner::Advanced(s) => s.derive_native_key(base, params, request),
    };
    match result {
        Err(
            error @ Error::Native {
                function: "C_DeriveKey",
                code,
                ..
            },
        ) if code == fe11_sys::CKR_MECHANISM_INVALID as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("derivation_report"))
        }
        Err(error) => Err(error.into()),
        Ok(output) => {
            *retained = Some(output.objects);
            Err(Failure::Oracle("unadvertised_derivation_accepted"))
        }
    }
}
