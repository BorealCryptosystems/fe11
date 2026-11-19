// SPDX-License-Identifier: Apache-2.0
//! Protocol-specific keys, output lengths and parameters for unavailable services.
use super::{derivation_absence, Failure, Owner, Report};
use crate::outcome;
use crate::report::Phase;
use fe11::*;
use fe11_sys::*;
use std::io::Write;

pub(super) fn selector(action: &str) -> Option<CK_MECHANISM_TYPE> {
    Some(match action {
        "ike-prf" => CKM_IKE_PRF_DERIVE,
        "ike1-prf" => CKM_IKE1_PRF_DERIVE,
        "ike1-extended" => CKM_IKE1_EXTENDED_DERIVE,
        "ike2-plus" => CKM_IKE2_PRF_PLUS_DERIVE,
        "wtls-master" => CKM_WTLS_MASTER_KEY_DERIVE,
        "wtls-master-dh" => CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
        "tls-finished" => CKM_TLS_MAC,
        "tls12-finished" => CKM_TLS12_MAC,
        _ => return None,
    })
}

pub(super) fn check<W: Write>(
    owner: &Owner,
    base: &NativeObjectRef,
    shared: Option<&NativeObjectRef>,
    action: &str,
    retained: &mut Option<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let prf = CKM_SHA256_HMAC as u64;
    if matches!(action, "tls-finished" | "tls12-finished") {
        let params = if action == "tls-finished" {
            NativeMacParameters::Tls {
                hash: CKM_TLS_PRF as u64,
                output_bytes: 12,
                server_or_client: 1,
            }
        } else {
            NativeMacParameters::Tls12 {
                hash: CKM_SHA256 as u64,
                output_bytes: 12,
                server_or_client: 1,
            }
        };
        let Owner::Session(session) = owner else {
            return Err(Failure::Input("tls_mac_route"));
        };
        let handshake = b"public handshake transcript";
        let result = session.compute_native_mac(
            base,
            params,
            MessageRoute::Single,
            &[handshake.as_slice()],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: handshake.len(),
            },
            12,
            None,
        );
        return match result {
            Err(
                error @ Error::Native {
                    function: "C_SignInit",
                    code,
                    ..
                },
            ) if code == CKR_MECHANISM_INVALID as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("absent_tls_mac_accepted")),
        };
    }
    let (params, length) = match action {
        "wtls-master" | "wtls-master-dh" => (
            NativeKeyDerivation::TlsMaster(TlsMasterDerivation::Wtls {
                randoms: TlsRandoms {
                    client: &[0x31; 16],
                    server: &[0x52; 16],
                },
                digest: CKM_SHA_1 as u64,
                dh_ecc: action.ends_with("-dh"),
            }),
            20,
        ),
        "ike-prf" => (
            NativeKeyDerivation::Ike(NativeIkeDerivation::Prf {
                prf,
                data_as_key: true,
                new_key: None,
                initiator_nonce: &[0x43; 16],
                responder_nonce: &[0x25; 16],
            }),
            32,
        ),
        "ike1-prf" => (
            NativeKeyDerivation::Ike(NativeIkeDerivation::Ike1 {
                prf,
                shared_key: shared.ok_or(Failure::Input("ike_shared_secret"))?,
                previous_key: None,
                initiator_cookie: &[0x31; 8],
                responder_cookie: &[0x74; 8],
                key_number: 0,
            }),
            32,
        ),
        "ike1-extended" => (
            NativeKeyDerivation::Ike(NativeIkeDerivation::Ike1Extended {
                prf,
                shared_key: None,
                extra: &[0x81; 8],
            }),
            48,
        ),
        "ike2-plus" => (
            NativeKeyDerivation::Ike(NativeIkeDerivation::PrfPlus {
                prf,
                seed_key: None,
                seed: &[0x73; 32],
            }),
            48,
        ),
        _ => return Err(Failure::Input("key_schedule_selector")),
    };
    derivation_absence::check_request(owner, base, params, length, retained, report)
}
