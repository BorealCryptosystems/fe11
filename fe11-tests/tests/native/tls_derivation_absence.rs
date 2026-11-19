// SPDX-License-Identifier: Apache-2.0
//! TLS master-secret and exporter parameters used to distinguish selector refusal
//! from a template, base-key length, or protocol-parameter error.
use super::Failure;
use fe11::*;
use fe11_sys::*;

pub(super) fn parameters(
    action: &str,
) -> std::result::Result<NativeKeyDerivation<'static>, Failure> {
    let randoms = TlsRandoms {
        client: &[0x51; 32],
        server: &[0x72; 32],
    };
    let hash = CKM_SHA256 as u64;
    let dh = action.ends_with("-dh");
    let master = match action {
        "ssl3-master" | "ssl3-master-dh" => TlsMasterDerivation::Ssl3 { randoms, dh },
        "tls-master" | "tls-master-dh" => TlsMasterDerivation::Tls { randoms, dh },
        "tls12-master" | "tls12-master-dh" => TlsMasterDerivation::Tls12 { randoms, hash, dh },
        "tls12-extended-master" | "tls12-extended-master-dh" => {
            TlsMasterDerivation::Tls12Extended {
                session_hash: &[0x47; 32],
                hash,
                dh,
            }
        }
        "tls-exporter" | "tls12-exporter" => {
            return Ok(NativeKeyDerivation::TlsKdf(TlsKdfParameters {
                mechanism: if action == "tls-exporter" {
                    TlsKdfMechanism::Tls
                } else {
                    TlsKdfMechanism::Tls12
                },
                prf: hash,
                label: b"EXPORTER-public-test",
                randoms,
                context: None,
            }));
        }
        _ => return Err(Failure::Input("tls_derivation_variant")),
    };
    Ok(NativeKeyDerivation::TlsMaster(master))
}

/// Synthetic premaster inputs carry the actual protocol version in the first
/// two octets. The DH variants use a same-width public shared-secret fixture.
pub(in super::super) fn base(action: &str) -> [u8; 48] {
    let mut value = [0x5a; 48];
    if !action.ends_with("-dh") && action.contains("master") {
        value[0] = 3;
        value[1] = if action.starts_with("ssl3") {
            0
        } else if action.starts_with("tls12") {
            3
        } else {
            1
        };
    }
    value
}
