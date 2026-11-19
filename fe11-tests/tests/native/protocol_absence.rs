// SPDX-License-Identifier: Apache-2.0
//! Reach absent native derivation selectors with real, compatible base keys.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    derived_value, key_wrap_fixture, module_controls,
    object_owner::Owner,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::*;
use std::io::{self, Write};

#[path = "derivation_absence.rs"]
mod derivation_absence;
#[path = "key_schedule_absence.rs"]
mod schedule;

fn is_simple_derivation(action: &str) -> bool {
    action.starts_with("handshake-")
        || action.starts_with("hash-")
        || matches!(action, "extract-first" | "xor-block")
}

fn selector(action: &str) -> std::result::Result<u64, Failure> {
    if let Some(id) = schedule::selector(action) {
        return Ok(id as u64);
    }
    if is_simple_derivation(action) {
        return Ok(derivation_absence::parameters(action)?.mechanism_number());
    }
    let value = match action {
        "kip-null" | "kip-empty" | "kip-key" => CKM_KIP_DERIVE,
        "kip-mac-sign" | "kip-mac-verify" => CKM_KIP_MAC,
        "kip-wrap" | "kip-unwrap" => CKM_KIP_WRAP,
        "counter" => CKM_SP800_108_COUNTER_KDF,
        "feedback" => CKM_SP800_108_FEEDBACK_KDF,
        "pipeline" => CKM_SP800_108_DOUBLE_PIPELINE_KDF,
        "tls-prf" => CKM_TLS_PRF,
        "wtls-prf" => CKM_WTLS_PRF,
        "ssl3-material" => CKM_SSL3_KEY_AND_MAC_DERIVE,
        "tls-material" => CKM_TLS_KEY_AND_MAC_DERIVE,
        "tls12-material" => CKM_TLS12_KEY_AND_MAC_DERIVE,
        "tls12-safe" => CKM_TLS12_KEY_SAFE_DERIVE,
        "wtls-server" => CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
        "wtls-client" => CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
        _ => return Err(Failure::Input("protocol_absence_selector")),
    };
    Ok(value as u64)
}

fn destination() -> DestinationPlan {
    DestinationPlan {
        search: DestinationSearchPlan::NotRequested,
        user: DestinationUserObservation::NotRequested,
    }
}

fn template<'a>(attributes: &'a [AttributeInput<'static>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: 64,
        },
        observation: None,
        destination: destination(),
    }
}

fn reject<T>(result: Result<T>, effect: bool) -> std::result::Result<(), Failure> {
    reject_at(result, "C_DeriveKey", effect)
}

fn reject_at<T>(
    result: Result<T>,
    expected_function: &'static str,
    effect: bool,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Native {
            function,
            code,
            may_have_effect,
        }) if function == expected_function
            && code == CKR_MECHANISM_INVALID as u64
            && may_have_effect == effect =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("absent_protocol_accepted")),
    }
}

fn created<T>(
    result: Result<CreatedObjects<T>>,
    effect: bool,
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    // Store the actual owners before interpreting any optional observations.
    // An unexpected success is cleaned up, never turned into absence evidence.
    let result = result.map(|value| {
        *retained = Some(value.objects);
    });
    reject(result, effect)
}

fn invoke(
    owner: &Owner,
    key: &NativeObjectRef,
    action: &str,
    retained: &mut Option<CreatedObjectSet>,
) -> std::result::Result<(), Failure> {
    let attributes = derived_value::template_attributes(32);
    if matches!(
        action,
        "kip-mac-sign" | "kip-mac-verify" | "kip-wrap" | "kip-unwrap"
    ) {
        let mac = action.starts_with("kip-mac-");
        // CT-KIP MAC uses hKey and ignores the seed; wrapping ignores hKey.
        // This checks the absent selector, not a successful CT-KIP exchange.
        let parameters = NativeKipParameters {
            mechanism: NativeNestedMechanism::Mac(NativeMacParameters::Full(
                NativeMacAlgorithm::SHA256_HMAC,
            )),
            key: mac.then_some(key),
            seed: None,
        };
        let input = [0, 0xff, 0x80, 1];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: input.len(),
        };
        return match action {
            "kip-mac-sign" => reject_at(
                match owner {
                    Owner::Session(s) => {
                        s.compute_native_kip_mac(key, parameters, &input, limits, 32, None)
                    }
                    Owner::Advanced(s) => {
                        s.compute_native_kip_mac(key, parameters, &input, limits, 32, None)
                    }
                },
                "C_SignInit",
                false,
            ),
            "kip-mac-verify" => reject_at(
                match owner {
                    Owner::Session(s) => {
                        s.verify_native_kip_mac(key, parameters, &input, &[0; 32], limits)
                    }
                    Owner::Advanced(s) => {
                        s.verify_native_kip_mac(key, parameters, &input, &[0; 32], limits)
                    }
                },
                "C_VerifyInit",
                false,
            ),
            "kip-wrap" => reject_at(
                match owner {
                    Owner::Session(s) => s.wrap_native_kip(key, key, parameters, 64),
                    Owner::Advanced(s) => s.wrap_native_kip(key, key, parameters, 64),
                },
                "C_WrapKey",
                false,
            ),
            "kip-unwrap" => {
                // Opaque bytes exercise mechanism rejection only. They are not
                // asserted to be an authenticated or valid CT-KIP envelope.
                let result = match owner {
                    Owner::Session(s) => {
                        s.unwrap_native_kip(key, &[0; 32], parameters, template(&attributes))
                    }
                    Owner::Advanced(s) => {
                        s.unwrap_native_kip(key, &[0; 32], parameters, template(&attributes))
                    }
                }
                .map(|value| {
                    *retained = Some(value.objects);
                });
                reject_at(result, "C_UnwrapKey", true)
            }
            _ => Err(Failure::Input("kip_operation")),
        };
    }
    if action.starts_with("kip-") {
        let parameters = NativeKipParameters {
            mechanism: NativeNestedMechanism::Mac(NativeMacParameters::Full(
                NativeMacAlgorithm::SHA256_HMAC,
            )),
            key: (action == "kip-key").then_some(key),
            seed: match action {
                "kip-null" => None,
                "kip-empty" => Some(&[]),
                _ => Some(&[0, 0xff, 0x80, 1]),
            },
        };
        let result = match owner {
            Owner::Session(s) => s.derive_native_kip(key, parameters, template(&attributes)),
            Owner::Advanced(s) => s.derive_native_kip(key, parameters, template(&attributes)),
        };
        return created(result, true, retained);
    }
    if matches!(action, "counter" | "feedback" | "pipeline") {
        let counter = Sp800CounterFormat {
            little_endian: false,
            width_bits: 32,
        };
        let data = [
            if action == "counter" {
                Sp800Data::CounterIteration(counter)
            } else {
                Sp800Data::Iteration
            },
            Sp800Data::Bytes(b"label\0context"),
            Sp800Data::Length(Sp800LengthFormat {
                method: CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS as u64,
                little_endian: false,
                width_bits: 32,
            }),
        ];
        let parameters = Sp800Request {
            mode: match action {
                "counter" => Sp800Mode::Counter,
                "feedback" => Sp800Mode::Feedback { iv: Some(&[0; 32]) },
                _ => Sp800Mode::DoublePipeline,
            },
            prf: CKM_SHA256_HMAC as u64,
            data: &data,
        };
        let result = match owner {
            Owner::Session(s) => s.derive_sp800_108(key, parameters, [template(&attributes)]),
            Owner::Advanced(s) => s.derive_sp800_108(key, parameters, [template(&attributes)]),
        };
        return created(result, true, retained);
    }
    if action.ends_with("prf") {
        let request = TlsPrfRequest {
            mechanism: if action == "tls-prf" {
                TlsPrfMechanism::Tls
            } else {
                TlsPrfMechanism::Wtls {
                    digest: CKM_SHA256 as u64,
                }
            },
            seed: &[0, 0xff, 0x80, 1],
            label: b"test label",
            output_bytes: 32,
        };
        let limits = InputLimits {
            maximum_parts: 2,
            maximum_total_bytes: 14,
        };
        let result = match owner {
            Owner::Session(s) => s.derive_tls_prf(key, request, limits),
            Owner::Advanced(s) => s.derive_tls_prf(key, request, limits),
        };
        return reject(result, false);
    }
    let mechanism = match action {
        "ssl3-material" => TlsKeyMaterialMechanism::Ssl3,
        "tls-material" => TlsKeyMaterialMechanism::Tls,
        "tls12-material" => TlsKeyMaterialMechanism::Tls12 {
            hash: CKM_SHA256 as u64,
        },
        "tls12-safe" => TlsKeyMaterialMechanism::Tls12Safe {
            hash: CKM_SHA256 as u64,
        },
        "wtls-server" => TlsKeyMaterialMechanism::WtlsServer {
            digest: CKM_SHA256 as u64,
            sequence: 1,
        },
        "wtls-client" => TlsKeyMaterialMechanism::WtlsClient {
            digest: CKM_SHA256 as u64,
            sequence: 1,
        },
        _ => return Err(Failure::Input("material_selector")),
    };
    let observe = || DerivedKeyObservation {
        observation: None,
        destination: destination(),
    };
    let observations = if action.starts_with("wtls") {
        TlsKeyMaterialObservations::Wtls(std::array::from_fn(|_| observe()))
    } else {
        TlsKeyMaterialObservations::Tls(std::array::from_fn(|_| observe()))
    };
    // Native bit-length fields govern these four/two outputs. Do not impose
    // a contradictory generic VALUE_LEN from the single-output KDF template.
    let attributes: Vec<_> = derived_value::template_attributes(16)
        .into_iter()
        .filter(|a| a.attribute != StandardAttribute::VALUE_LEN)
        .collect();
    let request = TlsKeyMaterialRequest {
        mechanism,
        randoms: TlsRandoms {
            client: &[0x11; 32],
            server: &[0x22; 32],
        },
        mac_bits: 160,
        key_bits: 128,
        iv_bits: 128,
        export: false,
        attributes: &attributes,
        limits: template(&attributes).limits,
    };
    let result = match owner {
        Owner::Session(s) => s.derive_tls_key_material(key, request, observations),
        Owner::Advanced(s) => s.derive_tls_key_material(key, request, observations),
    };
    created(result, false, retained)
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    selection: &str,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut owner = None;
    let mut key = None;
    let mut retained = None;
    let mut shared = None;
    let setup = (|| -> std::result::Result<&str, Failure> {
        let (route, action) = selection
            .split_once(':')
            .ok_or(Failure::Input("protocol_route"))?;
        if !matches!(route, "session" | "advanced") {
            return Err(Failure::Input("protocol_route"));
        }
        let mechanism = selector(action)?;
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module.as_ref().ok_or(Failure::Input("protocol_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("protocol_token"))?;
        if m.mechanism_ids(token.slot)?.contains(&mechanism) {
            return Err(Failure::Oracle("protocol_selector_present"));
        }
        owner = Some(Owner::open(m, config, route == "advanced")?);
        let o = owner.as_ref().ok_or(Failure::Input("protocol_owner"))?;
        // Public fixed test material, not an application key or fallback.
        let premaster;
        let bytes: &[u8] = if let Some(variant) = action.strip_prefix("handshake-") {
            premaster = derivation_absence::tls::base(variant);
            &premaster
        } else if action.starts_with("wtls-master") {
            // A WTLS premaster begins with the single-byte client version.
            premaster = [1; 48];
            &premaster
        } else if action.contains("tls") || action.starts_with("ssl3") {
            &[0x5a; 48]
        } else {
            &[0x5a; 32]
        };
        if action == "ike1-prf" {
            shared = Some(o.import_secret(
                &[0x72; 32],
                CKK_GENERIC_SECRET,
                [StandardAttribute::DERIVE, StandardAttribute::SIGN],
            )?);
        }
        key = Some(o.import_secret(
            bytes,
            CKK_GENERIC_SECRET,
            match action {
                "kip-mac-sign" | "kip-mac-verify" | "tls-finished" | "tls12-finished" => {
                    [StandardAttribute::SIGN, StandardAttribute::VERIFY]
                }
                "kip-wrap" => [StandardAttribute::WRAP, StandardAttribute::EXTRACTABLE],
                "kip-unwrap" => [StandardAttribute::UNWRAP, StandardAttribute::EXTRACTABLE],
                _ => [StandardAttribute::DERIVE, StandardAttribute::SIGN],
            },
        )?);
        Ok(action)
    })();
    let body = match (&setup, &owner, &key) {
        (Ok(action), Some(o), Some(k)) if schedule::selector(action).is_some() => {
            schedule::check(o, k, shared.as_ref(), action, &mut retained, &mut report)
        }
        (Ok(action), Some(o), Some(k)) if is_simple_derivation(action) => {
            derivation_absence::check(o, k, action, &mut retained, &mut report)
        }
        (Ok(action), Some(o), Some(k)) => invoke(o, k, action, &mut retained),
        _ => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let (Some(o), Some(set)) = (&owner, &retained) {
        for object in set.as_slice() {
            if let Err(error) = key_wrap_fixture::destroy(o, object) {
                cleanup.push(error.into());
            }
        }
    }
    if let (Some(o), Some(object)) = (&owner, &shared) {
        if let Err(error) = key_wrap_fixture::destroy(o, object) {
            cleanup.push(error.into());
        }
    }
    drop(shared);
    cleanup.extend(
        owner
            .as_ref()
            .map_or_else(Vec::new, |o| o.close(key.as_ref())),
    );
    drop(retained);
    drop(key);
    drop(owner);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
