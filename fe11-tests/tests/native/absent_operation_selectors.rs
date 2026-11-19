// SPDX-License-Identifier: Apache-2.0
//! A named, absent selector must reach the native initializer with valid inputs.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use fe11_sys::*;
use std::io::{self, Write};

#[path = "absent_cipher_parameters.rs"]
mod cipher;
#[path = "absent_legacy_key_selectors.rs"]
pub(super) mod legacy;
#[path = "absent_agreement_selectors.rs"]
pub(super) mod agreement;
#[path = "absent_rsa_selectors.rs"]
mod rsa;

fn refusal<T, W: Write>(
    result: fe11::Result<T>,
    function: &'static str,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: actual,
                code,
                ..
            },
        ) if actual == function && code == CKR_MECHANISM_INVALID as u64 => {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("selector_refusal_report"))
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("absent_mechanism_accepted")),
    }
}

fn digest(number: CK_MECHANISM_TYPE) -> std::result::Result<NativeDigestAlgorithm, Failure> {
    match number {
        CKM_NULL => Ok(NativeDigestAlgorithm::Null(NativeNullDigestCapacity::new(
            3,
        )?)),
        CKM_SHA512_T => Ok(NativeDigestAlgorithm::Sha512T(NativeDigestTruncation::new(
            256,
        )?)),
        _ => NativeDigestAlgorithm::from_mechanism(number as u64)
            .ok_or(Failure::Input("unknown_digest_selector")),
    }
}

fn mac(number: CK_MECHANISM_TYPE) -> std::result::Result<NativeMacParameters<'static>, Failure> {
    let p = match number {
        CKM_AES_GMAC => NativeMacParameters::AesGmac {
            iv: &[0x35; 12],
            tag_bits: 128,
        },
        CKM_SHA512_T_HMAC => NativeMacParameters::Sha512T { bits: 256 },
        CKM_SSL3_MD5_MAC => NativeMacParameters::Ssl3Md5 { output_bytes: 16 },
        CKM_SSL3_SHA1_MAC => NativeMacParameters::Ssl3Sha1 { output_bytes: 20 },
        _ => NativeMacParameters::Full(
            *NativeMacAlgorithm::ALL
                .iter()
                .find(|alg| alg.mechanism_number() == number as u64)
                .ok_or(Failure::Input("unknown_mac_selector"))?,
        ),
    };
    Ok(p)
}

fn public_key_material(family: &str) -> std::result::Result<(CK_KEY_TYPE, &'static [u8]), Failure> {
    // Public test inputs. DES components carry odd parity.
    const TDES: &[u8; 24] = &[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x01, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
    ];
    match family {
        "aes" => Ok((CKK_AES, &[0x37; 16])),
        "des" => Ok((CKK_DES, &TDES[..8])),
        "des3" => Ok((CKK_DES3, TDES)),
        "hmac" => Ok((CKK_GENERIC_SECRET, &[0x37; 48])),
        _ => Err(Failure::Input("selector_key_family")),
    }
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    selection: &str,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut owner = None;
    let mut key = None;
    let setup = (|| -> std::result::Result<_, Failure> {
        let (family, number) = selection
            .split_once(':')
            .ok_or(Failure::Input("selector_fields"))?;
        let number: CK_MECHANISM_TYPE = number
            .parse()
            .map_err(|_| Failure::Input("selector_number"))?;
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module.as_ref().ok_or(Failure::Input("selector_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("selector_token"))?;
        if m.mechanism_ids(token.slot)?.contains(&(number as u64)) {
            return Err(Failure::Oracle("absent_selector_in_catalogue"));
        }
        owner = Some(Owner::open(m, config, false)?);
        if family == "digest" {
            digest(number)?;
        } else if matches!(family, "rsa-sign" | "rsa-encrypt") {
            let o = owner.as_ref().ok_or(Failure::Input("selector_owner"))?;
            key = Some(rsa::import(o, family)?);
        } else {
            let (kind, bytes, usage) = if let Some(family) = family.strip_prefix("encrypt-") {
                let (kind, bytes) = public_key_material(family)?;
                if cipher::parameters(number)?.mechanism_number() != number as u64 {
                    return Err(Failure::Input("cipher_selector_identity"));
                }
                (
                    kind,
                    bytes,
                    [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
                )
            } else {
                let (kind, bytes) = public_key_material(family)?;
                if mac(number)?.mechanism_number()? != number as u64 {
                    return Err(Failure::Input("mac_selector_identity"));
                }
                (
                    kind,
                    bytes,
                    [StandardAttribute::SIGN, StandardAttribute::VERIFY],
                )
            };
            key = Some(
                owner
                    .as_ref()
                    .ok_or(Failure::Input("selector_owner"))?
                    .import_secret(bytes, kind, usage)?,
            );
        }
        Ok((family, number))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(&(family, number)) = setup.as_ref() else {
            return Ok(());
        };
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("selector_owner"));
        };
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let parts = [b"abc".as_slice()];
        if matches!(family, "rsa-sign" | "rsa-encrypt") {
            let key = key.as_ref().ok_or(Failure::Input("rsa_selector_key"))?;
            return rsa::observe(session, key, family, number, &mut report);
        }
        if family.starts_with("encrypt-") {
            let key = key.as_ref().ok_or(Failure::Input("cipher_selector_key"))?;
            // More than one AES block also satisfies CTS. No native output is
            // expected: the module lacks the selected initializer.
            let message = [0x35; 32];
            let parts = [message.as_slice()];
            let limits = InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: message.len(),
            };
            return refusal(
                session.encrypt_cipher(
                    CipherKeyReference::Secret(key),
                    cipher::parameters(number)?,
                    MessageRoute::Single,
                    &parts,
                    limits,
                ),
                "C_EncryptInit",
                &mut report,
            );
        }
        if let Some(k) = &key {
            for route in [MessageRoute::Single, MessageRoute::Multipart] {
                refusal(
                    session.compute_native_mac(k, mac(number)?, route, &parts, limits, 64, None),
                    "C_SignInit",
                    &mut report,
                )?;
            }
        } else {
            let alg = digest(number)?;
            refusal(
                session.digest_native_single(alg, parts[0], limits),
                "C_DigestInit",
                &mut report,
            )?;
            refusal(
                session.digest_native(alg, &parts, limits),
                "C_DigestInit",
                &mut report,
            )?;
        }
        Ok(())
    })();
    let mut cleanup = owner
        .as_ref()
        .map_or_else(Vec::new, |o| o.close(key.as_ref()));
    drop(key);
    drop(owner);
    if let Some(m) = module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
