// SPDX-License-Identifier: Apache-2.0
//! Native selection with mechanism-specific keys from public test data.
use super::{
    module_controls, refusal, select_token, Budgets, Configuration, Failure, Owner, Report,
};
use fe11::*;
use fe11_sys::*;
use std::io::{self, Write};

pub(super) const GOST_PARAMETERS: &[u8] = &[6, 7, 42, 133, 3, 2, 2, 31, 1];
const GOST_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const GOST_TARGET: &[u8] = b"fedcba9876543210fedcba9876543210";
const DES_KEY: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const DES_TARGET: &[u8] = &[0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01];
const IV: [u8; 8] = [0x35; 8];

pub(super) fn secret(
    owner: &Owner,
    kind: CK_KEY_TYPE,
    value: &[u8],
    usage: StandardAttribute,
    extractable: bool,
) -> fe11::Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let mut fields = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(CKO_SECRET_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(kind as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(extractable),
        ),
        attr(usage, AttributeInputValue::Boolean(true)),
        attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(value)),
    ];
    if kind == CKK_GOST28147 {
        // DER OID for id-Gost28147-89-CryptoPro-A-ParamSet (RFC 4357).
        fields.push(attr(
            StandardAttribute::GOST28147_PARAMS,
            AttributeInputValue::Bytes(GOST_PARAMETERS),
        ));
    }
    owner.create(
        &fields,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: fields.len(),
            maximum_value_bytes: 96,
        },
    )
}

pub(in super::super) fn execute<W: Write>(
    config: &Configuration,
    selector: &str,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut owner = None;
    let mut keys = Vec::new();
    let setup = (|| -> std::result::Result<(), Failure> {
        let number = match selector {
            "gost-encrypt" => CKM_GOST28147,
            "gost-ecb" => CKM_GOST28147_ECB,
            "gost-mac" => CKM_GOST28147_MAC,
            "gost-wrap" => CKM_GOST28147_KEY_WRAP,
            "lynks" => CKM_KEY_WRAP_LYNKS,
            "set-oaep" => CKM_KEY_WRAP_SET_OAEP,
            _ => return Err(Failure::Input("unknown_key_selector")),
        };
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module.as_ref().ok_or(Failure::Input("selector_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("selector_token"))?;
        if m.mechanism_ids(token.slot)?.contains(&(number as u64)) {
            return Err(Failure::Oracle("selected_mechanism_advertised"));
        }
        owner = Some(Owner::open(m, config, false)?);
        let o = owner.as_ref().ok_or(Failure::Input("selector_owner"))?;
        match selector {
            "set-oaep" => keys.push(super::rsa::import(o, "rsa-wrap")?),
            "lynks" => keys.push(secret(o, CKK_DES, DES_KEY, StandardAttribute::WRAP, false)?),
            "gost-wrap" => keys.push(secret(
                o,
                CKK_GOST28147,
                GOST_KEY,
                StandardAttribute::WRAP,
                false,
            )?),
            "gost-mac" => keys.push(secret(
                o,
                CKK_GOST28147,
                GOST_KEY,
                StandardAttribute::SIGN,
                false,
            )?),
            _ => keys.push(secret(
                o,
                CKK_GOST28147,
                GOST_KEY,
                StandardAttribute::ENCRYPT,
                false,
            )?),
        }
        match selector {
            "lynks" | "set-oaep" => keys.push(secret(
                o,
                CKK_DES,
                DES_TARGET,
                StandardAttribute::ENCRYPT,
                true,
            )?),
            "gost-wrap" => keys.push(secret(
                o,
                CKK_GOST28147,
                GOST_TARGET,
                StandardAttribute::ENCRYPT,
                true,
            )?),
            _ => (),
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("selector_session"));
        };
        let key = keys.first().ok_or(Failure::Input("selector_key"))?;
        let message = [0x17; 16];
        let parts = [message.as_slice()];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: message.len(),
        };
        if selector == "gost-mac" {
            return refusal(
                session.compute_native_mac(
                    key,
                    NativeMacParameters::Gost28147 { iv: &IV },
                    MessageRoute::Single,
                    &parts,
                    limits,
                    4,
                    None,
                ),
                "C_SignInit",
                &mut report,
            );
        }
        if matches!(selector, "gost-encrypt" | "gost-ecb") {
            let parameters = if selector == "gost-ecb" {
                CipherParameters::Gost28147Ecb
            } else {
                CipherParameters::Gost28147 { iv: Some(IV) }
            };
            return refusal(
                session.encrypt_cipher(
                    CipherKeyReference::Secret(key),
                    parameters,
                    MessageRoute::Single,
                    &parts,
                    limits,
                ),
                "C_EncryptInit",
                &mut report,
            );
        }
        let target = keys.get(1).ok_or(Failure::Input("selector_target"))?;
        let (parameters, capacity) = match selector {
            "gost-wrap" => (
                NativeTransportParameters::Fixed {
                    mechanism: NativeTransportMechanism::GOST28147_KEY_WRAP,
                    bytes: Some(&IV),
                },
                36,
            ),
            "lynks" => (
                NativeTransportParameters::Fixed {
                    mechanism: NativeTransportMechanism::KEY_WRAP_LYNKS,
                    bytes: None,
                },
                10,
            ),
            // SET's key-only block (BC=0x00) carries no extra data.
            "set-oaep" => (
                NativeTransportParameters::SetOaep {
                    block_contents: 0,
                    extra: None,
                },
                256,
            ),
            _ => return Err(Failure::Input("selector_wrap")),
        };
        refusal(
            session.wrap_native_key(key, target, parameters, capacity),
            "C_WrapKey",
            &mut report,
        )
    })();
    let mut cleanup = Vec::new();
    if let Some(Owner::Session(session)) = &owner {
        for object in keys.iter().rev() {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
    }
    drop(keys);
    if let Some(o) = owner {
        cleanup.extend(o.close(None));
    }
    if let Some(m) = module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup, body, cleanup)
}
