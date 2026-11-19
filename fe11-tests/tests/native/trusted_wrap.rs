// SPDX-License-Identifier: Apache-2.0
//! Trusted and untrusted wrapping keys are explicitly provisioned by an SO.
use crate::{
    arguments::Arguments,
    credentials::Credentials,
    key_wrap_fixture, module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::{self, Write};

pub(super) fn execute<W: Write>(
    module: Module,
    args: &Arguments,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut authentication = None;
    let mut kek = None;
    let mut trusted_kek = None;
    let mut target = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<(), Failure> {
        let advanced = match args.mode.as_str() {
            "trusted-wrap-session" => false,
            "trusted-wrap-advanced" => true,
            _ => return Err(Failure::Input("trusted_wrap_owner")),
        };
        let token = crate::configuration::select_token(&module, &args.config.label)
            .ok_or(Failure::Input("trusted_wrap_token"))?;
        authentication = Some(module.select(&token)?.open_session(true)?);
        authentication
            .as_ref()
            .ok_or(Failure::Input("trusted_wrap_authentication"))?
            .login_as(
                LoginRole::SecurityOfficer,
                SecretPin::new(pins.officer.to_vec()),
            )?;
        logged = true;
        // Login state belongs to the token. Keep a synchronous authentication
        // owner while exercising either wrapping owner on a second RW session.
        owner = Some(Owner::open(&module, &args.config, advanced)?);
        let o = owner.as_ref().ok_or(Failure::Input("trusted_wrap_owner"))?;
        let kek_bytes = crate::arguments::hex("000102030405060708090a0b0c0d0e0f", 16)
            .map_err(Failure::Input)?;
        let target_bytes = crate::arguments::hex("00112233445566778899aabbccddeeff", 16)
            .map_err(Failure::Input)?;
        kek = Some(o.import_secret(
            &kek_bytes,
            fe11_sys::CKK_AES,
            [StandardAttribute::WRAP, StandardAttribute::UNWRAP],
        )?);
        // TRUSTED can be read-only after creation. Provision its initial value
        // under the SO role instead of assuming a mutable trust attribute.
        let attributes = [
            (
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            (
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_AES as u64),
            ),
            (
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            (
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            (StandardAttribute::WRAP, AttributeInputValue::Boolean(true)),
            (
                StandardAttribute::TRUSTED,
                AttributeInputValue::Boolean(true),
            ),
            (
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&kek_bytes),
            ),
        ]
        .map(|(attribute, value)| AttributeInput {
            attribute: attribute.into(),
            value,
        });
        trusted_kek = Some(o.create(
            &attributes,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: kek_bytes.len() + 20,
            },
        )?);
        target = Some(key_wrap_fixture::import_target_checked(
            o,
            &target_bytes,
            Some("untrusted"),
        )?);
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let o = owner.as_ref().ok_or(Failure::Input("trusted_wrap_owner"))?;
        let kek = kek.as_ref().ok_or(Failure::Input("trusted_wrap_kek"))?;
        let target = target
            .as_ref()
            .ok_or(Failure::Input("trusted_wrap_target"))?;
        let wrap = |key: &NativeObjectRef| match o {
            Owner::Session(s) => {
                s.wrap_native_key(key, target, key_wrap_fixture::parameters(false), 24)
            }
            Owner::Advanced(s) => {
                s.wrap_native_key(key, target, key_wrap_fixture::parameters(false), 24)
            }
        };
        match wrap(kek) {
            Err(
                error @ Error::Native {
                    function: "C_WrapKey",
                    code,
                    may_have_effect: false,
                },
            ) if code == fe11_sys::CKR_KEY_NOT_WRAPPABLE as u64 => {
                outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?
            }
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(Failure::Oracle("untrusted_wrapping_key_accepted")),
        }
        let trusted_kek = trusted_kek
            .as_ref()
            .ok_or(Failure::Input("trusted_wrap_provisioning"))?;
        let read = match o {
            Owner::Session(s) => s.read_flat_attribute(
                trusted_kek,
                StandardAttribute::TRUSTED,
                FlatAttributeReadPlan::Buffer { capacity: 1 },
            ),
            Owner::Advanced(s) => s.read_flat_attribute(
                trusted_kek,
                StandardAttribute::TRUSTED,
                FlatAttributeReadPlan::Buffer { capacity: 1 },
            ),
        }?;
        if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("trusted_readback_status"));
        }
        match read.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == [1] => (),
            _ => return Err(Failure::Oracle("trusted_readback_value")),
        }
        let envelope = wrap(trusted_kek)?;
        let expected =
            crate::arguments::hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", 24)
                .map_err(Failure::Input)?;
        if envelope.as_bytes() != expected {
            return Err(Failure::Oracle("trusted_wrap_rfc3394_answer"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        for key in [target.as_ref(), kek.as_ref(), trusted_kek.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Err(e) = key_wrap_fixture::destroy(o, key) {
                cleanup.push(e.into());
            }
        }
    }
    if let Some(s) = &authentication {
        if logged {
            if let Err(e) = s.logout() {
                cleanup.push(e.into());
            }
        }
    }
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(target);
    drop(kek);
    drop(trusted_kek);
    drop(owner);
    if let Some(s) = &authentication {
        if let Err(e) = s.close() {
            cleanup.push(e.into());
        }
    }
    drop(authentication);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
