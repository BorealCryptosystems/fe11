// SPDX-License-Identifier: Apache-2.0
//! Exercise a private session key without publishing its credential-derived marker.
use super::{select_token, Configuration, Credentials, Failure, Report};
use crate::module_controls;
use fe11::*;
use std::io::{self, Write};

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut key = None;
    let mut logged = false;
    // Independent marker from the ephemeral user PIN, known to the supervisor.
    // This copy is wiped on every exit; interpreter/OS/native copies are outside
    // this Rust owner's erasure guarantee. No bytes enter an observation record.
    let value = zeroize::Zeroizing::new(pins.user.iter().map(|b| b ^ 0xa5).collect::<Vec<_>>());
    let setup = (|| -> std::result::Result<(), Failure> {
        if value.len() != 16 {
            return Err(Failure::Input("reporting_marker_width"));
        }
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("reporting_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        let s = session
            .as_ref()
            .ok_or(Failure::Input("reporting_session"))?;
        s.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        let attribute = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let fields = [
            attribute(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attribute(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            attribute(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attribute(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(true),
            ),
            attribute(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(true),
            ),
            attribute(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(false),
            ),
            attribute(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
            attribute(
                StandardAttribute::VERIFY,
                AttributeInputValue::Boolean(true),
            ),
            attribute(StandardAttribute::VALUE, AttributeInputValue::Bytes(&value)),
        ];
        key = Some(s.create_native_object(
            &fields,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: fields.len(),
                maximum_value_bytes: 64,
            },
        )?);
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let s = session
            .as_ref()
            .ok_or(Failure::Input("reporting_session"))?;
        let key = key.as_ref().ok_or(Failure::Input("reporting_key"))?;
        let parameters = || NativeMacParameters::Full(NativeMacAlgorithm::MD5_HMAC);
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let mac = s.compute_native_mac(
            key,
            parameters(),
            MessageRoute::Single,
            &[b"abc"],
            limits,
            16,
            None,
        )?;
        if mac.as_bytes().len() != 16 {
            return Err(Failure::Oracle("reporting_mac_width"));
        }
        s.verify_native_mac(
            key,
            parameters(),
            MessageRoute::Single,
            &[b"abc"],
            mac.as_bytes(),
            limits,
            None,
        )?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(s) = &session {
        if let Some(key) = &key {
            if let Err(e) = s.destroy_native_object(key) {
                cleanup.push(e.into());
            }
        }
        if logged {
            if let Err(e) = s.logout() {
                cleanup.push(e.into());
            }
        }
        if let Err(e) = s.close() {
            cleanup.push(e.into());
        }
    }
    drop(key);
    drop(session);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
