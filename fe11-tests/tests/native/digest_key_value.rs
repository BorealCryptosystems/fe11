// SPDX-License-Identifier: Apache-2.0
//! DigestKey must hash the public fixture's value rather than its object handle.
use super::{
    arguments::hex,
    configuration::Configuration,
    module_controls,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::{self, Write};

#[derive(Clone, Copy)]
pub(super) enum ValueCase {
    Sha256,
    Md5,
    SensitiveSha256,
    SensitiveMd5,
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    advanced: bool,
    case: ValueCase,
    mut report: Report<W>,
) -> io::Result<bool> {
    let sensitive = matches!(case, ValueCase::SensitiveSha256 | ValueCase::SensitiveMd5);
    let md5 = matches!(case, ValueCase::Md5 | ValueCase::SensitiveMd5);
    let algorithm = if md5 {
        NativeDigestAlgorithm::Md5
    } else {
        NativeDigestAlgorithm::Sha256
    };
    let mut owner = None;
    let mut key = None;
    let mut ticket = None;
    let setup = (|| -> std::result::Result<(), Failure> {
        owner = Some(Owner::open(&module, config, advanced)?);
        let field = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            field(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            field(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            field(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            field(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            field(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(sensitive),
            ),
            field(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(true),
            ),
            field(StandardAttribute::VALUE, AttributeInputValue::Bytes(b"abc")),
        ];
        key = Some(
            owner
                .as_ref()
                .ok_or(Failure::Input("digest_key_owner"))?
                .create(
                    &template,
                    AttributeTemplateLimits {
                        maximum_depth: 0,
                        maximum_attributes: template.len(),
                        maximum_value_bytes: 64,
                    },
                )?,
        );
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let owner = owner.as_ref().ok_or(Failure::Input("digest_key_owner"))?;
        let key = key.as_ref().ok_or(Failure::Input("digest_key_object"))?;
        ticket = Some(match owner {
            Owner::Session(s) => s.begin_native_digest(algorithm)?,
            Owner::Advanced(s) => s.begin_native_digest(algorithm)?,
        });
        let ticket = ticket.as_mut().ok_or(Failure::Input("digest_key_ticket"))?;
        let result = match owner {
            Owner::Session(s) => s.digest_key(ticket, key),
            Owner::Advanced(s) => s.digest_key(ticket, key),
        };
        if matches!(case, ValueCase::SensitiveMd5) {
            // The selected recipe refuses this key/mechanism combination.
            // SHA-256 is a separate positive control, not a universal refusal rule.
            return match result {
                Err(
                    error @ Error::Native {
                        function: "C_DigestKey",
                        code,
                        ..
                    },
                ) if code == fe11_sys::CKR_KEY_INDIGESTIBLE as u64 => {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("digest_key_report"))
                }
                Err(error) => Err(error.into()),
                Ok(()) => Err(Failure::Oracle("sensitive_digest_key_refusal_missing")),
            };
        }
        result?;
        let digest = match owner {
            Owner::Session(s) => s.finish_native_digest(ticket)?,
            Owner::Advanced(s) => match s.finish_native_digest(ticket)? {
                OperationProgress::NativeDigest(value) => value,
                _ => return Err(Failure::Oracle("digest_key_completion")),
            },
        };
        let expected = hex(
            if md5 {
                "900150983cd24fb0d6963f7d28e17f72"
            } else {
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            },
            32,
        )
        .map_err(Failure::Input)?;
        if digest.algorithm() != algorithm || digest.as_bytes() != expected {
            return Err(Failure::Oracle("digest_key_value_and_length"));
        }
        Ok(())
    })();
    drop(ticket);
    // A rejected DigestKey can leave the native digest active. Its key is a
    // session object: closing the owner ends the operation and destroys the
    // object together, without attempting an unrelated mutation mid-operation.
    let destroy = if matches!(case, ValueCase::SensitiveMd5) {
        None
    } else {
        key.as_ref()
    };
    let mut cleanup = owner.as_ref().map(|o| o.close(destroy)).unwrap_or_default();
    drop(key);
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
