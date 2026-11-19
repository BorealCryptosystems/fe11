// SPDX-License-Identifier: Apache-2.0
//! Published PQC signatures and precisely attributed native negative answers.
use super::{
    object_owner::Owner,
    outcome::{self, Failure},
    pqc_fixture::Vector,
    report::{Phase, Report},
};
use fe11::*;
use std::{fs::OpenOptions, io::Write};

#[path = "pqc_value_export.rs"]
mod value_export;

pub fn import(owner: &Owner, v: &Vector) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let value = if v.sign { &v.private } else { &v.public };
    let mut template = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(if v.sign {
                fe11_sys::CKO_PRIVATE_KEY as u64
            } else {
                fe11_sys::CKO_PUBLIC_KEY as u64
            }),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(v.parameters.key_type),
        ),
        attr(
            StandardAttribute::PARAMETER_SET,
            AttributeInputValue::Unsigned(v.parameters.set),
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
            if v.sign {
                StandardAttribute::SIGN
            } else {
                StandardAttribute::VERIFY
            },
            AttributeInputValue::Boolean(true),
        ),
        attr(StandardAttribute::VALUE, AttributeInputValue::Bytes(value)),
    ];
    if let Some(sensitive) = v.export_sensitive {
        template.push(attr(
            StandardAttribute::SENSITIVE,
            AttributeInputValue::Boolean(sensitive),
        ));
        template.push(attr(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(true),
        ));
    }
    owner.create(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: 27
                + value.len()
                + if v.export_sensitive.is_some() { 2 } else { 0 },
        },
    )
}

fn rejected<W: Write>(
    result: Result<()>,
    length_error: bool,
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
        ) if actual == function
            && (code == fe11_sys::CKR_SIGNATURE_INVALID as u64
                || (length_error && code == fe11_sys::CKR_SIGNATURE_LEN_RANGE as u64)) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("invalid_pqc_signature_accepted")),
    }
}

pub fn check<W: Write>(
    owner: &Owner,
    key: &NativeObjectRef,
    v: &Vector,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if let Some(sensitive) = v.export_sensitive {
        return value_export::check(owner, key, &v.private, sensitive, report);
    }
    let whole = [v.message.as_slice()];
    let middle = v.message.len() / 2;
    // Preserve the original bytes, including a genuine empty native Update.
    let split = [
        &v.message[..middle],
        &v.message[middle..middle],
        &v.message[middle..],
    ];
    let parts = if v.multipart {
        split.as_slice()
    } else {
        whole.as_slice()
    };
    let route = if v.multipart {
        MessageRoute::Multipart
    } else {
        MessageRoute::Single
    };
    let terminal = if v.multipart {
        "C_VerifyFinal"
    } else {
        "C_Verify"
    };
    let limits = InputLimits {
        maximum_parts: parts.len(),
        maximum_total_bytes: v.message.len(),
    };
    if v.sign {
        let signature = match owner {
            Owner::Session(s) => s.sign_native(
                key,
                v.mechanism(),
                route,
                parts,
                limits,
                v.parameters.signature_bytes,
                None,
            ),
            Owner::Advanced(s) => s.sign_native(
                key,
                v.mechanism(),
                route,
                parts,
                limits,
                v.parameters.signature_bytes,
                None,
            ),
        }?;
        if v.randomized {
            if signature.as_bytes().len() != v.parameters.signature_bytes {
                return Err(Failure::Oracle("pqc_signature_width"));
            }
            // Public signature only; the supervisor verifies it through the
            // independently invoked reference before assigning the case verdict.
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options
                .open("public-pqc-signature.bin")
                .map_err(|_| Failure::Input("pqc_output_create"))?;
            output
                .write_all(signature.as_bytes())
                .map_err(|_| Failure::Input("pqc_output_write"))?;
            output
                .flush()
                .map_err(|_| Failure::Input("pqc_output_flush"))?;
        } else if signature.as_bytes() != v.signature {
            return Err(Failure::Oracle("pqc_known_signature"));
        }
    } else {
        let result =
            owner.verify_parameters(key, v.mechanism(), route, parts, &v.signature, limits);
        if !v.valid {
            return rejected(
                result,
                v.signature.len() != v.parameters.signature_bytes,
                terminal,
                report,
            );
        }
        result?;
        let mut altered = v.signature.clone();
        *altered
            .last_mut()
            .ok_or(Failure::Input("pqc_signature_empty"))? ^= 1;
        rejected(
            owner.verify_parameters(key, v.mechanism(), route, parts, &altered, limits),
            false,
            terminal,
            report,
        )?;
    }
    Ok(())
}
