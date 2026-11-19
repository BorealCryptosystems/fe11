// SPDX-License-Identifier: Apache-2.0
//! Native object and attribute contracts on isolated caller-owned objects.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};
#[path = "object_contract_certificates.rs"]
mod certificates;
#[path = "object_contract_checks.rs"]
mod checks;
#[path = "object_contract_comparison.rs"]
mod comparison;
#[path = "object_contract_creation.rs"]
mod creation;
#[path = "data_object_lifetime.rs"]
mod data_lifetime;
#[path = "attribute_template_limits.rs"]
mod input_limits;
#[path = "reporting_sentinel.rs"]
mod reporting_sentinel;
#[path = "store_visibility.rs"]
mod store_visibility;
#[path = "object_contract_templates.rs"]
mod templates;
#[path = "object_contract_values.rs"]
mod values;

#[path = "object_contract_dates.rs"]
mod dates;
#[path = "gost_secret_object.rs"]
mod gost_secret;

enum Case {
    GostSecret,
    EmptyDate(bool),
    StoreVisibility(String),
    ReportingSentinel,
    DataLifetime(data_lifetime::Case),
    Flat(String, Vec<u8>),
    Certificate(certificates::Vector),
    Creation(String),
}

const VALUE: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
// The policy witness needs a key admitted by both HMAC mechanisms, so that the
// denied mechanism has no independent key-size fault.
const POLICY_VALUE: &[u8] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const LABEL: &[u8] = &[0, 0x61, 0x62, 0xff];
const ALLOWED: &[u64] = &[fe11_sys::CKM_SHA256_HMAC as u64];
const ACTIONS: &[&str] = &[
    "managed-available",
    "managed-sensitive",
    "empty",
    "short",
    "oversized",
    "sensitive",
    "unknown",
    "unavailable",
    "mixed",
    "order",
    "copy-refusal",
    "read-only",
    "size",
    "allowed",
    "length-only",
    "allocation-limits",
    "nested-wrap",
    "nested-unwrap",
    "input-limits-flat",
    "input-limits-nested",
];
fn limits(count: usize) -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: 0,
        maximum_attributes: count,
        maximum_value_bytes: 256,
    }
}
fn attr(
    attribute: StandardAttribute,
    value: AttributeInputValue<'static>,
) -> AttributeInput<'static> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}
fn template(action: &str) -> Vec<AttributeInput<'static>> {
    let data = action == "empty";
    let protected = matches!(action, "sensitive" | "mixed" | "managed-sensitive");
    let mut fields = vec![
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(if data {
                fe11_sys::CKO_DATA
            } else {
                fe11_sys::CKO_SECRET_KEY
            } as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(false),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(protected),
        ),
        attr(
            StandardAttribute::LABEL,
            AttributeInputValue::Bytes(if matches!(action, "empty" | "unavailable") {
                &[]
            } else {
                LABEL
            }),
        ),
        attr(
            StandardAttribute::VALUE,
            AttributeInputValue::Bytes(if data {
                &[]
            } else if action == "allowed" {
                POLICY_VALUE
            } else {
                VALUE
            }),
        ),
        attr(
            StandardAttribute::MODIFIABLE,
            AttributeInputValue::Boolean(true),
        ),
        attr(
            StandardAttribute::COPYABLE,
            AttributeInputValue::Boolean(action != "copy-refusal"),
        ),
        attr(
            StandardAttribute::DESTROYABLE,
            AttributeInputValue::Boolean(true),
        ),
    ];
    if !data {
        fields.extend([
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            attr(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(protected),
            ),
            attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(!protected),
            ),
            attr(StandardAttribute::SIGN, AttributeInputValue::Boolean(true)),
            attr(
                StandardAttribute::VERIFY,
                AttributeInputValue::Boolean(true),
            ),
        ]);
    }
    if action == "allowed" {
        fields.push(attr(
            StandardAttribute::ALLOWED_MECHANISMS,
            AttributeInputValue::UnsignedArray(ALLOWED),
        ));
    }
    fields
}
fn read(path: &Path) -> std::result::Result<Case, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("object_contract_open"))?
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("object_contract_read"))?;
    if bytes.len() > 65536 {
        return Err(Failure::Input("object_contract_bound"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::Input("object_contract_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() == 2 && fields[0] == "store-process" {
        if !matches!(fields[1], "producer" | "consumer" | "isolated") {
            return Err(Failure::Input("store_process_role"));
        }
        return Ok(Case::StoreVisibility(fields[1].to_owned()));
    }
    match fields.as_slice() {
        ["gost-secret-storage"] => return Ok(Case::GostSecret),
        ["empty-date", "session"] => return Ok(Case::EmptyDate(false)),
        ["empty-date", "advanced"] => return Ok(Case::EmptyDate(true)),
        _ => (),
    }
    if fields == ["reporting-secret-sentinel"] {
        return Ok(Case::ReportingSentinel);
    }
    if fields.first() == Some(&"data-lifetime") {
        return data_lifetime::Case::read(&fields).map(Case::DataLifetime);
    }
    if fields.len() == 1 && creation::ACTIONS.contains(&fields[0]) {
        return Ok(Case::Creation(fields[0].to_owned()));
    }
    if fields
        .first()
        .is_some_and(|action| action.starts_with("certificate-"))
    {
        return certificates::Vector::read(&fields).map(Case::Certificate);
    }
    if bytes.len() > 256 {
        return Err(Failure::Input("object_contract_bound"));
    }
    if fields.len() != 2 || !ACTIONS.contains(&fields[0]) {
        if fields.len() != 2 || !values::ACTIONS.contains(&fields[0]) {
            return Err(Failure::Input("object_contract_fields"));
        }
    }
    let mac = hex(fields[1], 32).map_err(Failure::Input)?;
    let expected = if matches!(fields[0], "order" | "copy-token" | "import-copy-history") {
        16
    } else {
        32
    };
    if mac.len() != expected {
        return Err(Failure::Input("object_contract_mac"));
    }
    Ok(Case::Flat(fields[0].to_owned(), mac))
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let parsed = match read(path) {
        Ok(Case::StoreVisibility(role)) => {
            return store_visibility::execute(module, config, pins, &role, report);
        }
        Ok(Case::ReportingSentinel) => {
            return reporting_sentinel::execute(module, config, pins, report);
        }
        Ok(Case::DataLifetime(case)) => {
            return data_lifetime::execute(module, config, pins, case, report);
        }
        other => other,
    };
    let mut session = None;
    let mut objects = Vec::new();
    let mut date_owner = None;
    let mut logged_in = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = parsed?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("object_contract_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged_in = true;
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            (|| -> std::result::Result<(), Failure> {
                let session = session
                    .as_ref()
                    .ok_or(Failure::Input("object_contract_session"))?;
                let (action, mac) = match case {
                    Case::DataLifetime(_) | Case::ReportingSentinel | Case::StoreVisibility(_) => {
                        return Err(Failure::Input("object_special_dispatch"))
                    }
                    Case::GostSecret => return gost_secret::check(session, &mut objects),
                    Case::EmptyDate(advanced) => {
                        let owner = crate::object_owner::Owner::open(&module, config, advanced)?;
                        return dates::check(&module, date_owner.insert(owner), session, &mut objects);
                    }
                    Case::Creation(action) => {
                        return creation::execute(session, &mut objects, &action, &mut report);
                    }
                    Case::Certificate(vector) => {
                        return certificates::execute(session, &mut objects, &vector, &mut report);
                    }
                    Case::Flat(action, mac) => (action, mac),
                };
                if action.starts_with("input-limits-") {
                    return input_limits::check(
                        &module,
                        session,
                        &mut objects,
                        action.ends_with("nested"),
                    );
                }
                if action.starts_with("nested-") {
                    return templates::execute(session, &mut objects, &action, &mut report);
                }
                if values::ACTIONS.contains(&action.as_str()) {
                    return values::execute(session, &mut objects, &action, &mac, &mut report);
                }
                let mut fields = template(&action);
                objects.push(session.create_native_object(&fields, limits(fields.len()))?);
                if matches!(action.as_str(), "managed-available" | "managed-sensitive") {
                    return comparison::execute(
                        session,
                        &objects[0],
                        action == "managed-sensitive",
                    );
                }
                if action == "order" {
                    fields.reverse();
                    objects.push(session.create_native_object(&fields, limits(fields.len()))?);
                }
                checks::execute(session, &mut objects, &action, &mac, &mut report)
            })(),
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        // Every successful native creation is retained before checking any
        // expectation. Explicit destruction uses references from this isolated case.
        for object in &objects {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(Failure::from(error));
            }
        }
        if let Some(owner) = &date_owner {
            cleanup.extend(owner.close(None));
        }
        if logged_in {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(date_owner);
    drop(objects);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "object_and_attribute_contract",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if setup_result.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
