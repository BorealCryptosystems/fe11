// SPDX-License-Identifier: Apache-2.0
//! Separate-process token persistence and disjoint-store visibility.
//!
//! The producer transfers an owned public token object to the supervisor's
//! subsequent consumer. It is not a session object or a concurrent-close test.
use super::{select_token, Configuration, Credentials, Failure, Report};
use crate::{module_controls, object_transition_fixture::find};
use fe11::*;
use std::io::{self, Write};

const LABEL: &[u8] = b"public-store-visibility";
const ORIGINAL: &[u8] = b"store-A\0object";
const ISOLATED: &[u8] = b"store-B\0object";

fn read_value(session: &Session, object: &NativeObjectRef, expected: &[u8]) -> Result<bool> {
    let request = [FlatAttributeRequest {
        attribute: StandardAttribute::VALUE.into(),
        plan: FlatAttributeReadPlan::Buffer {
            capacity: expected.len(),
        },
    }];
    let values = session.read_flat_attributes(object, &request, expected.len())?;
    if values.len() != 1
        || values.calls()
            != AttributeBatchCalls::One(AttributeBatchCall {
                code: 0,
                attribute_count: 1,
            })
    {
        return Ok(false);
    }
    let matches = values.iter().any(|entry| {
        matches!(&entry.value,
        FlatAttributeValue::Available(value) if value.as_bytes() == expected)
    });
    Ok(matches)
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    pins: &Credentials,
    role: &str,
    report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut object = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<(), Failure> {
        let token = select_token(&module, &config.label).ok_or(Failure::Input("store_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("store_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let session = session.as_ref().ok_or(Failure::Input("store_session"))?;
        let mut found = find(session, LABEL)?;
        if role == "consumer" {
            if found.len() != 1 {
                return Err(Failure::Oracle("cross_process_token_missing"));
            }
            object = found.pop();
        } else {
            if !found.is_empty() {
                return Err(Failure::Oracle("fresh_store_object_visible"));
            }
            let value = if role == "isolated" {
                ISOLATED
            } else {
                ORIGINAL
            };
            let fields = [
                (
                    StandardAttribute::CLASS,
                    AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
                ),
                (StandardAttribute::TOKEN, AttributeInputValue::Boolean(true)),
                (
                    StandardAttribute::PRIVATE,
                    AttributeInputValue::Boolean(false),
                ),
                (StandardAttribute::LABEL, AttributeInputValue::Bytes(LABEL)),
                (StandardAttribute::VALUE, AttributeInputValue::Bytes(value)),
            ]
            .map(|(attribute, value)| AttributeInput {
                attribute: attribute.into(),
                value,
            });
            object = Some(session.create_native_object(
                &fields,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: fields.len(),
                    maximum_value_bytes: 128,
                },
            )?);
        }
        let expected = if role == "isolated" {
            ISOLATED
        } else {
            ORIGINAL
        };
        if !read_value(
            session,
            object.as_ref().ok_or(Failure::Input("store_object"))?,
            expected,
        )? {
            return Err(Failure::Oracle("store_object_value"));
        }
        if role != "producer" {
            session
                .destroy_native_object(object.as_ref().ok_or(Failure::Input("store_object"))?)?;
            object = None;
            if !find(session, LABEL)?.is_empty() {
                return Err(Failure::Oracle("store_object_not_destroyed"));
            }
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(session) = &session {
        // Only a successful producer transfers ownership. On failure it tries
        // destruction; the supervisor always removes its disposable store too.
        if body.is_err() {
            if let Some(object) = &object {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        drop(object);
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
