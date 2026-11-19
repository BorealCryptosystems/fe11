// SPDX-License-Identifier: Apache-2.0
//! Native authentication actions without translating unexpected module returns.
use super::{
    authentication_state_case::Case,
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Phase, Report},
};
use fe11::*;
use std::io::Write;
use zeroize::Zeroizing;

pub struct Resources {
    pub peer: Option<Session>,
    pub object: Option<NativeObjectRef>,
    pub closed: bool,
}

pub fn role(state: u64) -> Option<LoginRole> {
    if state == fe11_sys::CKS_RW_SO_FUNCTIONS as u64 {
        Some(LoginRole::SecurityOfficer)
    } else if state == fe11_sys::CKS_RO_USER_FUNCTIONS as u64
        || state == fe11_sys::CKS_RW_USER_FUNCTIONS as u64
    {
        Some(LoginRole::User)
    } else {
        None
    }
}

fn object(session: &Session, case: &Case) -> Result<NativeObjectRef> {
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let template = [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
        ),
        attr(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(case.action.ends_with("_token")),
        ),
        attr(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(case.action.contains("_private_")),
        ),
        attr(
            StandardAttribute::VALUE,
            AttributeInputValue::Bytes(b"public authentication fixture"),
        ),
    ];
    session.create_native_object(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: 64,
        },
    )
}

pub fn check<W: Write>(
    session: &Session,
    context: &TokenContext,
    case: &Case,
    pins: &Credentials,
    resources: &mut Resources,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let officer = role(case.before) == Some(LoginRole::SecurityOfficer);
    let old = if officer && case.action == "set_pin" {
        &*pins.officer
    } else {
        &*pins.user
    };
    let mut new = Zeroizing::new(old.to_vec());
    if let Some(first) = new.first_mut() {
        *first ^= 1;
    } else {
        return Err(Failure::Input("empty_fixture_pin"));
    }
    let result = match case.action.as_str() {
        "login_user" => session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec())),
        "login_user_wrong_pin" => session.login_as(LoginRole::User, SecretPin::new(new.to_vec())),
        "login_named_empty"
        | "login_named_ascii"
        | "login_named_utf8"
        | "login_named_wrong_pin" => {
            let username: &[u8] = match case.action.as_str() {
                "login_named_empty" => b"",
                "login_named_utf8" => "é".as_bytes(),
                _ => b"user",
            };
            let pin = if case.action == "login_named_wrong_pin" {
                new.to_vec()
            } else {
                pins.user.to_vec()
            };
            session.login_user(LoginRole::User, SecretPin::new(pin), username.to_vec())
        }
        "login_so" | "login_so_with_ro_peer" => session.login_as(
            LoginRole::SecurityOfficer,
            SecretPin::new(pins.officer.to_vec()),
        ),
        "logout" => session.logout(),
        "open_ro" | "open_rw" => context
            .open_session(case.action == "open_rw")
            .map(|peer| resources.peer = Some(peer)),
        "close_last" | "close_with_peer" => session.close().map(|()| resources.closed = true),
        "set_pin" => session.change_pin(SecretPin::new(old.to_vec()), SecretPin::new(new.to_vec())),
        "init_pin" => session.initialize_user_pin(SecretPin::new(new.to_vec())),
        _ => object(session, case).map(|object| resources.object = Some(object)),
    };
    match result {
        Ok(()) if case.expected == 0 => (),
        Err(error @ Error::Native { function, code, .. })
            if function == case.function() && code == case.expected =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
        }
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("authentication_refusal_was_success")),
    }
    if resources.closed {
        if case.action == "close_last" {
            resources.peer = Some(context.open_session(case.writable())?);
        }
        let peer = resources
            .peer
            .as_ref()
            .ok_or(Failure::Input("authentication_peer"))?;
        if peer.info()?.state != case.after {
            return Err(Failure::Oracle("authentication_peer_state"));
        }
    } else {
        if session.info()?.state != case.after {
            return Err(Failure::Oracle("authentication_state_after"));
        }
        if let Some(peer) = &resources.peer {
            let expected = if matches!(case.action.as_str(), "open_ro" | "login_so_with_ro_peer") {
                if role(case.after).is_some() {
                    fe11_sys::CKS_RO_USER_FUNCTIONS
                } else {
                    fe11_sys::CKS_RO_PUBLIC_SESSION
                }
            } else if role(case.after) == Some(LoginRole::SecurityOfficer) {
                fe11_sys::CKS_RW_SO_FUNCTIONS
            } else if role(case.after).is_some() {
                fe11_sys::CKS_RW_USER_FUNCTIONS
            } else {
                fe11_sys::CKS_RW_PUBLIC_SESSION
            } as u64;
            if peer.info()?.state != expected {
                return Err(Failure::Oracle("authentication_new_session_state"));
            }
        }
        if matches!(case.action.as_str(), "set_pin" | "init_pin") && case.expected == 0 {
            if role(case.after).is_some() {
                session.logout()?;
            }
            session.login_as(
                if officer && case.action == "set_pin" {
                    LoginRole::SecurityOfficer
                } else {
                    LoginRole::User
                },
                SecretPin::new(new.to_vec()),
            )?;
            session.logout()?;
        }
    }
    Ok(())
}
