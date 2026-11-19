// SPDX-License-Identifier: Apache-2.0
//! Object visibility after authentication and the last owning session closes.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_transition_fixture::{check, find, label_template, limits, read, Case, Fixture},
    outcome::Failure,
};
use fe11::*;

fn flags(
    session: &Session,
    object: &NativeObjectRef,
    case: &Case,
) -> std::result::Result<(), Failure> {
    for (attribute, expected) in [
        (StandardAttribute::TOKEN, case.token),
        (StandardAttribute::PRIVATE, case.private),
        (StandardAttribute::SIGN, true),
        (StandardAttribute::VERIFY, true),
        (StandardAttribute::SENSITIVE, false),
        (StandardAttribute::EXTRACTABLE, true),
        (StandardAttribute::COPYABLE, true),
        (StandardAttribute::MODIFIABLE, true),
        (StandardAttribute::DESTROYABLE, true),
    ] {
        let value = session.read_flat_attribute(
            object,
            attribute,
            FlatAttributeReadPlan::Buffer { capacity: 1 },
        )?;
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) || value.boolean()? != expected {
            return Err(Failure::Oracle("object_lifetime_attribute_changed"));
        }
    }
    Ok(())
}

fn selected(f: &Fixture, case: &Case, present: bool) -> std::result::Result<(), Failure> {
    let objects = find(f.peer()?, &f.label)?;
    if objects.len() != usize::from(present) {
        return Err(Failure::Oracle("object_lifetime_visibility"));
    }
    if let Some(object) = objects.first() {
        check(&read(f.peer()?, object, &f.label)?, &f.label)?;
        flags(f.peer()?, object, case)?;
    }
    Ok(())
}

fn stale<T>(result: Result<T>) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::ObjectReferences(
            ObjectReferencesRejection::ForeignOrStaleNativeObject,
        ))) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("object_lifetime_stale_reference_accepted")),
    }
}

pub fn execute(
    f: &mut Fixture,
    module: &Module,
    config: &Configuration,
    case: &Case,
    pins: &Credentials,
) -> std::result::Result<(), Failure> {
    match case.action.as_str() {
        "shared_login" => {
            if !case.private || !case.token || case.state != "LIVE" {
                return Err(Failure::Input("shared_login_private_token_fixture"));
            }
            // Preparation authenticated the peer. Exercise the independently
            // opened creator, which has made no Login call of its own.
            let creator = f.creator.as_ref().ok_or(Failure::Input("object_creator"))?;
            let original = f
                .original
                .as_ref()
                .ok_or(Failure::Input("object_original"))?;
            for session in [creator, f.peer()?] {
                if session.info()?.state != fe11_sys::CKS_RW_USER_FUNCTIONS as u64 {
                    return Err(Failure::Oracle("shared_login_user_state"));
                }
            }
            let mac = creator.compute_native_mac(
                original,
                NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
                MessageRoute::Single,
                &[b"abc"],
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
                32,
                None,
            )?;
            if mac.as_bytes() != case.expected_mac {
                return Err(Failure::Oracle("shared_login_private_key_mac"));
            }
            f.peer()?.logout()?;
            f.logged = false;
            if creator.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("shared_logout_public_state"));
            }
            match read(creator, original, &f.label) {
                Err(Error::Native {
                    function: "C_GetAttributeValue",
                    code,
                    ..
                }) if code == fe11_sys::CKR_OBJECT_HANDLE_INVALID as u64 => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("shared_logout_private_access")),
            }
            // The token object survives Logout but its former private handles
            // do not. Cleanup reacquires a fresh reference after authentication.
            f.login(pins)?;
        }
        "mutate_label" => {
            flags(f.peer()?, f.object()?, case)?;
            f.peer()?.set_native_attributes(
                f.object()?,
                &label_template(&f.changed),
                limits(1, f.changed.len()),
            )?;
            let before = module.call_counts()?;
            stale(read(f.peer()?, f.object()?, &f.label))?;
            if module.call_counts()? != before {
                return Err(Failure::Oracle("object_mutation_stale_dispatch"));
            }
            if !find(f.peer()?, &f.label)?.is_empty() {
                return Err(Failure::Oracle("object_mutation_old_label"));
            }
            let objects = find(f.peer()?, &f.changed)?;
            if objects.len() != 1 {
                return Err(Failure::Oracle("object_mutation_new_label"));
            }
            check(&read(f.peer()?, &objects[0], &f.changed)?, &f.changed)?;
            flags(f.peer()?, &objects[0], case)?;
        }
        "destroy_again" => {
            let before = module.call_counts()?;
            stale(f.peer()?.destroy_native_object(f.object()?))?;
            if module.call_counts()? != before {
                return Err(Failure::Oracle("object_repeat_destroy_dispatch"));
            }
            selected(f, case, false)?;
        }
        "logout" => {
            f.peer()?.logout()?;
            f.logged = false;
            if case.private {
                match read(f.peer()?, f.object()?, &f.label) {
                    Err(Error::Native {
                        function: "C_GetAttributeValue",
                        code,
                        ..
                    }) if code == fe11_sys::CKR_OBJECT_HANDLE_INVALID as u64 => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("private_object_visible_after_logout")),
                }
            } else {
                check(&read(f.peer()?, f.object()?, &f.label)?, &f.label)?;
                flags(f.peer()?, f.object()?, case)?;
            }
            selected(f, case, !case.private)?;
            f.login(pins)?;
            selected(f, case, !case.private || case.token)?;
        }
        "close_last" => {
            f.peer()?.close()?;
            f.peer_closed = true;
            f.creator
                .as_ref()
                .ok_or(Failure::Input("object_creator"))?
                .close()?;
            f.creator_closed = true;
            f.logged = false;
            // Retire the old peer and all old references from use. Visibility is
            // observed through a genuinely new session, first public then USER.
            let token =
                select_token(module, &config.label).ok_or(Failure::Input("object_token"))?;
            f.peer = Some(module.select(&token)?.open_session(true)?);
            f.peer_closed = false;
            if f.peer()?.info()?.state != fe11_sys::CKS_RW_PUBLIC_SESSION as u64 {
                return Err(Failure::Oracle("last_close_authentication_reset"));
            }
            selected(f, case, case.token && !case.private)?;
            f.login(pins)?;
            selected(f, case, case.token)?;
        }
        _ => return Err(Failure::Input("object_lifetime_action")),
    }
    Ok(())
}
