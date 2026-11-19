// SPDX-License-Identifier: Apache-2.0
//! Real foreign session ownership, abandonment and explicit native closure.
use super::{
    configuration::{select_token, Budgets, Configuration},
    credentials::Credentials,
    foreign_info_image::Image,
    module_controls, native_support,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    ptr,
    sync::{Arc, Mutex},
};

#[path = "foreign_authentication.rs"]
mod authentication;
#[path = "foreign_objects.rs"]
mod objects;

fn require(condition: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("foreign_session_fixture"))?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("foreign_session_fixture"))?;
    let action = match bytes.as_slice() {
        b"prepare\n" => "prepare",
        b"prepare-widths\n" => "prepare-widths",
        b"declarations\n" => "declarations",
        b"open\n" => "open",
        b"close\n" => "close",
        b"take\n" => "take",
        b"authentication\n" => "authentication",
        b"object-destroy\n" => "object-destroy",
        b"object-close\n" => "object-close",
        _ => return Err(Failure::Input("foreign_session_action")),
    };
    Ok(action.into())
}

fn check(
    owner: &RuntimeOwner,
    client: &Module,
    config: &Configuration,
    action: &str,
    selected_token: Option<&TokenIdentity>,
    pins: &Credentials,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let before = client.call_counts()?;
    let token = match selected_token {
        Some(identity) => identity.clone(),
        None => {
            select_token(client, &config.label).ok_or(Failure::Input("foreign_session_token"))?
        }
    };
    let slot =
        CK_SLOT_ID::try_from(token.slot).map_err(|_| Failure::Input("foreign_session_slot"))?;
    let image = Image::load(config)?;
    // SAFETY: adapter uses only this same provider and the matching runtime
    // permits below. It never finalizes or closes a session from a destructor.
    let participant = unsafe { owner.register_foreign(image.clone()) }?;
    if action == "declarations" {
        for (value, layout, operation) in [
            (0, AttributeLayout::Unsigned, ExtensionOperation::GenerateKeyPair),
            (1, AttributeLayout::Boolean, ExtensionOperation::Encrypt),
        ] {
            // SAFETY: standard identifiers 0 and 1 are CKA_CLASS (CK_ULONG)
            // and CKA_TOKEN (CK_BBOOL). No object or value pointer is passed.
            let field = unsafe { client.declare_attribute_extension(value, layout) };
            match field {
                Err(Error::Rejected(RejectionReason::AttributeValues(
                    AttributeValuesRejection::StandardAttributeLayoutCannotBeOverridden))) => (),
                Err(e) => return Err(e.into()),
                Ok(_) => return Err(Failure::Oracle("unexpected_standard_attribute_override")),
            }
            // SAFETY: CKM_RSA_PKCS_KEY_PAIR_GEN and CKM_RSA_PKCS encryption
            // take no mechanism parameter. Their PKCS#11 edition and operation
            // are explicit. No operation is dispatched through this declaration.
            let mechanism = unsafe { client.declare_mechanism_extension(value, (2, 40), operation, false) }?;
            require(mechanism.mechanism_number() == value, "declared_rsa_identifier_width")?;
        }
        drop(participant);
        owner.collect_foreign()?;
        return require(before == client.call_counts()?, "scalar_declarations_dispatched");
    }
    if action == "prepare-widths" {
        for slot in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            let graph = Arc::new(Mutex::new(Box::new(CK_INVALID_HANDLE)));
            // SAFETY: the storage is stable and owned by this preparation.
            // Dropping the unused permit precedes any invocation or callback.
            let prepared = unsafe { participant.prepare_session_open(slot, graph) }?;
            require(prepared.scope() == ForeignScope::Slot(slot)
                && prepared.last_native_step()?.is_none()
                && prepared.last_native_return()?.is_none(), "prepared_slot_width")?;
            drop(prepared);
        }
        drop(participant);
        owner.collect_foreign()?;
        return require(before == client.call_counts()?, "preparing_slot_dispatched");
    }
    let graph = Arc::new(Mutex::new(Box::new(CK_INVALID_HANDLE)));
    // SAFETY: the result address is stable and retained by graph. Application
    // and notification pointers will both be null; there is no callback graph.
    let mut work = Some(unsafe { participant.prepare_session_open(token.slot, graph.clone()) }?);
    let mut native_handle = None;
    let body = (|| -> std::result::Result<(), Failure> {
        let prepared = work
            .as_mut()
            .ok_or(Failure::Input("foreign_session_owner"))?;
        let id = prepared.id();
        require(
            prepared.scope() == ForeignScope::Slot(token.slot)
                && prepared.last_native_step()?.is_none()
                && prepared.last_native_return()?.is_none(),
            "foreign_prepared_session_identity",
        )?;
        if action == "prepare" {
            return require(
                before == client.call_counts()?,
                "foreign_prepare_session_dispatched",
            );
        }
        // Lock before reserving/marking dispatch: a poisoned fixture mutex must
        // not create a fictitious in-flight native invocation.
        let mut output = graph
            .lock()
            .map_err(|_| Failure::Input("foreign_session_buffer"))?;
        let mut call = prepared.begin(ForeignStep::Start)?;
        call.dispatched()?;
        // SAFETY: a real selected slot, serial read-only session, no callback,
        // and writable handle storage held in the registered stable graph.
        let code = unsafe {
            (image.open_session)(
                slot,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut **output,
            )
        };
        if code == CKR_OK {
            native_handle = Some(**output);
        }
        // SAFETY: supply only the observed return. Handle is read only on OK.
        // No callback was supplied, so an ordinary failure retains no callback.
        let receipt = unsafe {
            if code == CKR_PENDING {
                call.returned(code as u64, ForeignCompletion::Uncertain)
            } else {
                call.opened(
                    code as u64,
                    native_handle.unwrap_or(CK_INVALID_HANDLE) as u64,
                )
            }
        };
        require(receipt.code == code as u64, "foreign_session_open_code")?;
        receipt.publication?;
        native_support::status("C_OpenSession", code)?;
        drop(output);
        let handle = native_handle.ok_or(Failure::Oracle("foreign_session_handle"))?;
        require(
            prepared.scope()
                == ForeignScope::Session {
                    slot: token.slot,
                    handle: handle as u64,
                }
                && prepared.last_native_step()? == Some(ForeignStep::Start)
                && prepared.last_native_return()? == Some(CKR_OK as u64),
            "foreign_open_session_identity",
        )?;
        require(
            owner.foreign_status()?.sessions == 1,
            "foreign_live_session_count",
        )?;
        if action == "authentication" {
            return authentication::check(
                &participant,
                prepared,
                &image,
                handle,
                client,
                &token,
                pins,
                cleanup,
            );
        }
        if action == "foreign_slot" {
            // SAFETY: this unissued session-info call owns complete writable
            // CK_SESSION_INFO storage. Its session is the actual opened owner
            // above; no handle or native return is fabricated.
            let output = Arc::new(Mutex::new(Box::new(unsafe {
                std::mem::zeroed::<CK_SESSION_INFO>()
            })));
            // SAFETY: the prepared Call belongs to this same registered
            // participant and real live session. It is never marked dispatched.
            let mut operation = unsafe {
                participant.prepare_operation(
                    prepared,
                    ForeignWorkKind::Call,
                    ForeignAccess::Session,
                    output,
                )
            }?;
            let identity_a = select_token(client, &config.label)
                .ok_or(Failure::Input("foreign_drained_token"))?;
            require(identity_a.slot != token.slot, "foreign_distinct_slots")?;
            let context_a = owner.module().select(&identity_a)?;
            let drain_a = context_a.begin_drain()?;
            match drain_a.begin_foreign(&mut operation, ForeignStep::Start) {
                Err(Error::Rejected(RejectionReason::ExternalExecution(
                    ExternalExecutionRejection::ForeignDrainingSlot,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("foreign_slot_drain_accepted")),
            }
            // B's ordinary admission is still valid. Dropping an unissued
            // guard cancels preparation and makes no native completion claim.
            drop(operation.begin(ForeignStep::Start)?);
            drop(drain_a);
            drop(operation);
        }
        if action == "take" {
            drop(work.take());
            // The native session is genuinely live. Reacquire the same owner
            // before any assertion can fail; a second take must find nothing.
            work = participant.take_abandoned_work()?;
            let recovered = work
                .as_ref()
                .ok_or(Failure::Oracle("foreign_abandoned_missing"))?;
            require(
                recovered.id() == id
                    && recovered.scope()
                        == ForeignScope::Session {
                            slot: token.slot,
                            handle: handle as u64,
                        },
                "foreign_abandoned_identity",
            )?;
            require(
                participant.take_abandoned_work()?.is_none(),
                "foreign_abandoned_taken_twice",
            )?;
        }
        require(
            before == client.call_counts()?,
            "foreign_open_changed_fe11_counts",
        )
    })();
    // Close on every post-open assertion path. This cleanup is itself observed
    // separately and never credited from dropping a Rust owner.
    if let Some(handle) = native_handle {
        let closed = (|| -> std::result::Result<(), Failure> {
            if work.is_none() {
                work = participant.take_abandoned_work()?;
            }
            let work = work.as_mut().ok_or(Failure::Input("foreign_close_owner"))?;
            let mut call = work.begin(ForeignStep::CloseSession)?;
            call.dispatched()?;
            // SAFETY: handle is the actual successful OpenSession result owned
            // by this graph, and no operation or notification callback is live.
            let code = unsafe { (image.close_session)(handle) };
            // SAFETY: only a successful close proves this graph's native
            // lifetime ended. Unexpected failures retain it as uncertain.
            let receipt = unsafe {
                call.returned(
                    code as u64,
                    if code == CKR_OK {
                        ForeignCompletion::Returned
                    } else {
                        ForeignCompletion::Uncertain
                    },
                )
            };
            require(receipt.code == code as u64, "foreign_session_close_code")?;
            receipt.publication?;
            native_support::status("C_CloseSession", code)?;
            require(
                work.last_native_step()? == Some(ForeignStep::CloseSession)
                    && work.last_native_return()? == Some(CKR_OK as u64)
                    && owner.foreign_status()?.sessions == 0,
                "foreign_closed_session_state",
            )?;
            require(
                action == "authentication" || before == client.call_counts()?,
                "foreign_close_changed_fe11_counts",
            )
        })();
        if let Err(error) = closed {
            cleanup.push(error);
        }
    }
    drop(work);
    drop(participant);
    if let Err(error) = owner.collect_foreign() {
        cleanup.push(error.into());
    }
    body
}

pub fn execute<W: Write>(
    arguments: &super::arguments::Arguments,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let config = &arguments.config;
    let action = read(&arguments.vector);
    if let Ok(action @ ("object-destroy" | "object-close")) = action.as_deref() {
        return objects::execute(config, pins, action, report);
    }
    let setup = action.and_then(|action| {
        let (owner, client) = config.builder(&Budgets::ordinary()).open_shared()?;
        Ok((owner, client, action))
    });
    let (owner, client, action) = match setup {
        Ok(value) => value,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), vec![]),
    };
    let mut cleanup = Vec::new();
    let body = check(&owner, &client, config, &action, None, pins, &mut cleanup);
    drop(client);
    if let Err(error) = owner.module().close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, Ok(()), body, cleanup)
}

pub fn execute_other_token<W: Write>(
    config: &Configuration,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let setup = config.builder(&Budgets::ordinary()).open_shared();
    let (owner, client) = match setup {
        Ok(value) => value,
        Err(error) => return module_controls::finish(report, Err(error.into()), Ok(()), vec![]),
    };
    let mut cleanup = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        let token = super::token_drain_session::second_token(owner.module(), config, pins)?;
        check(
            &owner,
            &client,
            config,
            "foreign_slot",
            Some(&token.capabilities().identity),
            pins,
            &mut cleanup,
        )
    })();
    drop(client);
    if let Err(error) = owner.module().close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, Ok(()), body, cleanup)
}
