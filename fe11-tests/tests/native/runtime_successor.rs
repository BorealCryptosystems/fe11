// SPDX-License-Identifier: Apache-2.0
//! Owner-authorized generation replacement, distinct from external native loss.
use super::{
    arguments::hex,
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
    num::NonZeroUsize,
    path::Path,
    ptr,
};

type Answer<T> = std::result::Result<T, Failure>;
const LABEL: &[u8] = b"generation-object";
const VALUE: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn limits(count: usize) -> AttributeTemplateLimits {
    AttributeTemplateLimits {
        maximum_depth: 0,
        maximum_attributes: count,
        maximum_value_bytes: 128,
    }
}

fn field(attribute: StandardAttribute, value: AttributeInputValue<'_>) -> AttributeInput<'_> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}

fn create(session: &Session, token: bool) -> Result<NativeObjectRef> {
    let template = [
        field(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(CKO_SECRET_KEY as u64),
        ),
        field(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(CKK_GENERIC_SECRET as u64),
        ),
        field(
            StandardAttribute::TOKEN,
            AttributeInputValue::Boolean(token),
        ),
        field(
            StandardAttribute::PRIVATE,
            AttributeInputValue::Boolean(false),
        ),
        field(
            StandardAttribute::SENSITIVE,
            AttributeInputValue::Boolean(false),
        ),
        field(
            StandardAttribute::EXTRACTABLE,
            AttributeInputValue::Boolean(true),
        ),
        field(StandardAttribute::LABEL, AttributeInputValue::Bytes(LABEL)),
        field(StandardAttribute::VALUE, AttributeInputValue::Bytes(VALUE)),
    ];
    session.create_native_object(&template, limits(template.len()))
}

fn successor(config: &Configuration, old: &Module, attached: bool) -> Answer<Module> {
    let builder = config.builder(&Budgets::ordinary());
    if !attached {
        return Ok(old.successor(builder)?);
    }
    let image = Image::load(config)?;
    let initialize = native_support::required(image.identity.initialize)?;
    let finalize = native_support::required(image.identity.finalize)?;
    // SAFETY: callbacks and reserved are NULL; only OS-locking is requested.
    let mut args: CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
    args.flags = CKF_OS_LOCKING_OK;
    // SAFETY: the previous owner has successfully finalized this exact image.
    // No old session or invocation remains; the descriptor lives through return.
    native_support::status("C_Initialize", unsafe {
        initialize((&mut args as *mut CK_C_INITIALIZE_ARGS).cast())
    })?;
    // SAFETY: the application owns the quiescent new initialization. No foreign
    // sessions exist, and the image lease has no native lifecycle destructor.
    let declaration = unsafe {
        ExternalInitialization::new(
            image.identity,
            ExternalConcurrency::Concurrent,
            image.clone(),
        )
    };
    // SAFETY: attachment transfers global authority before any new session or
    // client is created. The retired generation is never silently reactivated.
    match unsafe { old.attach_successor(builder, declaration) } {
        Ok(module) => Ok(module),
        Err(error) => {
            // SAFETY: attachment failed before any new caller or session was
            // published. The application still owns this idle initialization.
            native_support::status("C_Finalize", unsafe { finalize(ptr::null_mut()) })?;
            Err(error.into())
        }
    }
}

fn read_value(session: &Session, object: &NativeObjectRef) -> Answer<FlatAttributeObservation> {
    Ok(session.read_flat_attribute(
        object,
        StandardAttribute::VALUE,
        FlatAttributeReadPlan::Buffer {
            capacity: VALUE.len(),
        },
    )?)
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut old = None;
    let mut old_sessions = Vec::new();
    let mut old_closed = false;
    let mut new = None;
    let mut new_session = None;
    let mut found = Vec::new();
    let mut objects = Vec::new();
    let mut cleanup = Vec::new();
    let setup = (|| -> Answer<bool> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("successor_fixture_open"))?
            .take(17)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("successor_fixture_read"))?;
        let attached = match data.as_slice() {
            b"owned\n" => false,
            b"attached\n" => true,
            _ => return Err(Failure::Input("successor_fixture")),
        };
        old = Some(config.open(&Budgets::ordinary())?);
        let module = old.as_ref().ok_or(Failure::Input("successor_old_module"))?;
        let token = select_token(module, &config.label).ok_or(Failure::Input("successor_token"))?;
        for _ in 0..2 {
            old_sessions.push(module.select(&token)?.open_session(true)?);
        }
        old_sessions[0].login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        Ok(attached)
    })();
    let body = (|| -> Answer<()> {
        let attached = match &setup {
            Ok(value) => *value,
            Err(_) => return Ok(()),
        };
        let module = old.as_ref().ok_or(Failure::Input("successor_old_module"))?;
        let session = old_sessions
            .first()
            .ok_or(Failure::Input("successor_old_session"))?;
        objects.push(create(session, true)?);
        objects.push(create(session, false)?);
        let observed = read_value(session, &objects[0])?;
        let digest = session.digest_multipart(
            HashAlgorithm::Sha256,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        for session in &old_sessions {
            session.close()?;
        }
        old_sessions.clear();
        module.close()?;
        old_closed = true;
        let expected = hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            32,
        )
        .map_err(Failure::Input)?;
        if digest.as_bytes() != expected {
            return Err(Failure::Oracle("closed_owner_digest_changed"));
        }
        match observed.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == VALUE => (),
            _ => return Err(Failure::Oracle("closed_owner_attribute_changed")),
        }
        new = Some(successor(config, module, attached)?);
        let next = new.as_ref().ok_or(Failure::Input("successor_new_module"))?;
        let before = next.call_counts()?;
        match module.successor(config.builder(&Budgets::ordinary())) {
            Err(Error::Rejected(RejectionReason::NativeExecution(
                NativeExecutionRejection::RuntimeSuccessorAlreadyPublished,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(unexpected) => {
                if let Err(error) = unexpected.close() {
                    cleanup.push(error.into());
                }
                return Err(Failure::Oracle("successor_published_twice"));
            }
        }
        if next.call_counts()? != before {
            return Err(Failure::Oracle("second_successor_dispatched"));
        }
        let token =
            select_token(next, &config.label).ok_or(Failure::Input("successor_new_token"))?;
        new_session = Some(next.select(&token)?.open_session(true)?);
        let session = new_session
            .as_ref()
            .ok_or(Failure::Input("successor_new_session"))?;
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        let before = next.call_counts()?;
        for object in &objects {
            match read_value(session, object) {
                Err(Failure::Product(Error::Rejected(RejectionReason::ObjectReferences(
                    ObjectReferencesRejection::ForeignNativeObject,
                )))) => (),
                Err(error) => return Err(error),
                Ok(_) => return Err(Failure::Oracle("successor_old_reference_rebound")),
            }
        }
        if next.call_counts()? != before {
            return Err(Failure::Oracle("old_reference_dispatched"));
        }
        let template = [field(
            StandardAttribute::LABEL,
            AttributeInputValue::Bytes(LABEL),
        )];
        let batch = NonZeroUsize::new(2).ok_or(Failure::Input("successor_search_batch"))?;
        {
            let mut iterator = session.iter_native_objects(&template, limits(1), batch)?;
            for object in &mut iterator {
                found.push(object?);
            }
        }
        if found.len() != 1 {
            return Err(Failure::Oracle("successor_object_population"));
        }
        match read_value(session, &found[0])?.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == VALUE => (),
            _ => return Err(Failure::Oracle("successor_token_value_changed")),
        }
        // This session deliberately remains authenticated. The generic fresh
        // public-session witness has a different precondition and cannot be
        // reused here without losing the user-state contract of this scenario.
        if session.info()?.state != CKS_RW_USER_FUNCTIONS as u64 {
            return Err(Failure::Oracle("successor_user_session_state"));
        }
        let fresh = session.digest_multipart(
            HashAlgorithm::Sha256,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        if fresh.as_bytes() != expected {
            return Err(Failure::Oracle("successor_new_digest"));
        }
        Ok(())
    })();
    if let Some(session) = &new_session {
        for object in &found {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(new_session);
    if let Some(module) = &new {
        if let Err(error) = module.close() {
            cleanup.push(error.into());
        }
    }
    if !old_closed {
        if let Some(session) = old_sessions.first() {
            for object in &objects {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
    } else if !objects.is_empty() && found.is_empty() {
        // The runner still removes the isolated token directory. Report that
        // explicit object cleanup was not reached; never call that cleanup PASS.
        cleanup.push(Failure::Oracle("successor_token_cleanup_not_reached"));
    }
    for session in &old_sessions {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(old_sessions);
    if !old_closed {
        if let Some(module) = &old {
            if let Err(error) = module.close() {
                cleanup.push(error.into());
            }
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
