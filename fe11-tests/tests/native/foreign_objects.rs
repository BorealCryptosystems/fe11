// SPDX-License-Identifier: Apache-2.0
//! A direct-C peer changes real object lifetime between sequential Fe11 calls.
//! The peer owns only its own session and object; it never finalizes the module.
use super::super::{
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
    io::{self, Write},
    num::NonZeroUsize,
    ptr,
};

type Answer<T> = std::result::Result<T, Failure>;

fn search(session: &Session, label: &[u8]) -> Result<NativeObjectMatches> {
    let template = [AttributeInput {
        attribute: StandardAttribute::LABEL.into(),
        value: AttributeInputValue::Bytes(label),
    }];
    session.find_native_objects(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: 1,
            maximum_value_bytes: label.len(),
        },
        SearchPlan {
            maximum_objects: Some(2),
            batch_size: NonZeroUsize::new(1).unwrap(),
        },
    )
}

fn create(
    image: &Image,
    session: CK_SESSION_HANDLE,
    label: &[u8],
    token: bool,
) -> Answer<CK_OBJECT_HANDLE> {
    let function = native_support::required(image.create_object)?;
    let mut class = CKO_DATA;
    let mut persistence = if token { CK_TRUE } else { CK_FALSE };
    let mut private = CK_FALSE;
    let mut label = label.to_vec();
    let mut value = *b"public peer-owned value";
    let mut attributes = [
        CK_ATTRIBUTE {
            r#type: CKA_CLASS,
            pValue: (&mut class as *mut CK_OBJECT_CLASS).cast(),
            ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            r#type: CKA_TOKEN,
            pValue: (&mut persistence as *mut CK_BBOOL).cast(),
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            r#type: CKA_PRIVATE,
            pValue: (&mut private as *mut CK_BBOOL).cast(),
            ulValueLen: 1,
        },
        CK_ATTRIBUTE {
            r#type: CKA_LABEL,
            pValue: label.as_mut_ptr().cast(),
            ulValueLen: CK_ULONG::try_from(label.len())
                .map_err(|_| Failure::Input("peer_label_width"))?,
        },
        CK_ATTRIBUTE {
            r#type: CKA_VALUE,
            pValue: value.as_mut_ptr().cast(),
            ulValueLen: value.len() as CK_ULONG,
        },
    ];
    let mut object = CK_INVALID_HANDLE;
    // SAFETY: the trusted synchronous provider receives live bounded input
    // fields and one writable output. No callback or async entry is involved;
    // C_CreateObject retains its object contents, not these caller pointers.
    let code = unsafe {
        function(
            session,
            attributes.as_mut_ptr(),
            attributes.len() as CK_ULONG,
            &mut object,
        )
    };
    native_support::status("C_CreateObject", code)?;
    if object == CK_INVALID_HANDLE {
        return Err(Failure::Oracle("peer_created_invalid_handle"));
    }
    Ok(object)
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    pins: &Credentials,
    action: &str,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut subject = None;
    let mut image = None;
    let mut peer = None;
    let mut object = None;
    let mut logged = false;
    let token_object = action == "object-destroy";
    let label = format!("{}:foreign-object", config.label).into_bytes();
    let setup = (|| -> Answer<()> {
        if !matches!(action, "object-destroy" | "object-close") {
            return Err(Failure::Input("peer_object_action"));
        }
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("peer_object_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("peer_object_token"))?;
        subject = Some(m.select(&token)?.open_session(true)?);
        subject
            .as_ref()
            .ok_or(Failure::Input("peer_object_subject"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        image = Some(Image::load(config)?);
        let i = image.as_ref().ok_or(Failure::Input("peer_object_image"))?;
        native_support::required(i.create_object)?;
        native_support::required(i.destroy_object)?;
        let slot =
            CK_SLOT_ID::try_from(token.slot).map_err(|_| Failure::Input("peer_object_slot"))?;
        let mut handle = CK_INVALID_HANDLE;
        // SAFETY: same loaded image, selected slot and writable output; no
        // application pointer or notification callback, serial RW peer session.
        native_support::status("C_OpenSession", unsafe {
            (i.open_session)(
                slot,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        })?;
        peer = Some(handle);
        object = Some(create(i, handle, &label, token_object)?);
        Ok(())
    })();
    let body = (|| -> Answer<()> {
        if setup.is_err() {
            return Ok(());
        }
        let s = subject
            .as_ref()
            .ok_or(Failure::Input("peer_object_subject"))?;
        let m = module
            .as_ref()
            .ok_or(Failure::Input("peer_object_module"))?;
        let i = image.as_ref().ok_or(Failure::Input("peer_object_image"))?;
        let handle = peer.ok_or(Failure::Input("peer_object_session"))?;
        let found = search(s, &label)?;
        if found.as_slice().len() != 1 {
            return Err(Failure::Oracle("peer_object_not_visible"));
        }
        let reference = &found.as_slice()[0];
        let value = s.read_flat_attribute(
            reference,
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer { capacity: 23 },
        )?;
        match value.value {
            FlatAttributeValue::Available(bytes)
                if bytes.as_bytes() == b"public peer-owned value" =>
            {
                ()
            }
            _ => return Err(Failure::Oracle("peer_object_value")),
        }
        let counts = m.call_counts()?;
        if token_object {
            let destroy = native_support::required(i.destroy_object)?;
            let key = object.ok_or(Failure::Input("peer_object_handle"))?;
            // SAFETY: this exact token object was created by this peer. No
            // Fe11 handle is inspected or converted into a raw identifier.
            native_support::status("C_DestroyObject", unsafe { destroy(handle, key) })?;
            object = None;
        } else {
            // SAFETY: only the peer-owned session is closed, synchronously.
            // Its session objects disappear by the PKCS#11 ownership contract.
            native_support::status("C_CloseSession", unsafe { (i.close_session)(handle) })?;
            peer = None;
            object = None;
        }
        if m.call_counts()? != counts {
            return Err(Failure::Oracle("peer_changed_local_counters"));
        }
        match s.read_flat_attribute(
            reference,
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer { capacity: 23 },
        ) {
            Err(Error::Native {
                function: "C_GetAttributeValue",
                code,
                may_have_effect: false,
            }) if code == CKR_OBJECT_HANDLE_INVALID as u64 => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("peer_removed_object_still_readable")),
        }
        if !search(s, &label)?.as_slice().is_empty() {
            return Err(Failure::Oracle("peer_removed_object_still_found"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let (Some(i), Some(handle)) = (&image, peer) {
        if let Some(key) = object {
            let removed = native_support::required(i.destroy_object).and_then(|destroy| {
                // SAFETY: retained cleanup rights for this peer-created object.
                native_support::status("C_DestroyObject", unsafe { destroy(handle, key) })
            });
            if let Err(error) = removed {
                cleanup.push(error);
            }
        }
        // SAFETY: no native user remains; only this peer's live session is closed.
        if let Err(error) =
            native_support::status("C_CloseSession", unsafe { (i.close_session)(handle) })
        {
            cleanup.push(error);
        }
    }
    if let Some(s) = &subject {
        if logged {
            if let Err(error) = s.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(subject);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    drop(image);
    module_controls::finish(report, setup, body, cleanup)
}
