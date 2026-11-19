// SPDX-License-Identifier: Apache-2.0
//! Foreign owners remain bound to one independently initialized native image.
use super::{
    configuration::{Budgets, Configuration},
    foreign_info_image::Image,
    module_controls, native_support,
    object_owner::Owner,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

fn refusal<T>(
    result: Result<T>,
    expected: ExternalExecutionRejection,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::ExternalExecution(actual))) if actual == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("foreign_runtime_request_accepted")),
    }
}

fn foreign(
    a: &RuntimeOwner,
    b: &RuntimeOwner,
    image: Arc<Image>,
    action: &str,
) -> std::result::Result<(), Failure> {
    let before_a = a.module().call_counts()?;
    let before_b = b.module().call_counts()?;
    // SAFETY: B's verified image is retained and only B's admitted GetInfo may
    // execute. No destructor initializes, finalizes or issues native calls.
    let participant = unsafe { b.register_foreign(image.clone()) }?;
    // SAFETY: CK_INFO consists only of integers and fixed byte arrays.
    let output = Arc::new(Mutex::new(Box::new(unsafe {
        std::mem::zeroed::<CK_INFO>()
    })));
    // SAFETY: stable boxed output retained for the complete synchronous call.
    let mut work = unsafe { participant.prepare_call(ForeignScope::Module, output.clone()) }?;
    if action == "drain\n" {
        let drain = a.module().begin_drain()?;
        refusal(
            drain.begin_foreign(&mut work, ForeignStep::Start),
            ExternalExecutionRejection::ForeignDrainingRuntime,
        )?;
        drop(drain);
    } else {
        refusal(
            a.use_foreign_events(&participant),
            ExternalExecutionRejection::ForeignEventRuntimeMismatch,
        )?;
        b.use_foreign_events(&participant)?;
        b.use_fe11_events()?;
    }
    if a.module().call_counts()? != before_a || b.module().call_counts()? != before_b {
        return Err(Failure::Oracle("foreign_runtime_guard_dispatched"));
    }
    // The same graph must still be usable by its actual runtime after refusal.
    let mut target = output
        .lock()
        .map_err(|_| Failure::Input("foreign_runtime_output_lock"))?;
    let mut call = work.begin(ForeignStep::Start)?;
    call.dispatched()?;
    // SAFETY: exact B function with stable writable CK_INFO and B admission.
    let code = unsafe { (image.get_info)(&mut **target) };
    let completion = if code == CKR_PENDING {
        ForeignCompletion::Uncertain
    } else {
        ForeignCompletion::Returned
    };
    // SAFETY: this invocation returned; an unexpected PENDING is not proof of completion.
    let receipt = unsafe { call.returned(code as u64, completion) };
    receipt.publication?;
    native_support::status("C_GetInfo", code)?;
    if receipt.code != code as u64 || target.manufacturerID != b.module().info().manufacturer {
        return Err(Failure::Oracle("foreign_runtime_surviving_info"));
    }
    drop(target);
    drop(work);
    drop(participant);
    b.collect_foreign()?;
    Ok(())
}

fn object(
    a: &RuntimeOwner,
    b: &RuntimeOwner,
    ca: &Configuration,
    cb: &Configuration,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let mut source = None;
    let mut peer = None;
    let mut object = None;
    let result = (|| -> std::result::Result<(), Failure> {
        source = Some(Owner::open(a.module(), ca, false)?);
        peer = Some(Owner::open(b.module(), cb, false)?);
        let source = source
            .as_ref()
            .ok_or(Failure::Input("cross_object_source"))?;
        object = Some(source.import_secret(
            &[0x11; 16],
            CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?);
        let native = object
            .as_ref()
            .ok_or(Failure::Input("cross_object_owner"))?;
        let Some(Owner::Session(receiver)) = &peer else {
            return Err(Failure::Input("cross_object_receiver"));
        };
        let before_a = a.module().call_counts()?;
        let before_b = b.module().call_counts()?;
        match receiver.destroy_native_object(native) {
            Err(Error::Rejected(RejectionReason::ObjectReferences(
                ObjectReferencesRejection::ForeignNativeObject,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("foreign_native_object_destroyed")),
        }
        if a.module().call_counts()? != before_a || b.module().call_counts()? != before_b {
            return Err(Failure::Oracle("foreign_destroy_dispatched"));
        }
        let Owner::Session(source) = source else {
            return Err(Failure::Input("cross_object_session"));
        };
        let observed = source.read_flat_attribute(
            native,
            StandardAttribute::CLASS,
            FlatAttributeReadPlan::Buffer {
                capacity: std::mem::size_of::<CK_OBJECT_CLASS>(),
            },
        )?;
        if observed.calls
            != (AttributeReadCalls::Direct {
                code: CKR_OK as u64,
            })
            || !matches!(observed.value, FlatAttributeValue::Available(value) if value.as_bytes()==CKO_SECRET_KEY.to_ne_bytes())
        {
            return Err(Failure::Oracle("foreign_object_surviving_class"));
        }
        if receiver.info()?.state != CKS_RW_PUBLIC_SESSION as u64 {
            return Err(Failure::Oracle("foreign_object_receiver_state"));
        }
        Ok(())
    })();
    if let (Some(Owner::Session(source)), Some(object)) = (&source, &object) {
        if let Err(error) = source.destroy_native_object(object) {
            cleanup.push(error.into());
        }
    }
    drop(object);
    if let Some(peer) = &peer {
        cleanup.extend(peer.close(None));
    }
    drop(peer);
    if let Some(source) = &source {
        cleanup.extend(source.close(None));
    }
    drop(source);
    result
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut first = None;
    let mut second = None;
    let mut cleanup = Vec::new();
    let setup = (|| -> std::result::Result<(Configuration, Arc<Image>, String), Failure> {
        let mut action = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("cross_runtime_fixture"))?
            .take(17)
            .read_to_string(&mut action)
            .map_err(|_| Failure::Input("cross_runtime_action"))?;
        if !matches!(action.as_str(), "drain\n" | "event\n" | "object\n") {
            return Err(Failure::Input("cross_runtime_action"));
        }
        let peer = Configuration {
            module: PathBuf::from(
                std::env::var_os("FE11_PUBLIC_PEER_MODULE")
                    .ok_or(Failure::Input("cross_runtime_image"))?,
            ),
            module_sha256: config.module_sha256,
            interface: config.interface,
            label: config.label.clone(),
        };
        if !peer.module.is_absolute() || peer.module == config.module {
            return Err(Failure::Input("cross_runtime_distinct_image"));
        }
        let ia = Image::load(config)?;
        let ib = Image::load(&peer)?;
        let a = native_support::required(ia.identity.initialize)?;
        let b = native_support::required(ib.identity.initialize)?;
        if a as usize == b as usize {
            return Err(Failure::Input("cross_runtime_native_identity_shared"));
        }
        let (owner, client) = config.builder(&Budgets::ordinary()).open_shared()?;
        first = Some(owner);
        drop(client);
        let (owner, client) = peer.builder(&Budgets::ordinary()).open_shared()?;
        second = Some(owner);
        drop(client);
        Ok((peer, ib, action))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((peer, image, action)) = &setup else {
            return Ok(());
        };
        let a = first.as_ref().ok_or(Failure::Input("cross_runtime_a"))?;
        let b = second.as_ref().ok_or(Failure::Input("cross_runtime_b"))?;
        if action == "object\n" {
            object(a, b, config, peer, &mut cleanup)
        } else {
            foreign(a, b, image.clone(), action)
        }
    })();
    if let Some(owner) = &second {
        if let Err(error) = owner.module().close() {
            cleanup.push(error.into());
        }
    }
    if let Some(owner) = &first {
        if let Err(error) = owner.module().close() {
            cleanup.push(error.into());
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
