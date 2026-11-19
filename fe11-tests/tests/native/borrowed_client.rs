// SPDX-License-Identifier: Apache-2.0
//! An attached ordinary client cannot finalize the application's initialization.
use super::{
    configuration::{Budgets, Configuration},
    foreign_info_image::Image,
    module_controls, native_support,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::*;
use std::{
    io::{self, Write},
    ptr,
    sync::{Arc, Mutex},
};

fn peer_info(owner: &RuntimeOwner, image: Arc<Image>) -> std::result::Result<(), Failure> {
    // SAFETY: adapter retains the exact initialized image, with no native Drop.
    // Its only call is the synchronous GetInfo below, admitted by the owner.
    let participant = unsafe { owner.register_foreign(image.clone()) }?;
    // SAFETY: CK_INFO is an integer/byte-array output, with no pointer fields.
    let output = Arc::new(Mutex::new(Box::new(unsafe {
        std::mem::zeroed::<CK_INFO>()
    })));
    // SAFETY: the complete writable output graph is boxed and retained until
    // the synchronous call returns. GetInfo does not retain it on return.
    let mut work = unsafe { participant.prepare_call(ForeignScope::Module, output.clone()) }?;
    let mut target = output
        .lock()
        .map_err(|_| Failure::Input("borrowed_info_lock"))?;
    let mut call = work.begin(ForeignStep::Start)?;
    call.dispatched()?;
    // SAFETY: exact selected-image ABI, writable output, admitted call permit.
    let code = unsafe { (image.get_info)(&mut **target) };
    let completion = if code == CKR_PENDING {
        ForeignCompletion::Uncertain
    } else {
        ForeignCompletion::Returned
    };
    // SAFETY: this exact invocation returned. PENDING is never completion proof.
    let receipt = unsafe { call.returned(code as u64, completion) };
    receipt.publication?;
    native_support::status("C_GetInfo", code)?;
    if receipt.code != code as u64 || target.manufacturerID != owner.module().info().manufacturer {
        return Err(Failure::Oracle("borrowed_peer_information"));
    }
    drop(target);
    drop(work);
    drop(participant);
    owner.collect_foreign()?;
    Ok(())
}

pub fn execute<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let image = match Image::load(config) {
        Ok(image) => image,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), vec![]),
    };
    let init = match native_support::required(image.identity.initialize) {
        Ok(init) => init,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), vec![]),
    };
    let finalize = match native_support::required(image.identity.finalize) {
        Ok(finalize) => finalize,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), vec![]),
    };
    // SAFETY: descriptor contains only null callbacks/reserved and public flags.
    let mut args: CK_C_INITIALIZE_ARGS = unsafe { std::mem::zeroed() };
    args.flags = CKF_OS_LOCKING_OK;
    // SAFETY: exact retained table, fresh isolated process, live descriptor for
    // a synchronous initialization that retains no application-owned pointers.
    let code = unsafe { init((&mut args as *mut CK_C_INITIALIZE_ARGS).cast()) };
    if let Err(error) = native_support::status("C_Initialize", code) {
        return module_controls::finish(report, Err(error), Ok(()), vec![]);
    }
    // SAFETY: the exact identity is initialized with OS locking; no session or
    // foreign invocation exists. Image is retained and has no lifecycle Drop.
    let declaration = unsafe {
        ExternalInitialization::new(
            image.identity,
            ExternalConcurrency::Concurrent,
            image.clone(),
        )
    };
    // SAFETY: application is quiescent and transfers all global authority.
    // Every later foreign call joins the returned owner's protocol.
    let attached = unsafe {
        config
            .builder(&Budgets::ordinary())
            .attach_initialized(declaration)
    };
    let (owner, client) = match attached {
        Ok(value) => value,
        Err(error) => {
            // SAFETY: failed attachment created no client/session. The caller
            // still owns this exact initialization and no invocation is pending.
            let result = native_support::status("C_Finalize", unsafe { finalize(ptr::null_mut()) });
            return module_controls::finish(
                report,
                Err(error.into()),
                Ok(()),
                result.err().into_iter().collect(),
            );
        }
    };
    let body = (|| -> std::result::Result<(), Failure> {
        let before = owner.module().call_counts()?;
        match client.close() {
            Err(Error::Rejected(RejectionReason::ModuleLifecycle(
                ModuleLifecycleRejection::RuntimeOwnerRequired,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("borrowed_client_finalized")),
        }
        client
            .detach()
            .map_err(|_| Failure::Oracle("borrowed_client_detach"))?;
        if owner.module().call_counts()? != before {
            return Err(Failure::Oracle("borrowed_client_close_dispatched"));
        }
        peer_info(&owner, image.clone())
    })();
    let cleanup = owner
        .module()
        .close()
        .err()
        .map(Failure::from)
        .into_iter()
        .collect();
    module_controls::finish(report, Ok(()), body, cleanup)
}
