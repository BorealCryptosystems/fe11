// SPDX-License-Identifier: Apache-2.0
//! A repeated dispatch marker must not produce a second native event call.
use super::{
    configuration::{Budgets, Configuration},
    foreign_info_image::Image,
    module_controls,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::*;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

fn check(owner: &RuntimeOwner, config: &Configuration) -> std::result::Result<(), Failure> {
    let image = Image::load(config)?;
    let wait = image
        .wait_for_slot_event
        .ok_or(Failure::Input("event_function_absent"))?;
    // SAFETY: exact selected image is retained. This adapter issues only the
    // permitted nonblocking call below; it neither initializes nor finalizes.
    let participant = unsafe { owner.register_foreign(image) }?;
    owner.use_foreign_events(&participant)?;
    let slot = Arc::new(Mutex::new(Box::new(0 as CK_SLOT_ID)));
    let mut output = slot
        .lock()
        .map_err(|_| Failure::Input("event_output_lock"))?;
    // SAFETY: boxed output has a stable address and remains owned by this graph.
    // Exactly CKF_DONT_BLOCK, a null reserved pointer, and one call are used.
    let mut event = unsafe { participant.begin_event(false, slot.clone()) }?;
    event.dispatched()?;
    // Even an unexpected second-marker result must be followed by the actual
    // call and its truthful return. No assertion abandons an issued lease.
    let second = event.dispatched();
    // SAFETY: function comes from the selected retained image; output is a
    // writable CK_SLOT_ID for this synchronous call, with no callback or alias.
    let code = unsafe { wait(CKF_DONT_BLOCK, &mut **output, std::ptr::null_mut()) };
    let observed_slot = if code == CKR_OK { **output as u64 } else { 0 };
    // SAFETY: this exact call has returned; pSlot is read only on CKR_OK.
    let receipt = unsafe { event.returned(code as u64, observed_slot) };
    drop(output);
    let publication = receipt.publication;
    let same_code = receipt.code == code as u64;
    owner.use_fe11_events()?;
    drop(participant);
    owner.collect_foreign()?;
    publication?;
    if !same_code {
        return Err(Failure::Oracle("foreign_event_code_changed"));
    }
    if !matches!(code, CKR_OK | CKR_NO_EVENT | CKR_FUNCTION_NOT_SUPPORTED) {
        return Err(Failure::DirectNative {
            function: "C_WaitForSlotEvent",
            code: code as u64,
        });
    }
    match second {
        Err(Error::Rejected(RejectionReason::ExternalExecution(
            ExternalExecutionRejection::ForeignEventAlreadyIssued,
        ))) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("foreign_event_second_dispatch_accepted")),
    }
}

pub fn execute<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let (owner, client) = match config.builder(&Budgets::ordinary()).open_shared() {
        Ok(value) => value,
        Err(error) => return module_controls::finish(report, Err(error.into()), Ok(()), vec![]),
    };
    let body = check(&owner, config);
    drop(client);
    let cleanup = owner
        .module()
        .close()
        .err()
        .map(Failure::from)
        .into_iter()
        .collect();
    module_controls::finish(report, Ok(()), body, cleanup)
}
