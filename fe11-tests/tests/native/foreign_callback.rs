// SPDX-License-Identifier: Apache-2.0
//! Callback handles must respect the lifetime of their actual native owner.
use super::{
    configuration::{Budgets, Configuration},
    foreign_info_image::Image,
    module_controls,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use fe11_sys::CK_INFO;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("callback_fixture_open"))?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("callback_fixture_read"))?;
    if bytes.len() > 64 {
        return Err(Failure::Input("callback_fixture_size"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| Failure::Input("callback_fixture_encoding"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("callback_fixture_fields"))?;
    if !matches!(
        action,
        "prepared" | "graph_dropped" | "finalized" | "runtime_dropped"
    ) {
        return Err(Failure::Input("callback_fixture_action"));
    }
    Ok(action.into())
}

fn refusal(
    handle: &ForeignCallbackHandle,
    expected: ExternalExecutionRejection,
) -> std::result::Result<(), Failure> {
    match handle.enter() {
        Err(Error::Rejected(RejectionReason::ExternalExecution(actual))) if actual == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("retired_callback_accepted")),
    }
}

fn check(
    owner: &mut Option<RuntimeOwner>,
    closed: &mut bool,
    config: &Configuration,
    action: &str,
) -> std::result::Result<(), Failure> {
    let runtime = owner
        .as_ref()
        .ok_or(Failure::Oracle("callback_owner_missing"))?;
    let image = Image::load(config)?;
    // SAFETY: the adapter retains the exact selected, verified provider image.
    // Prepared GetInfo work below is never dispatched; neither the adapter nor
    // its destructor invokes native code or finalizes the runtime.
    let participant = unsafe { runtime.register_foreign(image) }?;
    if matches!(action, "prepared" | "graph_dropped") {
        // SAFETY: CK_INFO contains only integers and fixed byte arrays. The
        // owned Box is stable and the mutex excludes concurrent mutation.
        let output = Arc::new(Mutex::new(Box::new(unsafe {
            std::mem::zeroed::<CK_INFO>()
        })));
        // SAFETY: this is the complete writable graph for synchronous GetInfo.
        // It remains owned for the full lifetime of the never-issued call.
        let work = unsafe { participant.prepare_call(ForeignScope::Module, output) }?;
        let handle = work.callback_handle();
        let before = runtime.module().call_counts()?;
        let result = if action == "prepared" {
            let result = refusal(
                &handle,
                ExternalExecutionRejection::ForeignCallbackGraphRetired,
            );
            drop(work);
            result
        } else {
            drop(work);
            runtime.collect_foreign()?;
            refusal(&handle, ExternalExecutionRejection::ForeignGraphRetired)
        };
        let unchanged = before == runtime.module().call_counts()?;
        drop(participant);
        runtime.collect_foreign()?;
        result?;
        if !unchanged {
            return Err(Failure::Oracle("callback_guard_dispatched"));
        }
        let status = runtime.foreign_status()?;
        if status.callbacks != 0 || status.progressable != 0 || status.uncertain != 0 {
            return Err(Failure::Oracle("callback_guard_retained_activity"));
        }
        return Ok(());
    }

    let handle = participant.callback_handle();
    // Finalization is real and authorized by this runtime's owner. A refusal
    // before finalization must not be mistaken for a retired initialization.
    runtime.module().close()?;
    *closed = true;
    if action == "finalized" {
        let before = runtime.module().call_counts()?;
        let result = refusal(
            &handle,
            ExternalExecutionRejection::ForeignInitializationFinalized,
        );
        let unchanged = before == runtime.module().call_counts()?;
        drop(participant);
        result?;
        if !unchanged {
            return Err(Failure::Oracle("finalized_callback_dispatched"));
        }
        Ok(())
    } else {
        // The weak callback must outlive every strong runtime owner, including
        // the participant. It must not keep a finalized native runtime alive.
        drop(participant);
        drop(owner.take());
        refusal(&handle, ExternalExecutionRejection::ForeignRuntimeRetired)
    }
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let setup = read(path).and_then(|action| {
        let (owner, client) = config.builder(&Budgets::ordinary()).open_shared()?;
        drop(client);
        Ok((owner, action))
    });
    let (owner, action) = match setup {
        Ok(value) => value,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), vec![]),
    };
    let mut owner = Some(owner);
    let mut closed = false;
    let body = check(&mut owner, &mut closed, config, &action);
    let cleanup = if closed {
        vec![]
    } else {
        owner
            .as_ref()
            .map(|runtime| runtime.module().close())
            .transpose()
            .err()
            .map(Failure::from)
            .into_iter()
            .collect()
    };
    module_controls::finish(report, Ok(()), body, cleanup)
}
