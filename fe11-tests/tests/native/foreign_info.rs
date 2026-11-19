// SPDX-License-Identifier: Apache-2.0
//! Real synchronous foreign calls, with truthful memory-return receipts.
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
    fs::File,
    io::{self, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("foreign_fixture_open"))?
        .take(129)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("foreign_fixture_read"))?;
    if data.len() > 128 {
        return Err(Failure::Input("foreign_fixture_size"));
    }
    let text =
        std::str::from_utf8(&data).map_err(|_| Failure::Input("foreign_fixture_encoding"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("foreign_fixture_fields"))?;
    if !matches!(
        action,
        "PREPARED.inspect"
            | "register"
            | "prepared_drop"
            | "PREPARED.begin_start"
            | "PREPARED.continue"
            | "GUARD_PREPARED.dispatch"
            | "GUARD_PREPARED.drop_guard"
            | "DISPATCH_MARKED.dispatch"
            | "DISPATCH_MARKED.call_and_return"
            | "RETURNED.inspect"
            | "RETURNED.begin_start"
            | "RETURNED.continue"
            | "close_wrong_owner"
            | "operation_wrong_owner"
            | "status"
            | "module"
    ) {
        return Err(Failure::Input("foreign_fixture_action"));
    }
    Ok(action.into())
}

fn require(condition: bool, name: &'static str) -> std::result::Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(Failure::Oracle(name))
    }
}
fn status(
    owner: &RuntimeOwner,
    participants: usize,
    progressable: usize,
) -> std::result::Result<(), Failure> {
    let before = owner.module().call_counts()?;
    let observed = owner.foreign_status()?;
    require(
        observed.participants == participants
            && observed.progressable == progressable
            && observed.sessions == 0
            && observed.uncertain == 0
            && observed.callbacks == 0,
        "foreign_registry_counts",
    )?;
    require(
        before == owner.module().call_counts()?,
        "foreign_status_native_dispatch",
    )
}
fn refusal<T>(
    result: Result<T>,
    expected: ExternalExecutionRejection,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::ExternalExecution(actual))) if actual == expected => {
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("foreign_transition_accepted")),
    }
}
fn identity(
    work: &ForeignWork,
    id: ForeignWorkId,
    returned: bool,
) -> std::result::Result<(), Failure> {
    require(
        work.id() == id && matches!(work.scope(), ForeignScope::Module),
        "foreign_identity",
    )?;
    require(
        work.last_native_step()? == returned.then_some(ForeignStep::Start)
            && work.last_native_return()? == returned.then_some(CKR_OK as u64),
        "foreign_last_return",
    )
}

fn check(
    owner: &RuntimeOwner,
    client: &Module,
    config: &Configuration,
    action: &str,
) -> std::result::Result<(), Failure> {
    status(owner, 0, 0)?;
    let before = client.call_counts()?;
    let view = owner.module();
    require(
        std::ptr::eq(view, owner.module()),
        "foreign_owner_module_identity",
    )?;
    match &view.info().provenance {
        ModuleProvenance::File { file, .. }
            if file.path == config.module && file.sha256 == config.module_sha256 =>
        {
            ()
        }
        _ => return Err(Failure::Oracle("foreign_owner_module_provenance")),
    }
    require(
        view.info().function_list_version == client.info().function_list_version
            && before == client.call_counts()?,
        "foreign_owner_module_dispatch",
    )?;
    if action == "module" {
        return Ok(());
    }
    let image = Image::load(config)?;
    // SAFETY: participant retains the same selected provider image; only the
    // following permitted synchronous GetInfo can use it. No foreign destructor
    // finalizes, unloads early or invokes callbacks or lifecycle functions.
    let participant = unsafe { owner.register_foreign(image.clone()) }?;
    if action == "register" {
        let weak = Arc::downgrade(&image);
        drop(image);
        require(weak.upgrade().is_some(), "foreign_adapter_not_retained")?;
        status(owner, 1, 0)?;
        require(
            before == client.call_counts()?,
            "foreign_registration_dispatched",
        )?;
        drop(participant);
        owner.collect_foreign()?;
        return Ok(());
    }
    // SAFETY: CK_INFO has only integers and byte arrays; zero initializes them.
    // Box keeps the native address stable; Mutex excludes concurrent access.
    let output = Arc::new(Mutex::new(Box::new(unsafe {
        std::mem::zeroed::<CK_INFO>()
    })));
    // SAFETY: GetInfo accesses no token/session and retains no buffer on return.
    // The complete writable graph remains registered and locally retained until
    // a truthful Returned receipt. No pointers to application secrets are used.
    let mut work = unsafe { participant.prepare_call(ForeignScope::Module, output.clone()) }?;
    let id = work.id();
    status(owner, 1, 0)?;
    identity(&work, id, false)?;
    match action {
        "PREPARED.inspect" => (),
        "prepared_drop" => {
            drop(work);
            require(
                participant.take_abandoned_work()?.is_none(),
                "never_issued_work_is_not_progressable",
            )?;
            require(before == client.call_counts()?, "prepared_drop_dispatched")?;
            drop(participant);
            owner.collect_foreign()?;
            return Ok(());
        }
        "close_wrong_owner" => {
            refusal(
                work.begin(ForeignStep::CloseSession),
                ExternalExecutionRejection::ForeignCloseSessionOwnerRequired,
            )?;
            identity(&work, id, false)?;
            drop(work.begin(ForeignStep::Start)?);
        }
        "operation_wrong_owner" => {
            // SAFETY: the supplied Call is the exact live module-only graph;
            // kind Call claims no session-closure proof. The API must reject its
            // use as a session owner before admitting any native work. Both
            // original and proposed buffers remain stably retained here.
            let result = unsafe {
                participant.prepare_operation(
                    &work,
                    ForeignWorkKind::Call,
                    ForeignAccess::Session,
                    output.clone(),
                )
            };
            refusal(
                result,
                ExternalExecutionRejection::ForeignOperationSessionMismatch,
            )?;
            identity(&work, id, false)?;
            drop(work.begin(ForeignStep::Start)?);
        }

        "PREPARED.continue" => refusal(
            work.begin(ForeignStep::Continue),
            ExternalExecutionRejection::ForeignWorkStepNotAdmitted,
        )?,
        "PREPARED.begin_start" | "GUARD_PREPARED.drop_guard" => {
            let guard = work.begin(ForeignStep::Start)?;
            status(owner, 1, 1)?;
            drop(guard);
            identity(&work, id, false)?;
            status(owner, 1, 0)?;
            // Both cancellation paths leave the original prepared work usable.
            drop(work.begin(ForeignStep::Start)?);
        }
        _ => {
            // Obtain the output lock before marking dispatch: a poisoned test
            // mutex must not create a falsely issued native call.
            let mut output_guard = output
                .lock()
                .map_err(|_| Failure::Input("foreign_buffer_poisoned"))?;
            let mut call = work.begin(ForeignStep::Start)?;
            status(owner, 1, 1)?;
            call.dispatched()?;
            let duplicate = if action == "DISPATCH_MARKED.dispatch" {
                Some(call.dispatched())
            } else {
                None
            };
            // Always perform and record the authorized call before evaluating
            // the second-dispatch assertion, including its unexpected-success path.
            // SAFETY: valid writable CK_INFO within the retained graph; exactly
            // one synchronous invocation under the matching runtime permit.
            let code = unsafe { (image.get_info)(&mut **output_guard) };
            // SAFETY: GetInfo has returned and borrows no memory afterward.
            // An unexpected asynchronous code receives no completion claim.
            let completion = if code == CKR_PENDING {
                ForeignCompletion::Uncertain
            } else {
                ForeignCompletion::Returned
            };
            let receipt = unsafe { call.returned(code as u64, completion) };
            require(receipt.code == code as u64, "foreign_receipt_code")?;
            receipt.publication?;
            native_support::status("C_GetInfo", code)?;
            if let Some(duplicate) = duplicate {
                refusal(
                    duplicate,
                    ExternalExecutionRejection::ForeignCallAlreadyDispatched,
                )?;
            }
            let info = view.info();
            require(
                output_guard.manufacturerID == info.manufacturer
                    && output_guard.libraryDescription == info.description
                    && (
                        output_guard.cryptokiVersion.major,
                        output_guard.cryptokiVersion.minor,
                    ) == info.interface_version
                    && (
                        output_guard.libraryVersion.major,
                        output_guard.libraryVersion.minor,
                    ) == info.library_version
                    && output_guard.flags == 0,
                "foreign_native_info",
            )?;
            drop(output_guard);
            identity(&work, id, true)?;
            status(owner, 1, 0)?;
            if action == "RETURNED.begin_start" {
                refusal(
                    work.begin(ForeignStep::Start),
                    ExternalExecutionRejection::ForeignWorkStepNotAdmitted,
                )?;
            } else if action == "RETURNED.continue" {
                refusal(
                    work.begin(ForeignStep::Continue),
                    ExternalExecutionRejection::ForeignWorkStepNotAdmitted,
                )?;
            }
        }
    }
    // Fe11's counters describe its own calls; the independent native observer
    // counts the direct GetInfo. Neither counter substitutes for the other.
    require(
        before == client.call_counts()?,
        "foreign_local_action_dispatched",
    )?;
    drop(work);
    drop(participant);
    owner.collect_foreign()?;
    Ok(())
}

pub fn execute<W: Write>(
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let setup = read(path).and_then(|action| {
        let (owner, client) = config.builder(&Budgets::ordinary()).open_shared()?;
        Ok((owner, client, action))
    });
    let (owner, client, action) = match setup {
        Ok(value) => value,
        Err(error) => return module_controls::finish(report, Err(error), Ok(()), vec![]),
    };
    let body = check(&owner, &client, config, &action);
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
