// SPDX-License-Identifier: Apache-2.0
//! Independent client views retain children without gaining lifecycle authority.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls, module_lifecycle,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::io::{self, Write};

pub(super) fn execute<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let mut owner = None;
    let mut clients = Vec::new();
    let mut sessions = Vec::new();
    let mut first_closed = false;
    let setup = (|| -> std::result::Result<(), Failure> {
        let (runtime, first) = config.builder(&Budgets::ordinary()).open_shared()?;
        owner = Some(runtime);
        clients.push(first);
        clients.push(
            owner
                .as_ref()
                .ok_or(Failure::Input("shared_owner"))?
                .client()?,
        );
        for client in &clients {
            let token =
                select_token(client, &config.label).ok_or(Failure::Input("shared_client_token"))?;
            sessions.push(client.select(&token)?.open_session(true)?);
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let runtime = owner.as_ref().ok_or(Failure::Input("shared_owner"))?;
        let before = runtime.module().call_counts()?;
        for client in &clients {
            match client.close() {
                Err(Error::Rejected(RejectionReason::ModuleLifecycle(
                    ModuleLifecycleRejection::RuntimeOwnerRequired,
                ))) => (),
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(Failure::Oracle("ordinary_client_finalized")),
            }
        }
        while let Some(client) = clients.pop() {
            client
                .detach()
                .map_err(|_| Failure::Oracle("ordinary_client_detach"))?;
        }
        if runtime.module().call_counts()? != before {
            return Err(Failure::Oracle("client_detach_native_call"));
        }
        // Session children retain their individual participation after both
        // originating views detach. Closing one must not close the other.
        let first = sessions
            .first()
            .ok_or(Failure::Input("shared_first_session"))?;
        let second = sessions
            .get(1)
            .ok_or(Failure::Input("shared_second_session"))?;
        module_lifecycle::control(first)?;
        first.close()?;
        first_closed = true;
        module_lifecycle::control(second)?;
        Ok(())
    })();
    let mut cleanup = Vec::new();
    for (index, session) in sessions.iter().enumerate() {
        if index == 0 && first_closed {
            continue;
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(sessions);
    drop(clients);
    if let Some(runtime) = &owner {
        if let Err(error) = runtime.module().close() {
            cleanup.push(error.into());
        }
    }
    drop(owner);
    module_controls::finish(report, setup, body, cleanup)
}
