// SPDX-License-Identifier: Apache-2.0
//! Dropping a batch observer leaves ownership with the real session.
use super::{module_controls, select_token, Budgets, Configuration, Failure, Report};
use fe11::*;
use std::io::{self, Write};

pub(super) fn execute<W: Write>(
    config: &Configuration,
    eager: bool,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut ticket = None;
    let mut closed = false;
    let setup = (|| -> std::result::Result<(), Failure> {
        let mut limits = Budgets::ordinary();
        limits.sessions = 1;
        module = Some(config.open(&limits)?);
        let m = module.as_ref().ok_or(Failure::Input("observer_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("observer_token"))?;
        session = Some(m.select(&token)?.open_session(true)?.into_advanced()?);
        let s = session.as_mut().ok_or(Failure::Input("observer_session"))?;
        s.set_pacing(if eager {
            OperationPacing::Eager
        } else {
            OperationPacing::Cooperative
        })?;
        s.set_validation_capture(ValidationCaptureMode::Disabled)?;
        let before = m.call_counts()?;
        ticket = Some(s.digest_native(
            NativeDigestAlgorithm::Sha256,
            &[b"a", b"b", b"c"],
            InputLimits {
                maximum_parts: 3,
                maximum_total_bytes: 3,
            },
        )?);
        let after = m.call_counts()?;
        for (name, expected) in [
            ("C_DigestInit", 1),
            ("C_DigestUpdate", if eager { 3 } else { 0 }),
            ("C_DigestFinal", if eager { 1 } else { 0 }),
        ] {
            if after
                .get(name)
                .copied()
                .unwrap_or(0)
                .checked_sub(before.get(name).copied().unwrap_or(0))
                != Some(expected)
            {
                return Err(Failure::Oracle("observer_pacing_native_steps"));
            }
        }
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let m = module.as_ref().ok_or(Failure::Input("observer_module"))?;
        let s = session.as_ref().ok_or(Failure::Input("observer_session"))?;
        let before = m.call_counts()?;
        let owned = m.resource_status()?;
        if owned.usage.total != 1 || owned.usage.open != 1 {
            return Err(Failure::Oracle("observer_owned_session"));
        }
        drop(ticket.take());
        // Cooperative owns an active native digest; Eager owns the completed
        // but unpublished output. Neither is released by dropping the observer.
        match s.begin_native_digest(NativeDigestAlgorithm::Sha256) {
            Err(Error::Busy(BusyReason::OperationOwnership(
                OperationOwnershipBusy::AdvancedOperation,
            ))) => (),
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(Failure::Oracle("observer_drop_released_owner")),
        }
        if m.call_counts()? != before || m.resource_status()? != owned {
            return Err(Failure::Oracle("observer_drop_native_or_quota_change"));
        }
        if !matches!(s.close()?, AdvancedCloseStatus::Complete) {
            return Err(Failure::Oracle("observer_close_incomplete"));
        }
        closed = true;
        let released = m.resource_status()?;
        if released.usage != SessionUsage::default() || !released.tokens.is_empty() {
            return Err(Failure::Oracle("observer_close_credit_retained"));
        }
        Ok(())
    })();
    drop(ticket);
    let mut cleanup = Vec::new();
    if !closed {
        if let Some(s) = &session {
            match s.close() {
                Ok(AdvancedCloseStatus::Complete) => (),
                Ok(_) => cleanup.push(Failure::Oracle("observer_cleanup_incomplete")),
                Err(e) => cleanup.push(e.into()),
            }
        }
    }
    drop(session);
    if let Some(m) = &module {
        if let Err(e) = m.close() {
            cleanup.push(e.into());
        }
    }
    drop(module);
    module_controls::finish(report, setup, body, cleanup)
}
