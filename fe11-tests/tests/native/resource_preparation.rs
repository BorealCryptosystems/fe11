// SPDX-License-Identifier: Apache-2.0
//! A refused preparation releases the caller's sole session reservation.
use super::{
    module_controls, module_lifecycle, select_token, Budgets, Configuration, Failure, Report,
};
use fe11::*;
use std::io::{self, Write};

pub(super) fn execute<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let mut module = None;
    let mut session = None;
    let mut baseline = None;
    let setup = (|| -> std::result::Result<(), Failure> {
        let mut limits = Budgets::ordinary();
        limits.sessions = 1;
        module = Some(config.open(&limits)?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("preparation_module"))?;
        baseline = Some(m.resource_status()?);
        let empty = baseline
            .as_ref()
            .ok_or(Failure::Input("preparation_baseline"))?;
        if empty.usage != SessionUsage::default() || !empty.tokens.is_empty() {
            return Err(Failure::Oracle("preparation_initial_credits"));
        }
        let token = select_token(m, &config.label).ok_or(Failure::Input("preparation_token"))?;
        session = Some(m.select(&token)?.open_session(true)?);
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let m = module
            .as_ref()
            .ok_or(Failure::Input("preparation_module"))?;
        let s = session
            .as_ref()
            .ok_or(Failure::Input("preparation_session"))?;
        let before = m.call_counts()?;
        let owned = m.resource_status()?;
        if owned.usage.total != 1 || owned.usage.read_write != 1 || owned.usage.open != 1 {
            return Err(Failure::Oracle("preparation_one_owned_session"));
        }
        match s.digest_multipart(
            HashAlgorithm::Sha256,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 2,
            },
        ) {
            Err(Error::Rejected(RejectionReason::ClassicalSignatures(
                ClassicalSignaturesRejection::CryptoTotalCeiling,
            ))) => (),
            Err(e) => return Err(e.into()),
            Ok(_) => return Err(Failure::Oracle("preparation_ceiling_accepted")),
        }
        if m.call_counts()? != before || m.resource_status()? != owned {
            return Err(Failure::Oracle("preparation_failure_dispatch_or_quota"));
        }
        module_lifecycle::control(s)?;
        s.close()?;
        drop(session.take());
        if Some(m.resource_status()?) != baseline {
            return Err(Failure::Oracle("preparation_credits_not_restored"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    if let Some(s) = &session {
        if let Err(e) = s.close() {
            cleanup.push(e.into());
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
