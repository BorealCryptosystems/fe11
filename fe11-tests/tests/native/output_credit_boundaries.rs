// SPDX-License-Identifier: Apache-2.0
//! Compare adjacent request sizes using charges reported by the public API.
use super::{module_controls, select_token, Budgets, Configuration, Failure, Report};
use fe11::*;
use std::io::{self, Write};

fn owner<T>(
    config: &Configuration,
    limit: usize,
    cleanup: &mut Vec<Failure>,
    check: impl FnOnce(&Module, &Session) -> std::result::Result<T, Failure>,
) -> std::result::Result<T, Failure> {
    let mut budgets = Budgets::ordinary();
    budgets.buffer_bytes = limit;
    let module = config.open(&budgets)?;
    let mut session = None;
    let body = (|| {
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("random_boundary_token"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        check(
            &module,
            session
                .as_ref()
                .ok_or(Failure::Input("random_boundary_session"))?,
        )
    })();
    if let Some(session) = &session {
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    body
}

fn refusal(
    module: &Module,
    session: &Session,
    length: usize,
    limit: usize,
) -> std::result::Result<usize, Failure> {
    let before = module.call_counts()?;
    let result = session.generate_random(length);
    if module.call_counts()? != before {
        return Err(Failure::Oracle("random_boundary_refusal_dispatched"));
    }
    match result {
        Err(Error::ResourceLimitExceeded {
            resource: ResourceKind::SymmetricByteBudget,
            requested,
            limit: actual,
        }) if actual == limit && requested > limit => Ok(requested),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("random_boundary_missing_refusal")),
    }
}

pub(super) fn execute<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let mut cleanup = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        let nominal = Budgets::ordinary().buffer_bytes;
        let lengths = [
            nominal
                .checked_sub(1)
                .ok_or(Failure::Input("random_boundary_underflow"))?,
            nominal,
            nominal
                .checked_add(1)
                .ok_or(Failure::Input("random_boundary_overflow"))?,
        ];
        let mut charges = [0; 3];
        for (index, length) in lengths.iter().enumerate() {
            charges[index] = owner(config, nominal, &mut cleanup, |module, session| {
                refusal(module, session, *length, nominal)
            })?;
            if !cleanup.is_empty() {
                return Err(Failure::Oracle("random_boundary_probe_cleanup"));
            }
        }
        // These assertions describe the observed public charge partition. If
        // an implementation rounds charges, do not call the missing byte
        // boundary covered: report that diagnostic instead of widening it.
        if !(charges[0] < charges[1] && charges[1] < charges[2]) {
            return Err(Failure::Oracle("random_boundary_charge_partition"));
        }
        owner(config, charges[1], &mut cleanup, |module, session| {
            if refusal(module, session, lengths[2], charges[1])? != charges[2] {
                return Err(Failure::Oracle("random_boundary_charge_changed"));
            }
            // The same owner must remain usable after the refusal. Dropping
            // each result before the next call also proves output-credit
            // release at the exact ceiling, without private size constants.
            for length in [lengths[0], lengths[1], lengths[0]] {
                let bytes = session.generate_random(length)?;
                if bytes.len() != length {
                    return Err(Failure::Oracle("random_boundary_result_width"));
                }
                drop(bytes);
            }
            Ok(())
        })
    })();
    module_controls::finish(report, Ok(()), body, cleanup)
}
