// SPDX-License-Identifier: Apache-2.0
//! Explicit drain order with idle, completed and active native owners.
use super::{module_controls, select_token, Budgets, Configuration, Failure, Report};
use fe11::*;
use std::io::{self, Write};

const EXPECTED: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];
fn usage(module: &Module, count: usize) -> std::result::Result<(), Failure> {
    let status = module.resource_status()?;
    if status.usage
        != (SessionUsage {
            total: count,
            read_write: count,
            open: count,
            ..SessionUsage::default()
        })
        || (count == 0 && !status.tokens.is_empty())
    {
        return Err(Failure::Oracle("drain_owner_accounting"));
    }
    Ok(())
}
fn not_finalizable(module: &Module, drain: &ModuleDrain) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    match drain.close() {
        Err(Error::Busy(BusyReason::ModuleLifecycle(
            ModuleLifecycleBusy::UsableSessionPreventsRecoveryFinalization,
        ))) => (),
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("drain_finalized_live_owner")),
    }
    if before != module.call_counts()? {
        return Err(Failure::Oracle("drain_premature_native_call"));
    }
    Ok(())
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    order: &str,
    report: Report<W>,
) -> io::Result<bool> {
    let mut module = None;
    let mut ordinary = Vec::new();
    let mut active = None;
    let mut ticket = None;
    let mut outputs = Vec::new();
    let mut drain = None;
    let mut closed = [false; 3];
    let mut module_closed = false;
    let setup = (|| -> std::result::Result<(), Failure> {
        if !matches!(order, "012" | "021" | "102" | "120" | "201" | "210") {
            return Err(Failure::Input("drain_owner_order"));
        }
        module = Some(config.open(&Budgets::ordinary())?);
        let m = module.as_ref().ok_or(Failure::Input("drain_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("drain_token"))?;
        let context = m.select(&token)?;
        ordinary.push(context.open_session(true)?);
        ordinary.push(context.open_session(true)?);
        outputs.push(ordinary[1].digest_multipart(
            HashAlgorithm::Sha256,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?);
        let mut s = context.open_session(true)?.into_advanced()?;
        s.set_pacing(OperationPacing::Cooperative)?;
        s.set_validation_capture(ValidationCaptureMode::Disabled)?;
        active = Some(s);
        let s = active.as_ref().ok_or(Failure::Input("drain_active"))?;
        ticket = Some(s.digest(
            HashAlgorithm::Sha256,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?);
        if !matches!(
            s.poll(ticket.as_mut().ok_or(Failure::Input("drain_ticket"))?)?,
            OperationProgress::Ready
        ) {
            return Err(Failure::Oracle("drain_initial_progress"));
        }
        usage(m, 3)?;
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        if setup.is_err() {
            return Ok(());
        }
        let m = module.as_ref().ok_or(Failure::Input("drain_module"))?;
        let before = m.call_counts()?;
        drain = Some(m.begin_drain()?);
        let permit = drain.as_ref().ok_or(Failure::Input("drain_permit"))?;
        if before != m.call_counts()? {
            return Err(Failure::Oracle("drain_begin_dispatched"));
        }
        not_finalizable(m, permit)?;
        for (position, owner) in order.bytes().enumerate() {
            let index = usize::from(owner - b'0');
            if index == 2 {
                let session = active.as_ref().ok_or(Failure::Input("drain_active"))?;
                let current = ticket.as_mut().ok_or(Failure::Input("drain_ticket"))?;
                let mut result = None;
                // Input was updated during setup; only Final and publication
                // remain. The bounded polls also allow a local transition. The
                // native trace excludes retries or a silent reinitialization.
                for _ in 0..3 {
                    match permit.poll_advanced(session, current)? {
                        OperationProgress::Ready => (),
                        OperationProgress::Digest(value) => {
                            result = Some(value);
                            break;
                        }
                        _ => return Err(Failure::Oracle("drain_progress_kind")),
                    }
                }
                outputs.push(result.ok_or(Failure::Oracle("drain_progress_incomplete"))?);
                if permit.close_advanced_session(session)? != AdvancedCloseStatus::Complete {
                    return Err(Failure::Oracle("drain_close_pending"));
                }
            } else {
                permit.close_session(&ordinary[index])?;
            }
            closed[index] = true;
            usage(m, 2 - position)?;
            if position < 2 {
                not_finalizable(m, permit)?;
            }
        }
        // Completed values remain independently owned across native close.
        permit.close()?;
        module_closed = true;
        if outputs.len() != 2 || outputs.iter().any(|v| v.as_bytes() != EXPECTED) {
            return Err(Failure::Oracle("drain_completed_output_changed"));
        }
        Ok(())
    })();
    let mut cleanup = Vec::new();
    for (index, session) in ordinary.iter().enumerate() {
        if !closed[index] {
            let result = match &drain {
                Some(d) => d.close_session(session),
                None => session.close(),
            };
            if let Err(error) = result {
                cleanup.push(error.into());
            }
        }
    }
    if let Some(session) = &active {
        if !closed[2] {
            let result = match &drain {
                Some(d) => d.close_advanced_session(session),
                None => session.close(),
            };
            match result {
                Ok(AdvancedCloseStatus::Complete) => (),
                Ok(_) => cleanup.push(Failure::Oracle("drain_cleanup_pending")),
                Err(e) => cleanup.push(e.into()),
            }
        }
    }
    drop(ticket);
    drop(active);
    drop(ordinary);
    drop(outputs);
    drop(drain);
    if !module_closed {
        if let Some(m) = &module {
            if let Err(e) = m.close() {
                cleanup.push(e.into());
            }
        }
    }
    module_controls::finish(report, setup, body, cleanup)
}
