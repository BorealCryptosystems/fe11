// SPDX-License-Identifier: Apache-2.0
//! Refused state capture must release its temporary byte credits.
//!
//! A public oversized-request diagnostic supplies the exact complete random
//! request charge, including resident module storage. An independently opened
//! owner uses that ceiling. A bounded binary search measures the largest random
//! request while the actual Advanced owner is retained, after an ordinary
//! digest. That same request must succeed after a digest whose capture failed.
//! No private memory size, allocator RSS or session-quota proxy is used.
use super::{
    boundary_attempt, module_controls, select_token, Budgets, Configuration, Failure, Report,
};
use fe11::*;
use std::io::{self, Write};

fn random(session: &Session, length: usize) -> std::result::Result<(), Failure> {
    let output = session.generate_random(length)?;
    if output.len() != length {
        return Err(Failure::Oracle("capture_credit_random_width"));
    }
    drop(output);
    Ok(())
}

fn occupied(module: &Module, session: &Session, length: usize) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    match session.generate_random(length) {
        Err(Error::Busy(BusyReason::MemoryAccounting(
            MemoryAccountingBusy::SymmetricByteBudget,
        ))) => (),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err(Failure::Oracle("capture_credit_expected_occupied_boundary")),
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("capture_credit_boundary_dispatched"));
    }
    Ok(())
}

fn available(
    module: &Module,
    session: &Session,
    upper: usize,
) -> std::result::Result<usize, Failure> {
    occupied(module, session, upper)?;
    random(session, 0)?;
    let (mut low, mut high) = (0, upper);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        let mut expected = module.call_counts()?;
        match session.generate_random(middle) {
            Ok(value) => {
                if value.len() != middle {
                    return Err(Failure::Oracle("capture_credit_probe_width"));
                }
                drop(value);
                low = middle;
            }
            Err(Error::Busy(BusyReason::MemoryAccounting(
                MemoryAccountingBusy::SymmetricByteBudget,
            ))) => {
                if module.call_counts()? != expected {
                    return Err(Failure::Oracle("capture_credit_busy_probe_dispatched"));
                }
                high = middle;
                // A separate zero-length control keeps each search iteration
                // independently observable as exactly one native random call.
                random(session, 0)?;
            }
            Err(error) => return Err(error.into()),
        }
        *expected.entry("C_GenerateRandom").or_default() += 1;
        if module.call_counts()? != expected {
            return Err(Failure::Oracle("capture_credit_probe_call_count"));
        }
    }
    occupied(module, session, high)?;
    if low == 0 {
        return Err(Failure::Oracle("capture_credit_no_available_payload"));
    }
    Ok(low)
}

fn digest(session: &AdvancedSession, capture: bool) -> std::result::Result<(), Failure> {
    let mut ticket = session.begin_native_digest(NativeDigestAlgorithm::Sha256)?;
    session.digest_update(
        &mut ticket,
        b"abc",
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
    )?;
    if capture {
        match session.start_state_capture(&ticket, 4096) {
            Err(Error::Native {
                function: "C_GetOperationState",
                code,
                may_have_effect: false,
            }) if code == fe11_sys::CKR_FUNCTION_NOT_SUPPORTED as u64 => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("capture_credit_expected_native_refusal")),
        }
    }
    match session.finish_native_digest(&mut ticket)? {
        OperationProgress::NativeDigest(value) => {
            // FIPS 180-4 / SHA-256 public message abc known answer.
            let expected = [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ];
            if value.as_bytes() != expected {
                return Err(Failure::Oracle("capture_credit_same_ticket_digest"));
            }
        }
        _ => return Err(Failure::Oracle("capture_credit_unfinished_digest")),
    }
    drop(ticket);
    Ok(())
}

pub(super) fn execute<W: Write>(config: &Configuration, report: Report<W>) -> io::Result<bool> {
    let mut cleanup = Vec::new();
    let mut module = None;
    let mut peer = None;
    let mut subject = None;
    let body = (|| -> std::result::Result<(), Failure> {
        let length = Budgets::ordinary().buffer_bytes;
        let charge = boundary_attempt(config, length, None, &mut cleanup)?;
        if !cleanup.is_empty() {
            return Err(Failure::Oracle("capture_credit_probe_cleanup"));
        }
        let mut budgets = Budgets::ordinary();
        budgets.buffer_bytes = charge;
        module = Some(config.open(&budgets)?);
        let m = module
            .as_ref()
            .ok_or(Failure::Input("capture_credit_module"))?;
        let token = select_token(m, &config.label).ok_or(Failure::Input("capture_credit_token"))?;
        peer = Some(m.select(&token)?.open_session(true)?);
        subject = Some(m.select(&token)?.open_session(true)?.into_advanced()?);
        let p = peer.as_ref().ok_or(Failure::Input("capture_credit_peer"))?;
        let s = subject
            .as_ref()
            .ok_or(Failure::Input("capture_credit_subject"))?;
        digest(s, false)?;
        let available = available(m, p, length)?;
        digest(s, true)?;
        random(p, available)
    })();
    if let Some(s) = &subject {
        match s.close() {
            Ok(AdvancedCloseStatus::Complete) => (),
            Ok(AdvancedCloseStatus::Pending) => {
                cleanup.push(Failure::Oracle("capture_credit_close_pending"))
            }
            Err(error) => cleanup.push(error.into()),
        }
    }
    drop(subject);
    if let Some(s) = &peer {
        if let Err(error) = s.close() {
            cleanup.push(error.into());
        }
    }
    drop(peer);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    module_controls::finish(report, Ok(()), body, cleanup)
}
