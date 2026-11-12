// SPDX-License-Identifier: Apache-2.0
//! Snapshot an already completed result without reading a pending native frame.
use super::continuation::Continuation;

use super::{record, validation, OperationBody};
use crate::{symmetric::memory::Budget, Error, Result};

use std::sync::Arc;
pub(super) fn write(
    body: &OperationBody,
    capture: &validation::Capture,
    budget: &Arc<Budget>,
    writer: &mut record::Writer<'_>,
    limits: record::Limits,
) -> Result<()> {
    if !body.complete() || body.pending() {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::TerminalCryptoNotComplete,
        )));
    }
    let (descriptor, keys) = Continuation::header(body)?;
    let (maximum, observations) = capture.terminal_prefix(descriptor.phase.name())?;
    let valid = match body {
        OperationBody::Messages(b) => b.terminal_valid(),
        OperationBody::Dual(b) => b.terminal_valid(),
        _ => true,
    };
    descriptor.write(writer)?;
    keys.write(writer)?;
    match body {
        OperationBody::Messages(b) => b.write_terminal_messages(
            budget,
            writer,
            limits,
            Some(if valid {
                b.message_count()
            } else {
                observations.len()
            }),
        )?,
        OperationBody::Dual(b) => b.write_terminal_messages(budget, writer, limits, true)?,
        _ => Continuation::write_body(body, budget, writer, limits)?,
    }
    record::ValidationRecord::write(writer, Some((maximum, observations)), limits)?;
    writer.u8(u8::from(valid))
}


