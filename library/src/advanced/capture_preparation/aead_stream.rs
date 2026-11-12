// SPDX-License-Identifier: Apache-2.0
//! Capture caller-fed AEAD boundaries, retained input and unpublished outputs.
//! Discovery/copy use source guards; allocation and relocation run outside them.
use super::PreparedCapture;
use crate::advanced::{
    continuation::Continuation, gcm::checkpoint::capture::Materialized, preparation, progress,
    saved_state::CaptureOwner, state_io::StateIo, validation, OperationBody, OperationTicket,
};
use crate::symmetric::memory::ControlledReservation;
use crate::{Error, Result, Session};

pub(super) fn prepare<'a>(
    session: &'a Session,
    ticket: &OperationTicket,
    state_maximum: usize,
    diagnostics: &mut progress::FailureDiagnostics,
) -> Result<Option<PreparedCapture<'a>>> {
    let budget = diagnostics.budget().clone();
    let policy = crate::admission_wait::current();
    let mut allocation_floor = 0;
    loop {
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        Continuation::check_capture(&operation, &session.entry)?;
        if operation.capture_owner().is_some() {
            return Err(Error::Busy(crate::BusyReason::CheckpointCapture(
                crate::CheckpointCaptureBusy::StateCaptureActive,
            )));
        }
        let OperationBody::AeadMessages(source) = &operation.body else {
            return Ok(None);
        };
        if !source.caller_fed() {
            return Ok(None);
        }
        let shape = source.stream_snapshot_shape(&session.entry)?;
        let maximum = operation
            .validation
            .as_ref()
            .map(validation::Capture::snapshot_capacity)
            .transpose()?;
        let validation_bytes = maximum
            .map(validation::Capture::allocation_bytes)
            .transpose()?
            .unwrap_or(0);
        let authentication = operation._token.authentication;
        let provenance = operation.provenance;
        let exclusive = source.encrypting();
        let frame_bytes = shape.allocation_bytes()?.max(allocation_floor);
        let total = frame_bytes
            .checked_add(validation_bytes)
            .and_then(|n| n.checked_add(CaptureOwner::allocation_bytes()))
            .and_then(|n| n.checked_add(StateIo::allocation_bytes()))
            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::AeadStreamCaptureAccounting,
            )))?;
        let mut waiter =
            progress::Waiter::new(session, operation.id, progress::Effect::PreserveOwner)?;
        drop(operation);
        drop(held);
        drop(access);
        let result = (|| -> Result<Option<(CaptureOwner, StateIo)>> {
            let mut credit = match budget.reserve_controlled_retaining(
                total,
                crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                &policy,
                || {
                    preparation::context(session)?;
                    session
                        .snapshot
                        .observe_authentication_unchanged(authentication)?;
                    Ok(waiter.changed().then_some(()))
                },
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(()) => {
                    waiter.succeed()?;
                    allocation_floor = 0;
                    return Ok(None);
                }
            };
            let packet = shape.allocate_packet()?;
            let validation = maximum
                .map(validation::CaptureStorage::allocate)
                .transpose()?;
            let overhead = shape.packet_overhead(&packet)?;
            let validation_actual = validation
                .as_ref()
                .map(validation::CaptureStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0);
            let extra = overhead
                .checked_add(validation_actual.saturating_sub(validation_bytes))
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::AeadStreamCaptureCapacity,
                )))?;
            if shape
                .allocation_bytes()?
                .checked_add(extra)
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::AeadStreamCaptureCapacity,
                )))?
                > frame_bytes
            {
                allocation_floor = shape.allocation_bytes()? + extra;
                waiter.succeed()?;
                return Ok(None);
            }
            let mut packet = shape.bind_packet(packet, &mut credit)?;
            let mut validation = validation
                .map(|value| value.bind(&mut credit))
                .transpose()?;
            let owner_credit = credit.split(CaptureOwner::allocation_bytes())?;
            let io = StateIo::capture_prepaid(&mut credit, state_maximum)?;
            let access = session.advanced_access()?;
            let held = access.operations.get(ticket.uid)?;
            let operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::StaleOperationTicket,
                )));
            }
            if waiter.changed() {
                waiter.succeed()?;
                allocation_floor = 0;
                return Ok(None);
            }
            Continuation::check_capture(&operation, &session.entry)?;
            if operation.capture_owner().is_some() {
                return Err(Error::Busy(crate::BusyReason::CheckpointCapture(
                    crate::CheckpointCaptureBusy::StateCaptureActive,
                )));
            }
            let OperationBody::AeadMessages(source) = &operation.body else {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::AeadStreamCaptureOwnerChanged,
                )));
            };
            packet.copy_from(source, &session.entry)?;
            match (&mut validation, &operation.validation) {
                (Some(target), Some(original)) => target.copy_snapshot_from(original)?,
                (None, None) => {}
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::AeadStreamValidationShapeChanged,
                    )))
                }
            }
            drop(operation);
            drop(held);
            drop(access);
            // credit now excludes the packet and other bound owners. The
            // materializer's admitted count includes its packet for accounting.
            let frame_admitted = frame_bytes
                .checked_add(validation_bytes)
                .and_then(|n| n.checked_sub(validation_actual))
                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::AeadStreamCaptureAccounting,
                )))?;
            let frame = match packet.materialize(
                &mut credit,
                frame_admitted,
                session.inner.crypto_options.limits,
            )? {
                Materialized::Ready(frame) => frame,
                Materialized::Retry(actual) => {
                    allocation_floor = actual
                        .checked_add(validation_actual.saturating_sub(validation_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::AeadStreamCaptureAccounting,
                        )))?;
                    waiter.succeed()?;
                    return Ok(None);
                }
            };
            if waiter.changed() {
                waiter.succeed()?;
                allocation_floor = 0;
                return Ok(None);
            }
            let owner = CaptureOwner::from_continuation_prepaid(
                session,
                provenance,
                Continuation {
                    body: OperationBody::AeadMessages(frame),
                    validation,
                    encrypting: exclusive,
                },
                owner_credit,
            );
            // The caller performs the final revision check before installing.
            Ok(Some((owner, io)))
        })();
        match result {
            Ok(Some((owner, io))) => return Ok(Some(PreparedCapture { owner, io, waiter })),
            Ok(None) => continue,
            Err(error) => return Err(waiter.fail_prepared(error, diagnostics)),
        }
    }
}
