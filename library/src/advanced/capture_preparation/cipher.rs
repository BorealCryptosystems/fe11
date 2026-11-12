// SPDX-License-Identifier: Apache-2.0
//! Cipher continuation storage, prepared without retaining source possession.
use super::PreparedCapture;
use crate::advanced::{
    continuation::Continuation, preparation, progress, saved_state::CaptureOwner,
    state_io::StateIo, validation, OperationBody, OperationTicket,
};
use crate::{
    symmetric::memory::{ControlledReservation, Credit},
    Error, Result, Session,
};
enum CipherCandidate {
    Layout {
        shape: crate::advanced::cipher::snapshot::Shape,
        layout: crate::advanced::capture_layout::Layouts,
        credit: Credit,
        validation_maximum: Option<usize>,
        reserved: usize,
        layout_bytes: usize,
        graph: Option<crate::advanced::cipher::extension_snapshot::Packet>,
    },
    Ready {
        frame: crate::advanced::cipher::snapshot::PreparedSnapshot,
        validation: Option<validation::Capture>,
        credit: Credit,
        io: StateIo,
    },
}

pub(super) fn prepare<'a>(
    session: &'a Session,
    ticket: &OperationTicket,
    state_maximum: usize,
    diagnostics: &mut progress::FailureDiagnostics,
) -> Result<Option<PreparedCapture<'a>>> {
    let budget = diagnostics.budget().clone();
    let policy = crate::admission_wait::current();
    let mut retry_total = 0usize;
    let mut candidate: Option<CipherCandidate> = None;
    // Candidate presence implies a registered waiter. Creation of a candidate
    // follows waiter installation; every reset clears both before continuing.
    // A ready candidate transfers its waiter once. Failure returns immediately,
    // so neither native outcomes nor caught unwinds can reuse a consumed waiter.
    let mut waiter: Option<progress::Waiter<'a>> = None;
    loop {
        let access = session.advanced_access()?;
        let held = access.operations.get(ticket.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleOperationTicket,
            )));
        }
        operation.check_authentication(&session.entry)?;
        if operation.capture_owner().is_some() {
            return Err(Error::Busy(crate::BusyReason::CheckpointCapture(
                crate::CheckpointCaptureBusy::StateCaptureActive,
            )));
        }
        Continuation::check_capture(&operation, &session.entry)?;
        let OperationBody::Cipher(source) = &operation.body else {
            return Ok(None);
        };
        let shape = source.snapshot_shape(&session.entry)?;
        if waiter.as_ref().is_some_and(|waiting| waiting.changed()) {
            waiter.as_mut().expect("snapshot waiter").succeed()?;
            drop(operation);
            drop(held);
            drop(access);
            drop(candidate.take());
            drop(waiter.take());
            retry_total = 0;
            continue;
        }
        match candidate.take() {
            Some(CipherCandidate::Ready {
                frame,
                mut validation,
                credit,
                io,
            }) => {
                match (&mut validation, &operation.validation) {
                    (Some(target), Some(original)) => target.copy_snapshot_from(original)?,
                    (None, None) => {}
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                            crate::OperationOwnershipRejection::ValidationSnapshotShapeChanged,
                        )))
                    }
                }
                let continuation = Continuation {
                    body: OperationBody::Cipher(frame.copy_from(source, &session.entry)?),
                    validation,
                    encrypting: source.encrypting(),
                };
                let owner = CaptureOwner::from_continuation_prepaid(
                    session,
                    operation.provenance,
                    continuation,
                    credit,
                );
                return Ok(Some(PreparedCapture {
                    owner,
                    io,
                    waiter: waiter.take().expect("snapshot waiter"),
                }));
            }
            Some(CipherCandidate::Layout {
                shape: planned,
                mut layout,
                mut credit,
                validation_maximum,
                reserved,
                layout_bytes,
                mut graph,
            }) => {
                if shape != planned {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::CipherSnapshotShapeChanged,
                    )));
                }
                let parameters = source.describe_snapshot_with_graph(
                    &mut layout,
                    &mut credit,
                    graph.as_mut(),
                )?;
                drop(operation);
                drop(held);
                drop(access);
                let prepared = (|| -> Result<Option<CipherCandidate>> {
                    let parameters = match &graph {
                        Some(packet) => packet.parameters()?,
                        None => {
                            parameters
                                .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                                crate::CheckpointCaptureRejection::CipherCaptureParametersAbsent,
                            )))?
                        }
                    };
                    let graph_bytes = graph.as_ref().map_or(0, |packet| packet.capacity());
                    let frame = planned.allocate(&layout, parameters)?;
                    let validation = validation_maximum
                        .map(validation::CaptureStorage::allocate)
                        .transpose()?;
                    let actual = frame
                        .allocated_bytes()?
                        .checked_add(
                            validation
                                .as_ref()
                                .map(validation::CaptureStorage::allocated_bytes)
                                .transpose()?
                                .unwrap_or(0),
                        )
                        .and_then(|n| n.checked_add(CaptureOwner::allocation_bytes()))
                        .and_then(|n| n.checked_add(StateIo::allocation_bytes()))
                        .and_then(|n| n.checked_add(layout_bytes))
                        .and_then(|n| n.checked_add(graph_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                            crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
                        )))?;
                    if actual > reserved {
                        retry_total = actual;
                        return Ok(None);
                    }
                    credit.release(reserved - actual);
                    let mut frame = frame.bind(&mut credit)?;
                    if let Some(packet) = &graph {
                        frame.bind_extension_contract(packet.contract()?)?;
                    }
                    let validation = validation
                        .map(|storage| storage.bind(&mut credit))
                        .transpose()?;
                    let io = StateIo::capture_prepaid(&mut credit, state_maximum)?;
                    let owner_credit = credit.split(CaptureOwner::allocation_bytes())?;
                    Ok(Some(CipherCandidate::Ready {
                        frame,
                        validation,
                        credit: owner_credit,
                        io,
                    }))
                })();
                drop(layout);
                drop(credit);
                match prepared {
                    Ok(Some(value)) => candidate = Some(value),
                    Ok(None) => {
                        waiter.as_mut().expect("snapshot waiter").succeed()?;
                        drop(waiter.take());
                    }
                    Err(error) => {
                        return Err(waiter
                            .as_mut()
                            .expect("snapshot waiter")
                            .fail_prepared(error, diagnostics))
                    }
                }
            }
            None => {
                let maximum = operation
                    .validation
                    .as_ref()
                    .map(validation::Capture::snapshot_capacity)
                    .transpose()?;
                let required = shape
                    .allocation_bytes()
                    .checked_add(
                        maximum
                            .map(validation::Capture::allocation_bytes)
                            .transpose()?
                            .unwrap_or(0),
                    )
                    .and_then(|n| n.checked_add(StateIo::allocation_bytes()))
                    .and_then(|n| n.checked_add(CaptureOwner::allocation_bytes()))
                    .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
                    )))?;
                let authentication = operation._token.authentication;
                waiter = Some(progress::Waiter::new(
                    session,
                    operation.id,
                    progress::Effect::PreserveOwner,
                )?);
                drop(operation);
                drop(held);
                drop(access);
                let waiting = waiter.as_mut().expect("snapshot waiter");
                let prepared = (|| -> Result<_> {
                    let mut reserved = required.max(retry_total);
                    loop {
                        let mut credit = match budget.reserve_controlled_retaining(
                            reserved,
                            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                            &policy,
                            || {
                                preparation::context(session)?;
                                session
                                    .snapshot
                                    .observe_authentication_unchanged(authentication)?;
                                Ok(waiting.changed().then_some(()))
                            },
                            || Ok(None),
                        )? {
                            ControlledReservation::Acquired(credit) => credit,
                            ControlledReservation::Redirect(()) => return Ok(None),
                        };
                        let storage = shape.allocate_layout()?;
                        let layout_bytes = storage.allocated_bytes()?;
                        let graph = shape
                            .graph_packet_bytes()
                            .map(crate::symmetric::memory::UnboundBuffer::allocate)
                            .transpose()?;
                        let graph_extra = graph
                            .as_ref()
                            .map_or(0, |buffer| buffer.allocated())
                            .checked_sub(shape.graph_packet_bytes().unwrap_or(0))
                            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                                crate::CheckpointCaptureRejection::CipherGraphPacketAccounting,
                            )))?;
                        let actual = required
                            .checked_sub(shape.layout_bytes()?)
                            .and_then(|n| n.checked_add(layout_bytes))
                            .and_then(|n| n.checked_add(graph_extra))
                            .ok_or(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                                crate::CheckpointCaptureRejection::SnapshotStorageAccounting,
                            )))?
                            .max(retry_total);
                        if actual > reserved {
                            drop(graph);
                            drop(storage);
                            drop(credit);
                            reserved = actual;
                            continue;
                        }
                        credit.release(reserved - actual);
                        let layout = storage.bind(&mut credit)?;
                        let graph = graph
                            .map(|buffer| {
                                buffer
                                    .bind(&mut credit)
                                    .map(crate::advanced::cipher::extension_snapshot::Packet::new)
                            })
                            .transpose()?;
                        return Ok(Some(CipherCandidate::Layout {
                            shape,
                            layout,
                            credit,
                            validation_maximum: maximum,
                            reserved: actual,
                            layout_bytes,
                            graph,
                        }));
                    }
                })();
                match prepared {
                    Ok(Some(value)) => candidate = Some(value),
                    Ok(None) => {
                        waiting.succeed()?;
                        drop(waiter.take());
                    }
                    Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
                }
            }
        }
    }
}
