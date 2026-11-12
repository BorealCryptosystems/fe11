// SPDX-License-Identifier: Apache-2.0
//! Transactional restore: keep both owners until native replacement is known.
use super::restoration_keys::BoundKeys;

use super::{
    ownership, preparation, progress, state_io, AdvancedSession, Operation, OperationBody,
    OperationTicket, SavedOperationState, StateKeyEncoding, StateRestoreKeys,
};
use crate::{module::Inner, symmetric::memory::Credit, Error, Result};
use std::sync::Arc;
/// Control capability for one explicit restoration. Drop does not cancel it.
pub struct StateRestoreTicket {
    pub(super) owner: Arc<Inner>,
    pub(super) uid: u64,
    pub(super) id: u64,
}
/// A refusal with the original sensitive state returned to its owner.
/// It is not formatted implicitly and no automatic retry is performed.
pub struct StateRestoreFailure {
    /// Exact local or native failure.
    pub error: Error,
    /// Unconsumed captured state, available for an explicit caller decision.
    pub state: SavedOperationState,
}
/// Result of observing a restoration, distinct from cryptographic completion.
pub enum StateRestoreProgress {
    /// Between completed native steps; poll explicitly.
    Ready,
    /// Native call pending; the registry owns every allocation and both plans.
    Pending,
    /// Native state replaced successfully. Only this new ticket may continue it.
    Restored(OperationTicket),
    /// Terminal refusal; saved state returned and no retry issued.
    Refused(StateRestoreFailure),
}
pub(super) struct RestoreOwner {
    pub(super) id: u64,
    pub(super) replacing: bool,
    pub(super) saved: SavedOperationState,
    pub(super) keys: BoundKeys,
    pub(super) initialization: Option<super::native_messages::restoration::PreparedInitialization>,
    pub(super) encodings: (Option<StateKeyEncoding>, Option<StateKeyEncoding>),
    // Prepaid with this control. A successful Set followed by failed publication
    // cannot allocate a diagnostic while native/session possession is held.
    pub(super) publication: Option<crate::error::CompletionStorage>,
    pub(super) refusal: Option<crate::error::FailurePair>,
    pub(super) _credit: Credit,
}

/// Retire sensitive or role-owning values only after the poll's possession and
/// operation guards. A native success transfers resources; it never destroys
/// the replaced cryptographic body beneath those guards.
#[derive(Default)]
struct RetiredRestore {
    body: Option<OperationBody>,
    validation: Option<super::validation::Capture>,
    io: Option<state_io::StateIo>,
    keys: Option<BoundKeys>,
    initialization: Option<super::native_messages::restoration::PreparedInitialization>,
    destination: Option<super::native_messages::restoration::RetiredBinding>,
    saved_bytes: Option<crate::symmetric::memory::Buffer>,
    publication: Option<crate::error::CompletionStorage>,
    refusal: Option<crate::error::FailurePair>,
    control_credit: Option<Credit>,
    saved_credit: Option<Credit>,
}

// Original replacement exclusions shared by the early snapshot and final
// possession. A frozen continuation may be explicitly replaced; this is not the
// broader ordinary control-admission predicate.
fn check_restore_target(op: &Operation, entry: &crate::module::SessionEntry) -> Result<()> {
    op.check_authentication(entry)?;
    if op.rejoin().is_some()
        || op.detachment().is_some()
        || op.state_io().is_some()
        || op.restore_owner().is_some()
        || op.joined.is_some()
        || op.cancel.is_submitted()
        || op.cancellation.is_withdrawn()
        || op.body.pending()
        || op.validation.as_ref().is_some_and(|v| v.waiting())
    {
        return Err(Error::Busy(crate::BusyReason::Restoration(
            crate::RestorationBusy::DestinationOperationControlActive,
        )));
    }
    Ok(())
}
impl AdvancedSession {
    /// Reserve a restoration without making a native call. Supply the exact
    /// destination ticket to replace an existing operation, or None for idle.
    /// Keys must already be admitted in this destination. Every key role has an
    /// explicit supplied/embedded convention; native refusal never changes it.
    /// A local refusal returns the original state. Native work begins on poll.
    /// Fe11 retains the supplied key owners through the native call. The module
    /// decides whether those keys can restore the state; Fe11 does not compare
    /// their public material with a separately supplied expectation.
    pub fn start_state_restore(
        &self,
        saved: SavedOperationState,
        keys: StateRestoreKeys<'_>,
        replace: Option<&OperationTicket>,
    ) -> std::result::Result<StateRestoreTicket, StateRestoreFailure> {
        let mut saved = Some(saved);
        let admission = crate::admission_wait::current();
        let mut diagnostics = None;
        let mut waiter: Option<progress::Waiter<'_>> = None;
        let outcome = (|| -> Result<StateRestoreTicket> {
            let mut progress = crate::session::AdmissionProgress::default().retaining(
                saved
                    .as_ref()
                    .unwrap()
                    .retained_bytes(&self.session.inner.symmetric_budget)?,
            )?;
            let mut key_storage_floor = 0usize;
            'prepare: loop {
                let input = saved.as_ref().unwrap();
                let owner = input.owner.upgrade().ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::SavedStateModuleAbsent,
                    ),
                ))?;
                if !Arc::ptr_eq(&owner, &self.session.inner)
                    || !Arc::ptr_eq(&input.snapshot, &self.session.snapshot)
                {
                    return Err(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::SavedStateContextMismatch,
                    )));
                }
                input
                    .snapshot
                    .check_authentication_unchanged(input.authentication)?;

                {
                    // Local context admission and an optional target registration only. No target Arc,
                    // Operation guard or native access survives resource preparation.
                    let s = self
                        .session
                        .advanced_access_progress_at_epoch(&progress, input.authentication)?;
                    if s.native.table.C_SetOperationState.is_none() {
                        return Err(Error::Rejected(crate::RejectionReason::Restoration(
                            crate::RestorationRejection::CSetOperationStateUnavailable,
                        )));
                    }
                    if let Some(ticket) = replace {
                        if ticket.id == 0
                            || ticket.uid != self.session.uid
                            || !Arc::ptr_eq(&ticket.owner, &self.session.inner)
                        {
                            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                                crate::RestorationRejection::ForeignOrConsumedReplacementTicket,
                            )));
                        }
                        let held = s.operations.get(ticket.uid)?;
                        let operation = held.lock().map_err(|_| Error::Poisoned)?;
                        if operation.id != ticket.id {
                            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                                crate::RestorationRejection::StaleReplacementTicket,
                            )));
                        }
                        check_restore_target(&operation, &self.session.entry)?;
                        if diagnostics.is_none() {
                            drop(operation);
                            drop(held);
                            drop(s);
                            // The consumed source cannot be freed by a peer.
                            // Admit diagnostics against its existing footprint,
                            // before registering a waiter that may need them.
                            let mut prepaid = preparation::reserve_new_while(
                                &self.session,
                                progress::FailureDiagnostics::allocation_bytes(),
                                &progress,
                                || {
                                    input
                                        .snapshot
                                        .observe_authentication_unchanged(input.authentication)?;
                                    Ok(self
                                        .session
                                        .entry
                                        .advanced_operation
                                        .load(std::sync::atomic::Ordering::Acquire)
                                        == ticket.id)
                                },
                            )?
                            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                                crate::RestorationRejection::StaleReplacementTicket,
                            )))?;
                            let prepared =
                                progress::FailureDiagnostics::from_prepaid(&mut prepaid)?;
                            // Keep the same progress object: rebuilding it here
                            // would incorrectly renew its maintenance allowance.
                            progress.retain_additional(&prepared)?;
                            diagnostics = Some(prepared);
                            continue 'prepare;
                        }
                        waiter = Some(progress::Waiter::new(
                            &self.session,
                            operation.id,
                            progress::Effect::PreserveOwner,
                        )?);
                    }
                }
                let bytes = input.bytes.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::SavedStateConsumed,
                    ),
                ))?;
                crate::bounds::ck_length(bytes.as_slice().len())?;
                let total = state_io::StateIo::allocation_bytes()
                    .checked_add(std::mem::size_of::<RestoreOwner>())
                    .and_then(|n| {
                        n.checked_add(crate::error::CompletionStorage::allocation_bytes())
                            .and_then(|n| {
                                n.checked_add(crate::error::FailurePair::allocation_bytes())
                            })
                    })
                    .and_then(|n| n.checked_add(std::mem::size_of::<StateRestoreTicket>()))
                    .and_then(|n| {
                        n.checked_add(if replace.is_none() {
                            preparation::Shell::allocation_bytes()
                        } else {
                            0
                        })
                    })
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RestorationStorageSize,
                    )))?;
                let mut readers = super::keys::restoration::Prepared::captured(
                    &self.session,
                    &input.continuation.body,
                    keys,
                    &progress,
                    input.authentication,
                )?;
                let key_plan = readers.storage_plan(&self.session, input.authentication)?;
                let initialization_plan = readers.initialization_plan();
                let initialization_bytes = initialization_plan
                    .as_ref()
                    .map(super::native_messages::restoration::InitializationPlan::allocation_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let key_bytes = key_plan
                    .allocation_bytes()?
                    .checked_add(initialization_bytes)
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RestorationInitializationAccounting,
                    )))?
                    .max(key_storage_floor);
                let total = total.checked_add(key_bytes).ok_or(Error::Rejected(
                    crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RestorationKeyStorageAccounting,
                    ),
                ))?;
                progress.check_retained(&self.session, total)?;
                let mut prepaid = if let Some(waiting) = waiter.as_mut() {
                    match self
                        .session
                        .inner
                        .symmetric_budget
                        .reserve_controlled_retaining(
                            total,
                            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                            &admission,
                            || {
                                preparation::context(&self.session)?;
                                input
                                    .snapshot
                                    .observe_authentication_unchanged(input.authentication)?;
                                Ok(waiting.changed().then_some(()))
                            },
                            || Ok(None),
                        )? {
                        crate::symmetric::memory::ControlledReservation::Acquired(credit) => credit,
                        crate::symmetric::memory::ControlledReservation::Redirect(()) => {
                            waiting.succeed()?;
                            drop(waiter.take());
                            continue 'prepare;
                        }
                    }
                } else {
                    preparation::reserve_new_with_progress(&self.session, total, &progress)?
                };
                let key_storage = key_plan.allocate()?;
                let initialization_storage = initialization_plan
                    .as_ref()
                    .map(super::native_messages::restoration::InitializationPlan::allocate)
                    .transpose()?;
                let actual_initialization = initialization_storage
                    .as_ref()
                    .map(
                        super::native_messages::restoration::InitializationStorage::allocated_bytes,
                    )
                    .transpose()?
                    .unwrap_or(0);
                let actual = key_storage
                    .allocated_bytes()?
                    .checked_add(actual_initialization)
                    .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::RestorationInitializationCapacity,
                    )))?;
                if actual > key_bytes {
                    key_storage_floor = actual;
                    drop(initialization_storage);
                    drop(key_storage);
                    drop(prepaid);
                    drop(readers);
                    if let Some(waiting) = waiter.as_mut() {
                        waiting.succeed()?;
                    }
                    drop(waiter.take());
                    continue 'prepare;
                }
                prepaid.release(key_bytes - actual);
                let prepared_initialization = initialization_storage
                    .map(|storage| storage.bind(&mut prepaid))
                    .transpose()?;
                readers.attach_storage(key_storage.bind(&mut prepaid)?)?;
                let mut cancel = if replace.is_none() {
                    Some(preparation::Shell::from_prepaid(&mut prepaid)?)
                } else {
                    None
                };
                let mut io = state_io::StateIo::prepare_restore_prepaid(
                    &mut prepaid,
                    bytes.as_slice().len(),
                    input.session_state,
                )?;
                let credit = prepaid;
                let publication = crate::error::CompletionStorage::allocate()?;
                let refusal = crate::error::FailurePair::allocate()?;

                let (s, prepared_readers) =
                    match readers.try_access_with_progress(&self.session, &progress) {
                        Ok(access) => access,
                        Err(error @ Error::Busy(_)) => {
                            // This is a local replan, not abandonment of the
                            // previous revision's resource admission. Consume
                            // its waiter before another registration is made.
                            if let Some(waiting) = waiter.as_mut() {
                                waiting.succeed()?;
                            }
                            drop(waiter.take());
                            drop(io);
                            drop(prepared_initialization);
                            drop(publication);

                            drop(refusal);
                            drop(credit);

                            drop(cancel);
                            readers.wait_after_contention(
                                &self.session,
                                &progress,
                                input.authentication,
                                error,
                            )?;
                            continue 'prepare;
                        }
                        Err(error) => return Err(error),
                    };
                let bound;
                let mut bound_candidate = None;
                let mut candidate: Option<Operation>;
                let mut restore_payload;
                let installed;
                let operation;
                let _retired_readers;
                let mut prepared_readers = prepared_readers;
                let s = s;
                input
                    .snapshot
                    .check_authentication_unchanged(input.authentication)?;
                if s.native.table.C_SetOperationState.is_none() {
                    return Err(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::CSetOperationStateUnavailable,
                    )));
                }
                if let Some(waiting) = waiter.as_mut() {
                    if waiting.changed() {
                        waiting.succeed()?;
                        drop(s);
                        drop(prepared_readers);
                        drop(readers);
                        drop(io);
                        drop(prepared_initialization);
                        drop(publication);

                        drop(refusal);
                        drop(credit);

                        drop(cancel);
                        drop(waiter.take());
                        continue 'prepare;
                    }
                }
                bound = prepared_readers.bind(keys, |permits| {
                    input.continuation.restore_keys(
                        &self.session,
                        keys,
                        permits,
                        &mut bound_candidate,
                    )
                })?;
                check_initialization(
                    &input.continuation.body,
                    &bound,
                    prepared_initialization.as_ref(),
                )?;
                // End source-only borrows before consuming saved state, while
                // retaining attributed roles and credits until access leaves.
                _retired_readers = readers.retire();
                // BoundKeys retains the exact destination references through
                // installation and native restore. The module checks key usability.
                io.bind_restore_keys(bound.native_encryption, bound.native_authentication)?;
                // Both commit closures borrow this owner. If a registry or
                // state-slot check refuses, its resources outlive session access.
                restore_payload = Some((
                    io,
                    bound,
                    prepared_initialization,
                    publication,
                    refusal,
                    credit,
                ));
                if replace.is_none() {
                    let (lease, cancellation) =
                        preparation::Shell::bind_retained(&mut cancel, &s.lease_admission()?)?;
                    candidate = Some(Operation::new(OperationBody::Control, lease, cancellation));
                    check_restore_target(
                        candidate.as_ref().expect("prepared restoration control"),
                        &self.session.entry,
                    )?;
                    // No fallible step follows consumption of saved state. A
                    // rejected registry installation returns the original input.
                    let (id, owner) = s.operations.install_with_retained(
                        &self.session.entry,
                        &mut candidate,
                        &mut None,
                        |op| {
                            let id = op.id;
                            op.begin_restore(|| {
                                let (
                                    mut io,
                                    bound,
                                    prepared_initialization,
                                    publication,
                                    refusal,
                                    credit,
                                ) = restore_payload
                                    .take()
                                    .expect("prepared restoration payload");
                                let mut input = saved.take().expect("unconsumed restoration input");
                                io.attach_restore(
                                    input.bytes.take().expect("validated restoration input"),
                                );
                                (
                                    io,
                                    RestoreOwner {
                                        id,
                                        replacing: false,
                                        saved: input,
                                        keys: bound,
                                        initialization: prepared_initialization,
                                        encodings: (
                                            keys.encryption.map(|k| k.encoding),
                                            keys.authentication.map(|k| k.encoding),
                                        ),
                                        publication: Some(publication),
                                        refusal: Some(refusal),
                                        _credit: credit,
                                    },
                                )
                            })
                            .expect("unshared restoration control slot");
                        },
                    )?;
                    installed = owner;
                    // Keep an explicit installed anchor until access leaves.
                    let _ = &installed;
                    return Ok(StateRestoreTicket {
                        owner: self.session.inner.clone(),
                        uid: self.session.uid,
                        id,
                    });
                }
                let ticket = replace.expect("replacement branch");
                if ticket.id == 0
                    || ticket.uid != self.session.uid
                    || !Arc::ptr_eq(&ticket.owner, &self.session.inner)
                {
                    return Err(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::ForeignOrConsumedReplacementTicket,
                    )));
                }
                operation = s.operations.get(ticket.uid)?;
                let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
                if op.id != ticket.id {
                    return Err(Error::Rejected(crate::RejectionReason::Restoration(
                        crate::RestorationRejection::StaleReplacementTicket,
                    )));
                }
                check_restore_target(&op, &self.session.entry)?;
                if let Some(waiting) = waiter.as_mut() {
                    waiting.succeed()?;
                    s.operations.claim_progress(&self.session.entry, op.id)?;
                }
                let id = s.operations.reserve_ticket()?;
                op.begin_restore(|| {
                    let (mut io, bound, prepared_initialization, publication, refusal, credit) =
                        restore_payload
                            .take()
                            .expect("prepared replacement payload");
                    let mut input = saved.take().unwrap();
                    io.attach_restore(input.bytes.take().unwrap());
                    (
                        io,
                        RestoreOwner {
                            id,
                            replacing: true,
                            saved: input,
                            keys: bound,
                            initialization: prepared_initialization,
                            encodings: (
                                keys.encryption.map(|k| k.encoding),
                                keys.authentication.map(|k| k.encoding),
                            ),
                            publication: Some(publication),
                            refusal: Some(refusal),
                            _credit: credit,
                        },
                    )
                })?;
                return Ok(StateRestoreTicket {
                    owner: self.session.inner.clone(),
                    uid: self.session.uid,
                    id,
                });
            }
        })();
        match outcome {
            Ok(ticket) => Ok(ticket),
            Err(error) => Err(StateRestoreFailure {
                error: match waiter.as_mut() {
                    Some(waiting) => waiting.fail_prepared(
                        error,
                        diagnostics
                            .as_mut()
                            .expect("replacement diagnostics prepared"),
                    ),
                    None => error,
                },
                state: saved.unwrap(),
            }),
        }
    }
    /// Progress only the restore control. A completed success atomically replaces
    /// the old local plan and ticket after C_SetOperationState OK. Refusal does
    /// not promise the old native state survived an error with possible effects.
    pub fn poll_state_restore(
        &self,
        ticket: &mut StateRestoreTicket,
    ) -> Result<StateRestoreProgress> {
        let mut retired = RetiredRestore::default();
        let operation;
        if ticket.id == 0
            || ticket.uid != self.session.uid
            || !Arc::ptr_eq(&ticket.owner, &self.session.inner)
        {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::ForeignOrConsumedRestorationTicket,
            )));
        }
        let s = self.session.advanced_access()?;
        operation = s.operations.get(ticket.uid)?;
        let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
        let control = op.restore_owner().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationAbsent,
            ),
        ))?;
        if control.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::StaleRestorationTicket,
            )));
        }
        if op.restore_transfer().is_some() || op.rejoin().is_some() {
            return Err(Error::Busy(crate::BusyReason::Restoration(
                crate::RestorationBusy::RestorationTransferActive,
            )));
        }
        control
            .saved
            .snapshot
            .check_authentication_unchanged(control.saved.authentication)?;
        let mut remaining = self.pacing.budget();
        let outcome = (|| -> Result<()> {
            if !op.drive_join(&s, &self.session.entry, true, &mut remaining)? {
                return Ok(());
            }
            op.drive_restoration(&s, &self.session.entry, &mut remaining)
        })();
        if outcome.is_err()
            && !s.native.is_uncertain()
            && op.state_io().is_some_and(|io| !io.pending())
            && op.joined.as_ref().is_some_and(|call| call.consumed())
        {
            op.joined.take();
        }
        let joined = op.joined.is_some();
        let io = op.state_io_mut().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationIoAbsent,
            ),
        ))?;
        if let Err(error) = outcome {
            if io.pending() || joined {
                return Err(error);
            }
            let bytes = io.take_refused_restore()?;
            let (io, mut control) = op.take_restore().unwrap();
            retired.io = Some(io);
            control.saved.bytes = Some(bytes);
            match &mut control.saved.continuation.body {
                OperationBody::Signature(body) => body.retain_refused_binding(&control.keys),
                OperationBody::Cipher(body) => body.retain_refused_binding(&control.keys),
                OperationBody::NativeMessages(body) => body.retain_refused_binding(&control.keys),
                _ => {}
            }
            ticket.id = 0;
            retired.keys = Some(control.keys);
            retired.initialization = control.initialization;
            retired.publication = control.publication;
            retired.refusal = control.refusal;
            retired.control_credit = Some(control._credit);
            // StateIo already applies the native failure scope. Keep any old
            // identity/frames; ordinary access refuses a withdrawn session.
            let release = !control.replacing;
            drop(op);
            // Saved state has left the registry. From here every outcome must
            // return it, including a failed local retirement of the empty owner.
            let error = if release {
                match s.operations.release_closed(&self.session.entry) {
                    Ok(()) => error,
                    Err(cleanup) => retired
                        .refusal
                        .take()
                        .expect("restore refusal diagnostic prepared before possession")
                        .finish(error, cleanup),
                }
            } else {
                error
            };
            return Ok(StateRestoreProgress::Refused(StateRestoreFailure {
                error,
                state: control.saved,
            }));
        }
        if !io.complete() {
            return Ok(if io.pending() {
                StateRestoreProgress::Pending
            } else {
                StateRestoreProgress::Ready
            });
        }
        // Retain the complete native input/output owners if local publication
        // fails after SetOperationState. A successful native replacement cannot
        // be repeated to recover a poisoned coordination cell.
        let replacement = op.restore_owner().unwrap().id;
        if let Err(cause) = s
            .operations
            .publish_replacement(&self.session.entry, replacement)
        {
            s.native.mark_uncertain();
            // mark_uncertain prevents another ordinary restore poll from
            // reaching this single-use publication diagnostic.
            return op
                .restore_owner_mut()
                .expect("completed restoration control")
                .publication
                .take()
                .expect("restoration publication diagnostic prepared")
                .bind("C_SetOperationState")
                .finish(Err(cause));
        }
        // All remaining transfers are infallible. New leases already retain
        // the original creator, even for an embedded native key.
        let (io, mut control) = op.take_restore().unwrap();
        retired.io = Some(io);
        if let OperationBody::NativeMessages(body) = &mut control.saved.continuation.body {
            retired.destination = Some(
                body.commit_restoration(
                    control.keys,
                    control
                        .initialization
                        .take()
                        .expect("validated message initialization"),
                ),
            );
        } else {
            retired.keys = Some(control.saved.continuation.bind_restored(control.keys));
        }
        // Native replacement has completed and the saved epoch was checked
        // under token activity. Transfer it with the new body, never on refusal
        // and never by relabelling the old operation before C_SetOperationState.
        op._token.authentication = control.saved.authentication;
        retired.body = Some(std::mem::replace(
            &mut op.body,
            control.saved.continuation.body,
        ));
        retired.validation =
            std::mem::replace(&mut op.validation, control.saved.continuation.validation);
        op.provenance = Some(control.saved.provenance);
        op.id = control.id;
        op.cancellation = ownership::CancellationState::Uncancelled;
        op.continuation_status = ownership::ContinuationStatus::Runnable;
        retired.saved_bytes = control.saved.bytes;
        retired.publication = control.publication;
        retired.refusal = control.refusal;
        retired.control_credit = Some(control._credit);
        retired.saved_credit = Some(control.saved._credit);
        ticket.id = 0;
        Ok(StateRestoreProgress::Restored(OperationTicket {
            owner: self.session.inner.clone(),
            uid: self.session.uid,
            id: control.id,
            validation_report: None,
            state_provenance: op.provenance,
        }))
    }
}

pub(super) fn check_initialization(
    body: &OperationBody,
    keys: &BoundKeys,
    initialization: Option<&super::native_messages::restoration::PreparedInitialization>,
) -> Result<()> {
    match (body, keys.native_messages(), initialization) {
        (OperationBody::NativeMessages(body), Some(binding), Some(initialization)) => {
            initialization.check(body, binding)
        }
        (OperationBody::NativeMessages(_), _, _) | (_, Some(_), _) | (_, _, Some(_)) => {
            Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestorationInitializationOwnerMismatch,
            )))
        }
        _ => Ok(()),
    }
}
