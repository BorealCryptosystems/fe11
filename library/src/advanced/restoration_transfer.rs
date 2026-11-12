// SPDX-License-Identifier: Apache-2.0
//! Explicit transfer of a restore control, never of its old destination plan.
use super::preparation::Shell;

use super::{
    asynchronous, ownership, progress, reconstruction, record, state_io, AdvancedSession,
    AdvancedSessionMode, DetachedOperation, DetachmentProgress, Operation, OperationBody,
    RejoinKeys, SavedOperationState, StateKeyEncoding, StateKeyReference, StateRestoreKey,
    StateRestoreKeys, StateRestoreTicket,
};
use super::{restoration::RestoreOwner, restoration_keys::BoundKeys};
use crate::{
    bounds,
    module::{SessionEntry, State},
    symmetric::memory::{Budget, Buffer, Credit},
    Error, Result, Session,
};
use fe11_sys::{CK_SLOT_ID, CK_ULONG};
use std::sync::Arc;
mod preparation;

pub(super) struct RestoreTransfer {
    get_id: asynchronous::GetId,
    id: Option<CK_ULONG>,
    limits: record::Limits,
    source_slot: CK_SLOT_ID,
    publication: Option<preparation::Publication>,
    _credit: Credit,
}
impl RestoreTransfer {
    pub(super) fn execution_incomplete(&self) -> bool {
        self.get_id.execution_incomplete()
    }
}

impl Drop for RestoreTransfer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(id) = &mut self.id {
            id.zeroize();
        }
    }
}
fn check(session: &Session, ticket: &StateRestoreTicket, op: &Operation) -> Result<()> {
    if ticket.id == 0 || ticket.uid != session.uid || !Arc::ptr_eq(&ticket.owner, &session.inner) {
        return Err(Error::Rejected(crate::RejectionReason::Restoration(
            crate::RestorationRejection::ForeignOrConsumedRestorationTicket,
        )));
    }
    if op.restore_owner().map(|c| c.id) != Some(ticket.id) {
        return Err(Error::Rejected(crate::RejectionReason::Restoration(
            crate::RestorationRejection::StaleRestorationTicket,
        )));
    }
    Ok(())
}
impl RestoreOwner {
    pub(super) fn check_keys(&self, entry: &SessionEntry) -> Result<()> {
        self.saved
            .snapshot
            .check_authentication_unchanged(self.saved.authentication)?;
        self.keys.check(entry)?;
        super::restoration::check_initialization(
            &self.saved.continuation.body,
            &self.keys,
            self.initialization.as_ref(),
        )
    }
    /// Write the nested Saved envelope directly into the destination. Before
    /// GetID, callers pass an empty native slice and inspect metadata only.
    fn write_record(
        &self,
        budget: &Arc<Budget>,
        io: &state_io::StateIo,
        limits: record::Limits,
        source_slot: CK_SLOT_ID,
        id: CK_ULONG,
        native: &[u8],
        writer: &mut record::Writer<'_>,
    ) -> Result<()> {
        let context = self.saved.checkpoint_context()?;
        writer.record_bytes(record::Kind::Saved, limits, |nested| {
            self.saved
                .write_checkpoint_with_native(budget, limits, &context, native, nested)
        })?;
        record::RestorationRecord::write_tail(
            writer,
            self.encodings.0,
            self.encodings.1,
            record::Function::from_name(io.function()?)?,
            id,
            source_slot,
        )
    }
}
impl AdvancedSession {
    /// Native restoration detachment requires the unsupported native asynchronous mode and is
    /// rejected on current synchronous sessions before native detachment.
    /// Transfer a pending restoration control explicitly. No Set is repeated.
    /// Before GetID only metadata and the immutable input length are inspected;
    /// state bytes remain owned until the native release is established.
    pub fn start_restore_detachment(
        &self,
        ticket: &mut StateRestoreTicket,
        maximum_bytes: usize,
    ) -> Result<DetachmentProgress> {
        self.session.inner.module_binding.persistent_digest()?;
        let limits = record::Limits {
            bytes: maximum_bytes,
            messages: 1024,
            fragments: 1024,
        };
        limits.validate()?;
        bounds::ck_length(maximum_bytes)?;
        let budget = &self.session.inner.symmetric_budget;
        // Neither candidate nor registration retains source possession while
        // credit is unavailable. The exact operation revision guards reentry.
        let mut diagnostics = None;
        let mut candidate: Option<preparation::Prepared> = None;
        let mut waiter: Option<progress::Waiter<'_>> = None;
        loop {
            let s = self.session.advanced_access()?;
            let held = s.operations.get(self.session.uid)?;
            let mut op = held.lock().map_err(|_| Error::Poisoned)?;
            check(&self.session, ticket, &op)?;
            op.check_authentication(&self.session.entry)?;
            if self.mode() != AdvancedSessionMode::Asynchronous {
                return Err(Error::Rejected(crate::RejectionReason::Detachment(
                    crate::DetachmentRejection::AsynchronousDetachmentSessionMode,
                )));
            }
            if op.rejoin().is_some() || op.detachment().is_some() || op.cancel.is_submitted() {
                return Err(Error::Busy(crate::BusyReason::Restoration(
                    crate::RestorationBusy::RestorationControlActive,
                )));
            }
            if op.restore_transfer().is_some() {
                return Err(Error::Busy(crate::BusyReason::Restoration(
                    crate::RestorationBusy::RestorationTransferActive,
                )));
            }
            let owner = op.restore_owner().unwrap();
            owner.check_keys(&self.session.entry)?;
            let function = asynchronous::GetId::checked_function(&op)?;
            let io = op.state_io().ok_or(Error::Rejected(
                crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::RestorationIoAbsent,
                ),
            ))?;
            let source_slot = io.restore_source_slot(self.session.entry.slot);
            let preview_length = record::encoded_size(limits, |writer| {
                owner.write_record(budget, io, limits, source_slot, 0, &[], writer)
            })?;
            let record_length = preview_length
                .checked_add(io.restore_input_length()?)
                .filter(|n| *n <= limits.bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RestorationTransferCeiling,
                )))?;
            if s.native.asynchronous.and_then(|f| f.get_id).is_none() {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::CAsyncGetIDUnavailable,
                    ),
                ));
            }
            let shape = preparation::Shape {
                function,
                source_slot,
                preview_length,
                record_length,
            };
            if diagnostics.is_none() {
                // Every refusal above is a pure preflight. Prepare outside
                // possession, then revalidate the exact restoration owner.
                drop(op);
                drop(held);
                drop(s);
                diagnostics = Some(progress::FailureDiagnostics::prepare(
                    &self.session,
                    ticket.id,
                )?);
                continue;
            }
            if let Some(waiting) = waiter.as_mut() {
                if waiting.changed() || candidate.as_ref().is_some_and(|p| p.shape != shape) {
                    waiting.succeed()?;
                    drop(op);
                    drop(held);
                    drop(s);
                    drop(candidate.take());
                    drop(waiter.take());
                    continue;
                }
            }
            if let Some(mut prepared) = candidate.take() {
                record::encode_into(
                    record::Kind::DetachedRestore,
                    limits,
                    &mut prepared.preview,
                    |writer| owner.write_record(budget, io, limits, source_slot, 0, &[], writer),
                )?;
                record::RestorationRecord::read(prepared.preview.as_slice(), limits)?;
                waiter.as_mut().expect("transfer waiter").succeed()?;
                s.operations.claim_progress(&self.session.entry, op.id)?;
                op.begin_restore_transfer(|| RestoreTransfer {
                    get_id: prepared.get_id,
                    id: None,
                    limits,
                    source_slot,
                    publication: Some(prepared.publication),
                    _credit: prepared.control_credit,
                })?;
                return self.finish_restore_detachment(&s, &mut op, ticket);
            }
            let authentication = op._token.authentication;
            waiter = Some(progress::Waiter::new(
                &self.session,
                op.id,
                progress::Effect::PreserveOwner,
            )?);
            drop(op);
            drop(held);
            drop(s);
            let waiting = waiter.as_mut().expect("transfer waiter");
            let diagnostics = diagnostics
                .as_mut()
                .expect("restore transfer diagnostics prepared");
            match preparation::prepare(
                &self.session,
                diagnostics.budget(),
                shape,
                authentication,
                waiting,
            ) {
                Ok(Some(prepared)) => candidate = Some(prepared),
                Ok(None) => {
                    waiting.succeed()?;
                    drop(waiter.take());
                }
                Err(error) => return Err(waiting.fail_prepared(error, diagnostics)),
            }
        }
    }

    /// Finish local publication after an accepted transfer. This never repeats
    /// GetID after success and cannot poll or restart the original restoration.
    pub fn poll_restore_detachment(
        &self,
        ticket: &mut StateRestoreTicket,
    ) -> Result<DetachmentProgress> {
        let s = self.session.advanced_access()?;
        let held = s.operations.get(self.session.uid)?;
        let mut op = held.lock().map_err(|_| Error::Poisoned)?;
        check(&self.session, ticket, &op)?;
        if op.restore_transfer().is_none() {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestorationTransferAbsent,
            )));
        }
        s.operations.claim_progress(&self.session.entry, op.id)?;
        self.finish_restore_detachment(&s, &mut op, ticket)
    }
    fn finish_restore_detachment(
        &self,
        s: &State,
        op: &mut Operation,
        ticket: &mut StateRestoreTicket,
    ) -> Result<DetachmentProgress> {
        let owner = op.restore_owner().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationAbsent,
            ),
        ))?;
        owner.check_keys(&self.session.entry)?;
        let transfer =
            op.restore_transfer()
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RestorationTransferAbsent,
                )))?;
        if transfer.get_id.retains_native_memory() {
            return Err(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestorationTransferUncertain,
            )));
        }
        if transfer.id.is_none() {
            let result = op
                .restore_transfer_mut()
                .unwrap()
                .get_id
                .dispatch(s, &self.session.entry);
            match result {
                Err(error) => {
                    if !op
                        .restore_transfer()
                        .unwrap()
                        .get_id
                        .retains_native_memory()
                    {
                        op.take_restore_transfer();
                    }
                    return Err(error);
                }
                Ok(id) => {
                    op.continuation_status = ownership::ContinuationStatus::Frozen(
                        ownership::FreezeReason::NativeDetachment,
                    );
                    op.restore_transfer_mut().unwrap().id = Some(id);
                    op.state_io_mut().unwrap().detached_restore_release();
                    op.joined.take();
                }
            }
        }
        // Take only local publication storage. The source, native ID and input
        // remain installed on every error; no failed copy can redispatch GetID.
        let mut publication = op
            .restore_transfer_mut()
            .unwrap()
            .publication
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestorationPublicationStorageAbsent,
            )))?;
        let result = (|| -> Result<_> {
            let owner = op.restore_owner().unwrap();
            let transfer = op.restore_transfer().unwrap();
            let io = op.state_io().ok_or(Error::Rejected(
                crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::RestorationIoAbsent,
                ),
            ))?;
            record::encode_into(
                record::Kind::DetachedRestore,
                transfer.limits,
                &mut publication.record,
                |writer| {
                    owner.write_record(
                        &self.session.inner.symmetric_budget,
                        io,
                        transfer.limits,
                        transfer.source_slot,
                        transfer.id.unwrap(),
                        io.restore_input()?,
                        writer,
                    )
                },
            )?;
            record::RestorationRecord::read(publication.record.as_slice(), transfer.limits)?;
            if matches!(op.body, OperationBody::Control) {
                s.operations.release_closed(&self.session.entry)?;
            }
            Ok((owner.saved.provenance, transfer.limits))
        })();
        let (provenance, limits) = match result {
            Ok(value) => value,
            Err(error) => {
                op.restore_transfer_mut().unwrap().publication = Some(publication);
                return Err(error);
            }
        };
        let result = DetachedOperation {
            provenance: Some(provenance),
            record: publication.record,
            limits,
            _credit: publication.credit,
        };
        // An old crypto body is not transferred by Info or Set. Retain its
        // frozen owner until the caller explicitly cancels/closes the source.
        op.state.take();
        op.take_restore_transfer();
        ticket.id = 0;
        Ok(DetachmentProgress::Detached(result))
    }
}

/// Unpublished restore-transfer storage. It owns no Activity permission or
/// session guard and cannot dispatch until final destination binding.
pub(super) struct PreparedDestination {
    continuation: reconstruction::DestinationContinuation,
    bytes: Option<Buffer>,
    io: state_io::StateIo,
    call: asynchronous::JoinedCall,
    publication: crate::error::CompletionStorage,
    refusal: crate::error::FailurePair,
    credit: Credit,
    saved_credit: Credit,
}
/// Validated scalar record fields needed by the final ownership transfer.
pub(super) struct DestinationBinding {
    context: record::Context,
    expected: fe11_sys::CK_STATE,
    provenance: super::StateProvenance,
    encodings: (Option<StateKeyEncoding>, Option<StateKeyEncoding>),
}
impl PreparedDestination {
    pub(super) fn prepare_at_epoch(
        session: &Session,
        input: &DetachedOperation,
        progress: &crate::session::AdmissionProgress,
        extra_bytes: usize,
        keys: RejoinKeys<'_>,
        authentication: u64,
    ) -> Result<(Self, Credit, super::keys::KeyReaders<2>)> {
        let r = record::RestorationRecord::read(input.record.as_slice(), input.limits)?;
        // The nested Saved codec understands generic messages, but joining an
        // outstanding native restore also needs their destination graph owner.
        // native asynchronous mode remains unsupported; do not route that owner through read-only
        // legacy key reconstruction or fabricate its initialization authority.
        if r.saved.descriptor.family == record::Family::NativeMessages {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::GenericMessageAsynchronousModeUnavailable,
                ),
            ));
        }
        r.saved
            .context
            .check_destination_binding(&session.inner, &session.snapshot)?;
        let expected = r.saved.context.required_session_state()?;
        let recipe = reconstruction::Recipe::checkpoint(
            r.saved.descriptor,
            &r.saved.keys,
            &r.saved.messages,
            r.saved.validation.as_ref(),
            input.limits,
            session.inner.crypto_options.limits,
        )?;
        let join = asynchronous::JoinPlan::new(r.function.name(), r.id, r.capacity)?;
        let fixed = reconstruction::resources::total(&[
            extra_bytes,
            state_io::StateIo::allocation_bytes(),
            std::mem::size_of::<RestoreOwner>(),
            crate::error::CompletionStorage::allocation_bytes(),
            crate::error::FailurePair::allocation_bytes(),
            std::mem::size_of::<StateRestoreTicket>(),
            std::mem::size_of::<SavedOperationState>(),
        ])?;
        let readers = super::keys::KeyReaders::prepare_retaining_at_epoch(
            session,
            [
                keys.encryption.map(StateKeyReference::managed),
                keys.authentication.map(StateKeyReference::managed),
            ],
            authentication,
            progress,
        )?;
        let resources = reconstruction::resources::Resources::prepare_at_epoch(
            session,
            progress,
            recipe,
            Some(r.saved.native.len()),
            Some(join),
            fixed,
            authentication,
        )?;
        let mut metadata = resources.metadata;
        let continuation = resources.continuation;
        let mut bytes =
            resources
                .native
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RestoreNativeStorageAbsent,
                )))?;
        bytes.as_mut().copy_from_slice(r.saved.native);
        let io = state_io::StateIo::prepare_restore_prepaid(
            &mut metadata,
            bytes.as_slice().len(),
            expected,
        )?;
        let call = resources
            .joined
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::RestoreJoinedStorageAbsent,
            )))?;
        let credit = metadata.split(reconstruction::resources::total(&[
            std::mem::size_of::<RestoreOwner>(),
            crate::error::CompletionStorage::allocation_bytes(),
            crate::error::FailurePair::allocation_bytes(),
            std::mem::size_of::<StateRestoreTicket>(),
        ])?)?;
        let saved_credit = metadata.split(std::mem::size_of::<SavedOperationState>())?;
        let publication = crate::error::CompletionStorage::allocate()?;
        let refusal = crate::error::FailurePair::allocate()?;
        Ok((
            Self {
                continuation: reconstruction::DestinationContinuation::Prepared(continuation),
                bytes: Some(bytes),
                io,
                call,
                publication,
                refusal,
                credit,
                saved_credit,
            },
            metadata,
            readers,
        ))
    }

    /// All partial owners remain in self or caller slots declared before access.
    pub(super) fn prepare_binding(
        &mut self,
        session: &Session,
        admission: &crate::session::LeaseAdmission<'_, '_>,
        input: &DetachedOperation,
        keys: RejoinKeys<'_>,
        cancel: &mut Option<Shell>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut Option<BoundKeys>,
        duplicate: &mut Option<BoundKeys>,
        token: &mut Option<(
            super::lease::TokenLease,
            super::preparation::PreparedControl,
        )>,
    ) -> Result<DestinationBinding> {
        if !admission.access().owns_session(session) {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::ForeignOperationLeaseAdmission,
            )));
        }
        let r = record::RestorationRecord::read(input.record.as_slice(), input.limits)?;
        r.saved
            .context
            .check_destination_binding(&session.inner, &session.snapshot)?;
        let expected = r.saved.context.required_session_state()?;
        fn role(
            reference: Option<StateKeyReference<'_>>,
            encoding: Option<StateKeyEncoding>,
        ) -> Result<Option<StateRestoreKey<'_>>> {
            match (reference, encoding) {
                (None, None) => Ok(None),
                (Some(reference), Some(encoding)) => Ok(Some(StateRestoreKey {
                    reference,
                    encoding,
                })),
                _ => Err(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RestoreTransferDestinationKeyRoles,
                ))),
            }
        }
        *bound = Some(BoundKeys::from_record_retained(
            session,
            r.saved.descriptor,
            &r.saved.keys,
            &r.saved.messages,
            StateRestoreKeys {
                extension: None,
                encryption: role(keys.encryption, r.encryption)?,
                authentication: role(keys.authentication, r.authentication)?,
            },
            permits,
            bound,
        )?);
        let keys = bound.as_ref().expect("bound restoration transfer keys");
        *duplicate = Some(keys.duplicate_retained(duplicate)?);
        self.continuation
            .bind(duplicate.as_mut().expect("duplicated transfer keys"))?;
        self.io
            .bind_restore_keys(keys.native_encryption, keys.native_authentication)?;
        self.io
            .attach_restore(self.bytes.take().expect("prepared restore transfer bytes"));
        self.io
            .mark_joined_restore(r.function.name(), r.source_slot)?;
        let provenance =
            input
                .provenance
                .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                    crate::RestorationRejection::RestorationTransferProvenanceAbsent,
                )))?;
        *token = Some(Shell::bind_retained(cancel, admission)?);
        Ok(DestinationBinding {
            context: r.saved.context,
            expected,
            provenance,
            encodings: (r.encryption, r.authentication),
        })
    }
    /// No refusal remains after prepare_binding succeeds on these inputs.
    pub(super) fn finish_binding(
        self,
        session: &Session,
        binding: DestinationBinding,
        bound: BoundKeys,
        token: (
            super::lease::TokenLease,
            super::preparation::PreparedControl,
        ),
    ) -> (Operation, record::Context, asynchronous::JoinedCall) {
        let saved = SavedOperationState {
            provenance: binding.provenance,
            owner: Arc::downgrade(&session.inner),
            snapshot: session.snapshot.clone(),
            authentication: session.snapshot.authentication_stamp(),
            session_state: binding.expected,
            bytes: None,
            continuation: self.continuation.into_bound(),
            _credit: self.saved_credit,
        };
        let (token, cancel) = token;
        let mut op = Operation::new(OperationBody::Control, token, cancel);
        op.provenance = Some(binding.provenance);
        op.begin_restore(|| {
            (
                self.io,
                RestoreOwner {
                    id: 0,
                    replacing: false,
                    saved,
                    keys: bound,
                    initialization: None,
                    encodings: binding.encodings,
                    publication: Some(self.publication),
                    refusal: Some(self.refusal),
                    _credit: self.credit,
                },
            )
        })
        .expect("new restoration control has an empty state slot");
        (op, binding.context, self.call)
    }
}
