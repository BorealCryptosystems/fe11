// SPDX-License-Identifier: Apache-2.0
//! Explicit destination binding and one-shot native asynchronous attachment.
use super::restoration_keys::BoundKeys;
use super::{
    asynchronous, preparation, reconstruction, record, restoration_transfer, saved_state, spend,
    state_io, AdvancedSession, AdvancedSessionMode, DetachedOperation, Operation, OperationBody,
    OperationTicket, StateKeyEncoding, StateKeyReference, StateRestoreKey, StateRestoreKeys,
    StateRestoreTicket,
};

use crate::module::{Inner, SessionEntry, State};
use crate::symmetric::memory::Credit;

use crate::{Error, Result, Session};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Already admitted destination references; no serialized native handles.
/// The references retain their module/session identity and role. No comparison
/// of public-key fingerprints or historical protection is an admission condition.
#[derive(Clone, Copy, Default)]
pub struct RejoinKeys<'a> {
    /// Cipher role required by the detached cryptographic plan, if any.
    pub encryption: Option<StateKeyReference<'a>>,
    /// MAC/signature/verification role required by the plan, if any.
    pub authentication: Option<StateKeyReference<'a>>,
}

/// Single-use control capability. Drop does not cancel the installed control.
pub struct RejoinTicket {
    owner: Arc<Inner>,
    uid: u64,
    id: u64,
}
/// A pre-Join refusal retaining the original opaque detached operation.
pub struct RejoinFailure {
    /// Exact local/native error; no automatic retry is performed.
    pub error: Error,
    /// Unconsumed operation for an explicit caller decision.
    pub operation: DetachedOperation,
}
/// Attachment progress, distinct from cryptographic completion.
pub enum RejoinProgress {
    /// Between control calls; another explicit poll may continue attachment.
    Ready,
    /// Native session inspection is pending and retains its allocations.
    Pending,
    /// C_AsyncJoin succeeded. Poll this ticket to observe C_AsyncComplete.
    Attached(OperationTicket),
    /// A final opaque-byte capture was attached. Use poll_state_capture; its
    /// result must be explicitly restored before any cryptographic continuation.
    StateCapture(OperationTicket),
    /// A restoration control was attached. Only poll_state_restore can observe
    /// its completion and issue the resulting cryptographic continuation.
    StateRestore(StateRestoreTicket),
    /// Refused before any Join attempt; the detached operation is returned.
    Refused(RejoinFailure),
}
pub(super) struct RejoinControl {
    detached: DetachedOperation,
    call: Option<asynchronous::JoinedCall>,
    context: record::Context,
    authentication: u64,
    inspection: Option<Box<state_io::Inspection>>,
    _credit: Credit,
}
impl RejoinControl {
    pub(super) fn execution_incomplete(&self) -> bool {
        self.inspection_pending()
            || self
                .call
                .as_ref()
                .is_some_and(|call| call.execution_incomplete())
    }
    pub(super) fn inspection_pending(&self) -> bool {
        self.inspection.as_ref().is_some_and(|io| io.pending())
    }
}
fn bind(
    session: &Session,
    record: &record::DetachedRecord<'_>,
    keys: RejoinKeys<'_>,
    permits: &mut [Option<crate::registry::ReadPermit>],
    candidate: &mut Option<BoundKeys>,
) -> Result<BoundKeys> {
    BoundKeys::from_record_retained(
        session,
        record.descriptor,
        &record.keys,
        &record.messages,
        StateRestoreKeys {
            extension: None,
            encryption: keys.encryption.map(|reference| StateRestoreKey {
                reference,
                encoding: StateKeyEncoding::Supplied,
            }),
            authentication: keys.authentication.map(|reference| StateRestoreKey {
                reference,
                encoding: StateKeyEncoding::Supplied,
            }),
        },
        permits,
        candidate,
    )
}
pub(super) fn check_keys(body: &OperationBody, entry: &SessionEntry) -> Result<()> {
    match body {
        OperationBody::Digest(_) => Ok(()),
        OperationBody::Messages(b) => b.check_rejoin_key(entry),
        OperationBody::NativeMessages(b) => b.check_key(entry),
        OperationBody::AeadMessages(b) => b.check_rejoin_key(entry),
        OperationBody::Dual(b) => b.check_keys(entry),
        OperationBody::Recover(b) => b.check_key(entry),
        OperationBody::Signature(b) => b.check_key(entry),
        OperationBody::Cipher(b) => b.check_key(entry),
        _ => Err(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::RejoinOwnerAdapterAbsent,
            ),
        )),
    }
}
/// All allocations for a new attachment precede final key/session possession.
enum PreparedRejoin {
    Restoration(restoration_transfer::PreparedDestination),
    Capture {
        continuation: reconstruction::DestinationContinuation,
        io: state_io::StateIo,
        owner_credit: Credit,
        diagnostics: super::progress::FailureDiagnostics,
        call: asynchronous::JoinedCall,
    },
    Cryptographic {
        continuation: reconstruction::DestinationContinuation,
        call: asynchronous::JoinedCall,
    },
}
impl PreparedRejoin {
    fn prepare(
        session: &Session,
        input: &DetachedOperation,
        progress: &crate::session::AdmissionProgress,
        extra_bytes: usize,
        keys: RejoinKeys<'_>,
        authentication: u64,
    ) -> Result<(Self, Credit, super::keys::KeyReaders<2>)> {
        if record::decode(input.record.as_slice(), input.limits)?.0 == record::Kind::DetachedRestore
        {
            let (prepared, credit, readers) =
                restoration_transfer::PreparedDestination::prepare_at_epoch(
                    session,
                    input,
                    progress,
                    extra_bytes,
                    keys,
                    authentication,
                )?;
            return Ok((Self::Restoration(prepared), credit, readers));
        }
        let record = record::DetachedRecord::read(input.record.as_slice(), input.limits)?;
        let join = asynchronous::JoinPlan::new(record.function.name(), record.id, record.capacity)?;
        let (recipe, native_capacity, fixed) = if record.capture {
            record
                .context
                .check_destination_binding(&session.inner, &session.snapshot)?;
            let recipe = reconstruction::Recipe::checkpoint(
                record.descriptor,
                &record.keys,
                &record.messages,
                record.validation.as_ref(),
                input.limits,
                session.inner.crypto_options.limits,
            )?;
            record.context.required_session_state()?;
            let capacity = record.capacity.ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::DetachedCaptureCapacityAbsent,
                ),
            ))?;
            (
                recipe,
                Some(capacity),
                reconstruction::resources::total(&[
                    extra_bytes,
                    state_io::StateIo::allocation_bytes(),
                    saved_state::CaptureOwner::allocation_bytes(),
                    super::progress::FailureDiagnostics::allocation_bytes(),
                    crate::symmetric::memory::Budget::observation_bytes(),
                ])?,
            )
        } else {
            (
                reconstruction::Recipe::detached(
                    &record,
                    input.limits,
                    session.inner.crypto_options.limits,
                )?,
                None,
                extra_bytes,
            )
        };
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
            native_capacity,
            Some(join),
            fixed,
            authentication,
        )?;
        let mut metadata = resources.metadata;
        let continuation =
            reconstruction::DestinationContinuation::Prepared(resources.continuation);
        let call = resources.joined.ok_or(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::RejoinOutputStorageAbsent,
            ),
        ))?;
        let prepared = if record.capture {
            let bytes = resources.native.ok_or(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::CaptureNativeStorageAbsent,
                ),
            ))?;
            let io = state_io::StateIo::joined_capture_prepaid(
                &mut metadata,
                record.context.required_session_state()?,
                bytes,
            )?;
            let owner_credit = metadata.split(saved_state::CaptureOwner::allocation_bytes())?;
            let mut diagnostic_credit = metadata.split(
                super::progress::FailureDiagnostics::allocation_bytes()
                    + crate::symmetric::memory::Budget::observation_bytes(),
            )?;
            diagnostic_credit.observation_budget()?;
            let diagnostics =
                super::progress::FailureDiagnostics::from_prepaid(&mut diagnostic_credit)?;
            Self::Capture {
                continuation,
                io,
                owner_credit,
                diagnostics,
                call,
            }
        } else {
            Self::Cryptographic { continuation, call }
        };
        Ok((prepared, metadata, readers))
    }
    fn bind_retained(
        prepared: &mut Option<Self>,
        session: &Session,
        admission: &crate::session::LeaseAdmission<'_, '_>,
        input: &DetachedOperation,
        keys: RejoinKeys<'_>,
        cancel: &mut Option<preparation::Shell>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        bound: &mut Option<BoundKeys>,
        duplicate: &mut Option<BoundKeys>,
        token: &mut Option<(
            super::lease::TokenLease,
            super::preparation::PreparedControl,
        )>,
    ) -> Result<(Operation, record::Context, asynchronous::JoinedCall)> {
        let storage = prepared.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::RejoinPreparationAbsent,
            ),
        ))?;
        if let Self::Restoration(destination) = storage {
            let binding = destination.prepare_binding(
                session, admission, input, keys, cancel, permits, bound, duplicate, token,
            )?;
            let Self::Restoration(destination) =
                prepared.take().expect("checked rejoin preparation")
            else {
                unreachable!("restoration preparation variant unchanged")
            };
            return Ok(destination.finish_binding(
                session,
                binding,
                bound.take().expect("bound restoration keys"),
                token.take().expect("bound restoration shell"),
            ));
        }
        let record = record::DetachedRecord::read(input.record.as_slice(), input.limits)?;
        *bound = Some(bind(session, &record, keys, permits, bound)?);
        *token = Some(preparation::Shell::bind_retained(cancel, admission)?);
        let destination = bound.as_mut().expect("bound rejoin keys");
        match storage {
            Self::Capture { continuation, .. } => {
                record
                    .context
                    .check_destination_binding(&session.inner, &session.snapshot)?;
                continuation.bind(destination)?;
            }
            Self::Cryptographic { continuation, .. } => {
                continuation.bind_detached(destination, &record)?;
            }
            Self::Restoration(_) => unreachable!("restoration bound above"),
        }
        // Everything below transfers existing owners after all refusal points.
        let storage = prepared.take().expect("bound rejoin preparation");
        let (lease, cancel) = token.take().expect("bound rejoin shell");
        match storage {
            Self::Capture {
                continuation,
                io,
                owner_credit,
                diagnostics,
                call,
            } => {
                let mut owner = saved_state::CaptureOwner::from_continuation_prepaid(
                    session,
                    input.provenance,
                    continuation.into_bound(),
                    owner_credit,
                );
                owner.resource_diagnostics = Some(diagnostics);
                let mut next = Operation::new(OperationBody::Control, lease, cancel);
                next.begin_capture(|| (io, owner))
                    .expect("new capture control has an empty state slot");
                Ok((next, record.context, call))
            }
            Self::Cryptographic { continuation, call } => {
                let continuation = continuation.into_bound();
                let next = Operation::new(continuation.body, lease, cancel)
                    .with_validation(continuation.validation);
                Ok((next, record.context, call))
            }
            Self::Restoration(_) => unreachable!("restoration bound above"),
        }
    }
}
impl AdvancedSession {
    /// Native rejoin requires the unsupported native asynchronous mode. Current synchronous
    /// sessions reject it before reconstruction or native attachment. The
    /// retained types and checks below do not enable that mode.
    ///
    /// Prepare attachment to an idle asynchronous destination without native IO.
    /// The opaque operation is consumed only after bounded reconstruction, exact
    /// destination-key checks and installation of all native output owners.
    /// A local preparation refusal returns it unchanged. No archive is imported.
    pub fn start_rejoin(
        &self,
        detached: DetachedOperation,
        keys: RejoinKeys<'_>,
    ) -> std::result::Result<RejoinTicket, RejoinFailure> {
        let mut detached = Some(detached);
        let result = (|| -> Result<RejoinTicket> {
            let check_route = |state: &State| -> Result<()> {
                if self.mode() != AdvancedSessionMode::Asynchronous {
                    return Err(Error::Rejected(crate::RejectionReason::Persistence(
                        crate::PersistenceRejection::AsynchronousRejoinSessionMode,
                    )));
                }
                if self
                    .session
                    .entry
                    .advanced_operation
                    .load(Ordering::Acquire)
                    != 0
                {
                    return Err(Error::Busy(crate::BusyReason::AsynchronousExecution(
                        crate::AsynchronousExecutionBusy::RejoinDestinationActive,
                    )));
                }
                let functions = state.native.asynchronous.ok_or(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::AsynchronousInterfaceUnavailable,
                    ),
                ))?;
                if functions.join.is_none() || functions.complete.is_none() {
                    return Err(Error::Rejected(crate::RejectionReason::AsynchronousExecution(crate::AsynchronousExecutionRejection::AsynchronousRejoinFunctionsUnavailable)));
                }
                Ok(())
            };
            let progress = self.session.advanced_preflight(&check_route)?.retaining(
                detached
                    .as_ref()
                    .unwrap()
                    .retained_bytes(&self.session.inner.symmetric_budget)?,
            )?;
            let authentication = {
                let state = self.session.advanced_access_progress(
                    crate::session::CleanupAdmission::Ordinary,
                    &progress,
                )?;
                check_route(&state)?;
                for key in [keys.encryption, keys.authentication].into_iter().flatten() {
                    self.session.managed_handle(&state, key.managed())?;
                }
                self.session.snapshot.authentication_stamp()
            };
            let input = detached.as_ref().unwrap();
            let fixed = reconstruction::resources::total(&[
                preparation::Shell::allocation_bytes(),
                state_io::StateIo::allocation_bytes(),
                std::mem::size_of::<RejoinControl>(),
                std::mem::size_of::<RejoinTicket>(),
            ])?;
            let (prepared, cancel, inspection, credit, _readers, _metadata, prepared_readers, s) = loop {
                let (prepared, mut metadata, readers) = PreparedRejoin::prepare(
                    &self.session,
                    input,
                    &progress,
                    fixed,
                    keys,
                    authentication,
                )?;
                let cancel = preparation::Shell::from_prepaid(&mut metadata)?;
                let inspection = Box::new(state_io::Inspection::new_prepaid(&mut metadata)?);
                let credit = metadata.split(reconstruction::resources::total(&[
                    std::mem::size_of::<RejoinControl>(),
                    std::mem::size_of::<RejoinTicket>(),
                ])?)?;
                let (s, anchors) = match readers.try_access_with_progress(&self.session, &progress)
                {
                    Ok(access) => access,
                    Err(error @ Error::Busy(_)) => {
                        drop(inspection);
                        drop(prepared);
                        drop(credit);
                        drop(cancel);
                        drop(metadata);
                        readers.wait_after_contention(
                            &self.session,
                            &progress,
                            authentication,
                            error,
                        )?;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                // Carry attribution and any residual credit out with access;
                // neither may be destroyed by leaving this preparation scope.
                break (
                    prepared, cancel, inspection, credit, readers, metadata, anchors, s,
                );
            };
            let mut prepared = Some(prepared);
            let mut cancel = Some(cancel);
            let mut bound = None;
            let mut duplicate = None;
            let mut token = None;
            let mut candidate;
            let mut publication;
            let installed;
            let (mut next, context, call);
            let mut prepared_readers = prepared_readers;
            let s = s;
            check_route(&s)?;
            self.session
                .snapshot
                .check_authentication_unchanged(authentication)?;
            (next, context, call) = PreparedRejoin::bind_retained(
                &mut prepared,
                &self.session,
                &s.lease_admission()?,
                input,
                keys,
                &mut cancel,
                &mut prepared_readers,
                &mut bound,
                &mut duplicate,
                &mut token,
            )?;
            next.provenance = input.provenance;
            if next.transfer.as_ref().is_some() {
                return Err(Error::Busy(crate::BusyReason::AsynchronousExecution(
                    crate::AsynchronousExecutionBusy::OperationTransferActive,
                )));
            }
            candidate = Some(next);
            publication = Some((call, context, inspection, credit));
            let (id, owner) = s.operations.install_with_retained(
                &self.session.entry,
                &mut candidate,
                &mut None,
                |op| {
                    let id = op.id;
                    if let Some(restore) = op.restore_owner_mut() {
                        restore.id = id;
                    }
                    // The unshared shell's empty transfer slot was checked before
                    // admission. No failure remains after consuming the input record.
                    op.begin_rejoin(|| {
                        let (call, context, inspection, credit) =
                            publication.take().expect("prepared rejoin publication");
                        RejoinControl {
                            detached: detached.take().expect("unconsumed rejoin input"),
                            call: Some(call),
                            context,
                            authentication,
                            inspection: Some(inspection),
                            _credit: credit,
                        }
                    })
                    .expect("prepared rejoin transfer slot");
                },
            )?;
            installed = owner;
            let _ = &installed;
            Ok(RejoinTicket {
                owner: self.session.inner.clone(),
                uid: self.session.uid,
                id,
            })
        })();
        match result {
            Ok(ticket) => Ok(ticket),
            Err(error) => Err(RejoinFailure {
                error,
                operation: detached.unwrap(),
            }),
        }
    }
    /// Inspect destination context and attempt C_AsyncJoin exactly once. Join OK
    /// does not publish crypto output or invoke AsyncComplete in this call.
    /// After an installed native Join fails, its control and buffers remain for
    /// explicit session cleanup. A local refusal before installation drops the
    /// unsubmitted control/buffers; the detached operation remains owned by the
    /// session cleanup path. Polling cannot repeat Join or resume the original call.
    pub fn poll_rejoin(&self, ticket: &mut RejoinTicket) -> Result<RejoinProgress> {
        if ticket.id == 0
            || ticket.uid != self.session.uid
            || !Arc::ptr_eq(&ticket.owner, &self.session.inner)
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::ForeignOrConsumedRejoinTicket,
                ),
            ));
        }
        let s = self.session.advanced_access()?;
        let operation = s.operations.get(ticket.uid)?;
        let mut op = operation.lock().map_err(|_| Error::Poisoned)?;
        if op.id != ticket.id {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::StaleRejoinTicket,
                ),
            ));
        }
        let control = op.rejoin().ok_or(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::RejoinAbsent,
            ),
        ))?;
        if control.call.is_none() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::AsynchronousJoinAlreadyAttempted,
                ),
            ));
        }
        let mut remaining = self.pacing.budget();
        let preparation = (|| -> Result<bool> {
            self.session
                .snapshot
                .check_authentication_unchanged(op.rejoin().unwrap().authentication)?;
            if let Some(capture) = op.capture_owner() {
                capture.check_keys(&self.session.entry)?;
            } else if let Some(restore) = op.restore_owner() {
                restore.check_keys(&self.session.entry)?;
            } else {
                check_keys(&op.body, &self.session.entry)?;
            }
            let io = op
                .rejoin_mut()
                .unwrap()
                .inspection
                .as_mut()
                .ok_or(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::RejoinInspectionAbsent,
                    ),
                ))?;
            io.drive(&s, &self.session.entry, true, &mut remaining)?;
            if !io.complete() {
                return Ok(false);
            }
            let context = record::Context::from_snapshot(
                &self.session.inner,
                &self.session.snapshot,
                io.inspected_state()?,
            )?;
            op.rejoin().unwrap().context.check(&context)?;
            Ok(true)
        })();
        match preparation {
            Err(error) => {
                // PENDING and an uncertain native return retain the inspection
                // graph. In particular, GENERAL_ERROR clears pending without
                // proving that the module returned its memory loan. Keep the
                // entire owner installed until explicit termination is proven.
                if op.rejoin().unwrap().inspection_pending() || s.native.is_uncertain() {
                    return Err(error);
                }
                // Remove first, then move the sole record. A poisoned ledger
                // leaves this complete owner intact and recoverable by cleanup.
                s.operations.release_closed(&self.session.entry)?;
                let control = op.take_rejoin().unwrap();
                ticket.id = 0;
                return Ok(RejoinProgress::Refused(RejoinFailure {
                    error,
                    operation: control.detached,
                }));
            }
            Ok(false) => {
                return Ok(if op.rejoin().unwrap().inspection_pending() {
                    RejoinProgress::Pending
                } else {
                    RejoinProgress::Ready
                })
            }
            Ok(true) => {}
        }
        if !spend(&mut remaining) {
            return Ok(RejoinProgress::Ready);
        }
        // Prepare the only restoration capability before Join can have a native
        // effect. The installed owner and ticket identity establish the transfer;
        // no application material-comparison report participates in ownership.
        let restoration = match op.restore_owner() {
            Some(restore) => Some(StateRestoreTicket {
                owner: self.session.inner.clone(),
                uid: self.session.uid,
                id: restore.id,
            }),
            None => None,
        };
        op.rejoin_mut().unwrap().inspection.take();
        let call = op.rejoin_mut().unwrap().call.take().unwrap();
        if let Err(error) = op.attach_join(&s, &self.session.entry, call) {
            // A native attachment failure keeps its installed control for cleanup.
            // A local refusal before installation drops the unsubmitted JoinedCall.
            // The original ticket remains usable for its installed control;
            // dropping this unissued capability does not cancel that control.
            return Err(error);
        }
        // JoinedCall remains in the ledger. The old record is no longer a
        // second capability; only the new operation ticket can observe it.
        op.take_rejoin();
        ticket.id = 0;
        if let Some(restoration) = restoration {
            return Ok(RejoinProgress::StateRestore(restoration));
        }
        let next = OperationTicket {
            owner: self.session.inner.clone(),
            uid: self.session.uid,
            id: op.id,
            validation_report: None,
            state_provenance: op.provenance,
        };
        Ok(if op.capture_owner().is_some() {
            RejoinProgress::StateCapture(next)
        } else {
            RejoinProgress::Attached(next)
        })
    }
}
