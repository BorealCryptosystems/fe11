// SPDX-License-Identifier: Apache-2.0
//! Keep the original writers from reference observation through destruction.
use super::*;
use crate::managed::search::SearchWithdrawal;
use crate::{
    reference_controls::resident::{
        self as reference,
        preparation::{self, Initial},
        ReferenceOwner,
    },
    session::{
        observation_protection::{MutationProtection, ObservationProtection},
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::Credit,
};

enum Phase {
    Observation {
        read: Box<ReferenceOwner>,
        targets: RevocationTargets,
    },
    Dispatch,
    Stopped,
}
pub(crate) struct DestructionOwner {
    phase: Phase,
    effect: DestroyProgress,
    protection: Arc<MutationProtection>,
    _credit: Credit,
}
impl DestructionOwner {
    pub(crate) fn pending(&self) -> bool {
        self.effect.pending()
            || matches!(&self.phase, Phase::Observation { read, .. } if read.pending())
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Observation { read, .. } if read.search_claimed())
    }
    fn read(&mut self) -> Result<&mut ReferenceOwner> {
        match &mut self.phase {
            Phase::Observation { read, .. } => Ok(read),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DestructionObservationAbsent,
            ))),
        }
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Observation { read, .. } => read.finish_search(session, access),
            _ => Ok(()),
        }
    }
    fn destroy(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        object: &ManagedObjectRef,
        diagnostic: &mut DestructionDiagnostic,
    ) -> Result<crate::ObjectReferenceReport> {
        let Phase::Observation { read, targets } =
            std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DestructionAlreadyDispatched,
            )));
        };
        // The parent keeps the same exclusive proof after the child completes.
        // Do not release it between evaluation and the destructive native call.
        let report =
            object
                .identity
                .access
                .result(session, access, read.result(session, access))?;
        session.managed_handle(access, object)?;
        self.phase = Phase::Dispatch;
        let session_handle = session.entry(access)?.handle;
        let completed = session.destroy_resource_with(
            access,
            session_handle,
            object.identity.resource(),
            targets,
            diagnostic.take()?,
            &mut self.effect,
            |resource| {
                self.protection
                    .forget_object(session, resource, &object.identity.activity)
            },
        )?;
        // Success already revoked aliases. Preserve the original visibility
        // check and OperationCompleted diagnostic without revalidating revocation.
        completed.finish(object.identity.access.result(session, access, Ok(report)))
    }
}

pub(super) fn destroy(
    session: &Session,
    object: &ManagedObjectRef,
    selection: crate::ObjectReferencePlan,
    content: crate::ContentObservation,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
) -> Result<crate::ObjectReferenceReport> {
    let recipe = mutations::identity_recipe(session, &object.identity)?;
    let authentication = Some(epoch);
    let policy = crate::admission_wait::current();
    let selected_content = reference::content_plan(&content);
    if !Initial::requires_preparation(&selection, object, selected_content)? {
        // No observation can discover a dynamic native allocation. Keep this
        // direct path free of a synthetic resident byte/registry admission.
        let (mut diagnostic, targets, reservation, access) =
            prepare_destruction(session, &[recipe], object, progress, epoch, |access| {
                session.managed_handle(access, object).map(|_| ())
            })?;
        let report = crate::ObjectReferenceReport::observe_local(
            selection, &access, session, object, content,
        )?;
        session.managed_handle(&access, object)?;
        let completed = session.destroy_resource_reserved(
            &access,
            session.entry(&access)?.handle,
            object.identity.resource(),
            &object.identity.activity,
            &reservation,
            targets,
            diagnostic.take()?,
        )?;
        return completed.finish(object.identity.access.result(session, &access, Ok(report)));
    }

    let fixed = Prepared::allocation_bytes()
        .checked_add(std::mem::size_of::<DestructionOwner>())
        .and_then(|n| n.checked_add(MutationProtection::allocation_bytes()))
        .and_then(|n| n.checked_add(DestructionDiagnostic::allocation_bytes()))
        .and_then(|n| n.checked_add(crate::error::PreparedCleanupDiagnostic::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::DestructionStorageSize,
        )))?;
    let mut required = Initial::requested(&selection, object)?
        .checked_add(fixed)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::DestructionStorageSize,
        )))?;
    let (
        ((mut search_cleanup, mut diagnostic, initial, registry, mut credit, targets), reservation),
        first_access,
    ) = loop {
        let retirement = mutations::DestinationRetirement::new(session);
        retirement.retire();
        let (
            ((search_cleanup, diagnostic, initial, registry, credit, mut revocation), reservation),
            first_access,
        ) = Reservation::prepare_mutation_prepaid(
            session,
            &[recipe],
            0,
            None,
            [(Some(&**object), crate::session::activity::AccessMode::Write)],
            false,
            epoch,
            progress,
            |overhead, current| loop {
                context(session, authentication, epoch)?;
                let shape = RevocationShape::discover(session, object.identity.resource(), epoch)?;
                let revocation_bytes = shape.allocation_bytes()?;
                let admitted = required
                    .checked_add(overhead)
                    .and_then(|n| n.checked_add(revocation_bytes))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    )))?;
                let Some(mut credit) = crate::advanced::reserve_preparation_while(
                    session,
                    admitted,
                    progress,
                    || {
                        context(session, authentication, epoch)?;
                        current()
                    },
                )?
                else {
                    return Ok(None);
                };
                let revocation = shape.allocate()?;
                let revocation_actual = revocation.allocated_bytes()?;
                let initial = Initial::allocate(&selection, object)?;
                let actual = initial
                    .allocated_bytes()?
                    .checked_add(fixed)
                    .and_then(|n| n.checked_add(revocation_actual))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestructionStorageSize,
                    )))?;
                let actual = actual.checked_add(overhead).ok_or(Error::Rejected(
                    crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                    ),
                ))?;
                if actual > admitted {
                    drop(revocation);
                    drop(initial);
                    drop(credit);
                    required = actual
                        .checked_sub(overhead)
                        .and_then(|n| n.checked_sub(revocation_bytes))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                        )))?;
                    continue;
                }
                credit.release(admitted - actual);
                credit.observation_budget()?;
                let search_cleanup = crate::error::PreparedCleanupDiagnostic::prepare(&mut credit)?;
                let diagnostic = DestructionDiagnostic::prepare(&mut credit)?;
                let revocation = revocation.bind(&mut credit)?;
                let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
                let coordination = credit.split(overhead)?;
                return Ok(Some((
                    (
                        search_cleanup,
                        diagnostic,
                        initial,
                        registry,
                        credit,
                        revocation,
                    ),
                    coordination,
                )));
            },
            |access| {
                context(session, authentication, epoch)?;
                session.managed_handle(access, object).map(|_| ())
            },
        )?;
        let targets = match revocation.bind(&first_access) {
            Ok(Some(targets)) => targets,
            Ok(None) => {
                // Return possession first, then destroy the still-unbound
                // storage before releasing the credit that covers it.
                drop(first_access);
                drop((initial, registry));
                drop((reservation, credit));
                continue;
            }
            Err(error) => {
                drop(first_access);
                drop((initial, registry));
                drop((reservation, credit));
                return Err(error);
            }
        };
        break (
            (
                (
                    search_cleanup,
                    diagnostic,
                    initial,
                    registry,
                    credit,
                    targets,
                ),
                reservation,
            ),
            first_access,
        );
    };
    let protection = MutationProtection::take(session, &first_access, &mut credit)?;
    let read = initial.bind(
        session,
        &first_access,
        object,
        selection.clone(),
        content,
        epoch,
        ObservationProtection::mutation(&protection),
        &mut credit,
    )?;
    let owner = DestructionOwner {
        phase: Phase::Observation {
            read: Box::new(read),
            targets,
        },
        effect: DestroyProgress::BeforeDispatch,
        protection,
        _credit: credit.split(std::mem::size_of::<DestructionOwner>())?,
    };
    let coordination = session
        .entry
        .recovery
        .observations
        .publish(registry.bind_destruction(owner))?;
    // The resident proof owns a counted durable reservation and every writer.
    // The original Arc<Reservation> must not survive in a resource waiter.
    drop(reservation);
    drop(credit);
    let waiter = Waiting::new(session, coordination, authentication, epoch);
    let search_open = std::cell::Cell::new(false);
    let _withdrawal = SearchWithdrawal::new(session, &search_open);
    let mut access = Some(first_access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::DestructionPossessionAbsent,
                )))?;
        let handle = session.managed_handle(&owned_access, object)?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DestructionOwnerAbsent,
            )))?
            .destruction_mut()?;
        search_open.set(owner.search_claimed());
        let advanced = owner.read()?.advance(session, &owned_access, handle);
        search_open.set(owner.search_claimed() && owner.pending());
        advanced?;
        if owner.read()?.complete() {
            // Remain registered during dispatch and unwind. A returned failure
            // is not evidence that an in-flight native operation can be freed.
            let result = owner.destroy(session, &owned_access, object, &mut diagnostic);
            if !owner.pending() {
                payload.take();
            }
            return result;
        }
        let need = owner.read()?.need()?.ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DestructionResourceNeedAbsent,
            ),
        ))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            let candidate = preparation::prepare(
                need,
                &selection,
                selected_content,
                session,
                &policy,
                &waiter,
            )?;
            let resumed = match session.try_operation_access_progress(false, &progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(session.access_progress(&progress)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            session.managed_handle(&resumed, object)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::DestructionOwnerAbsent,
                )))?
                .destruction_mut()?
                .read()?
                .attach(need, candidate)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    let result = crate::managed::search::finish_failed_search(
        session,
        &waiter.coordination,
        &search_open,
        result,
        &mut search_cleanup,
        None,
        || session.try_advanced_access_progress(&progress),
        |owner, access| {
            let owner = owner.destruction_mut()?;
            let cleanup = owner.finish_search(session, access);
            search_open.set(owner.search_claimed() && owner.pending());
            cleanup
        },
    );
    result
}
