// SPDX-License-Identifier: Apache-2.0
//! Root-owned possession changes; no borrowed SessionAccess is suspended.
use super::*;
use crate::{
    session::{
        recovery::observations::{context, Prepared, Waiting},
        AdmissionProgress,
    },
    ManagedObjectRef, ObjectRef, Session,
};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum Source<'a> {
    Managed(&'a ManagedObjectRef),
    Object(&'a ObjectRef),
}
impl Source<'_> {
    fn activity(self) -> Arc<crate::registry::Activity> {
        match self {
            Self::Managed(source) => source.identity.activity.clone(),
            Self::Object(source) => source.identity.activity.clone(),
        }
    }
    fn handle(self, session: &Session, access: &SessionAccess<'_>) -> Result<CK_OBJECT_HANDLE> {
        match self {
            Self::Managed(source) => session.managed_handle(access, source),
            Self::Object(source) => session.object(access, source, None),
        }
    }
}

pub(crate) fn observe(
    session: &Session,
    source: Source<'_>,
    fields: &[crate::Attribute],
    plan: AttributeReadPlan,
) -> Result<Vec<AttributeValue>> {
    observe_recipe(
        session,
        source,
        Recipe::Public { fields, plan },
        |output| match output {
            Output::Public(values) => Ok(values.into_values()),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        },
    )
}
pub(crate) fn observe_controls(
    session: &Session,
    object: &ManagedObjectRef,
    admission: &crate::ObjectAdmission,
) -> Result<crate::ObjectObservationReport> {
    observe_recipe(
        session,
        Source::Managed(object),
        Recipe::Controls(admission),
        |output| match output {
            Output::Observed(values) => admission.observe_owned(values),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        },
    )
}
pub(crate) fn observe_history_with<T>(
    session: &Session,
    object: &ManagedObjectRef,
    plan: crate::HistoryObservationPlan,
    finish: impl FnOnce(crate::BaseProtection) -> Result<T>,
) -> Result<T> {
    observe_recipe(
        session,
        Source::Managed(object),
        Recipe::History(plan),
        |output| match output {
            Output::Observed(values) => {
                finish(crate::crypto::derivation::history::snapshot(plan, &values))
            }
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        },
    )
}

fn observe_recipe<T>(
    session: &Session,
    source: Source<'_>,
    recipe: Recipe<'_>,
    finish: impl FnOnce(Output) -> Result<T>,
) -> Result<T> {
    recipe.validate()?;
    let epoch = session.snapshot.authentication_stamp();
    // Only changes during this observation affect its coherence.
    let authentication = Some(epoch);
    let progress = AdmissionProgress::default();
    let policy = crate::admission_wait::current();
    let session_policy = session.admission();
    if recipe.len() == 0 {
        let acquire = || {
            let access = session.access()?;
            source.handle(session, &access)?;
            Ok(access)
        };
        drop(acquire()?);
        let activity = source.activity();
        let readers = crate::session::activity::Readers::prepare(session, [Some(&activity)])?;
        let (access, mut permits) = readers.acquire(session, acquire)?;
        access.retain_prepared_reader(permits[0].take().expect("prepared object reader"))?;
        let output = match recipe.output() {
            OutputKind::Fingerprint => {
                return Err(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::FingerprintRequiresBorrowedResult,
                    ),
                ))
            }
            OutputKind::Precise => {
                return Err(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::EmptyPreciseObservation,
                    ),
                ))
            }
            OutputKind::Public => Output::Public(AttributeSnapshot::default()),
            OutputKind::Required => Output::Required(ObservedAttributes::empty().require_all()?),
            OutputKind::Observed => Output::Observed(ObservedAttributes::empty()),
        };
        return session.metadata_result(&access, authentication, finish(output));
    }
    let activity = source.activity();
    let reader = activity.prepare_reader_checked(session.uid, &policy, || {
        context(session, authentication, epoch)
    })?;
    let registry_bytes = Prepared::allocation_bytes();
    let mut required = preparation::Storage::requested(recipe)?
        .checked_add(registry_bytes)
        .ok_or(Error::Rejected(
            crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::AttributeObservationStorageSize,
            ),
        ))?;
    let (coordination, access) = loop {
        context(session, authentication, epoch)?;
        policy.check_available()?;
        session_policy.check_available()?;
        let mut credit =
            crate::advanced::reserve_preparation_with_progress(session, required, &progress)?;
        let storage = preparation::Storage::allocate(recipe)?;
        let actual = storage
            .allocated_bytes()?
            .checked_add(registry_bytes)
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationStorageSize,
                ),
            ))?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let registry = Prepared::allocate(&session.inner.symmetric_budget, &mut credit)?;
        let acquired = (|| {
            // This slot predates access: refusal releases the guards first.
            let mut permit = None;
            let access = session.try_operation_access_progress(false, &progress)?;
            reader.acquire_into(&policy, &mut permit)?;
            // The read permit excludes a mutator between this identity check
            // and native dispatch, including writers from another session.
            let handle = source.handle(session, &access)?;
            Ok((access, handle, permit.take().expect("reader acquired")))
        })();
        match acquired {
            Ok((access, handle, permit)) => {
                let owner = storage.bind(&mut credit, recipe, handle, authentication, permit)?;
                let coordination = session
                    .entry
                    .recovery
                    .observations
                    .publish(registry.bind_legacy(owner))?;
                break (coordination, access);
            }
            Err(Error::Busy(_)) => {
                drop(storage);
                drop(registry);
                drop(credit);
                drop(session.access_progress(&progress)?);
                reader
                    .wait_available_checked(&policy, || context(session, authentication, epoch))?;
            }
            Err(error) => return Err(error),
        }
    };
    let waiter = Waiting::new(session, coordination, authentication, epoch);
    let mut access = Some(access);
    let result = (|| loop {
        waiter.check()?;
        let owned_access =
            access
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributePossessionAbsent,
                )))?;
        let handle = source.handle(session, &owned_access)?;
        let slot = session
            .entry
            .recovery
            .observations
            .get(&waiter.coordination)?;
        let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
        let owner = payload
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeOwnerAbsent,
            )))?
            .legacy_mut()?;
        owner.advance(session, &owned_access, handle)?;
        if owner.complete() {
            let owner = payload
                .take()
                .expect("completed observation")
                .into_legacy()?;
            let result = owner.result(session, &owned_access, finish);
            drop(payload);
            drop(slot);
            drop(owned_access);
            return result;
        }
        let need = owner
            .need()
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeValueNeedAbsent,
            )))?;
        drop(payload);
        drop(slot);
        drop(owned_access);
        loop {
            // Only this original call can attach to the private continuation.
            // A close may reclaim it while the waiter holds no owner reference.
            let value =
                preparation::prepare_value(need, waiter.budget(), &policy, || waiter.check())?;
            waiter.check()?;
            let resumed = match session.try_operation_access_progress(false, &progress) {
                Ok(access) => access,
                Err(Error::Busy(_)) => {
                    drop(value);
                    drop(session.access_progress(&progress)?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            waiter.check()?;
            source.handle(session, &resumed)?;
            let slot = session
                .entry
                .recovery
                .observations
                .get(&waiter.coordination)?;
            let mut payload = slot.owner.lock().map_err(|_| Error::Poisoned)?;
            payload
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributeOwnerAbsent,
                )))?
                .legacy_mut()?
                .attach(need, value)?;
            drop(payload);
            drop(slot);
            access = Some(resumed);
            break;
        }
    })();
    drop(access);
    result
}
