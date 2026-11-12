// SPDX-License-Identifier: Apache-2.0
//! Variable source sets share destination admission without partial byte waits.
use super::Reservation;
use crate::managed::mutations::reservation_preparation::{
    DestinationRecipe, DestinationRetirement,
};
use crate::{
    session::{
        activity::{DynamicReadPlan, DynamicReadStorage},
        AdmissionProgress, SessionAccess,
    },
    symmetric::memory::Credit,
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};
use std::sync::Arc;

impl Reservation {
    pub(crate) fn prepare_with_readers_prepaid<'s, 'k, T>(
        session: &'s Session,
        recipes: &[DestinationRecipe<'_>],
        creation_count: usize,
        keys: impl Iterator<Item = &'k NativeObjectRef> + Clone,
        epoch: u64,
        progress: &AdmissionProgress,
        mut prepare: impl FnMut(usize, &dyn Fn() -> Result<bool>) -> Result<Option<(T, Credit)>>,
        mut check: impl FnMut(&SessionAccess<'s>) -> Result<()>,
    ) -> Result<((T, Arc<Self>), SessionAccess<'s>)> {
        let policy = crate::admission_wait::current();
        let session_policy = session.admission();
        let plan = DynamicReadPlan::prepare_at_epoch(session, keys, progress, epoch)?;
        let mut reader_bytes = DynamicReadStorage::requested(plan.count())?;
        loop {
            policy.check_available()?;
            session_policy.check_available()?;
            // Only a failed source pin/permission probe authorizes the outer
            // availability retry. Factory failures retain their own semantics.
            let mut source_contention = false;
            // This outer retirement also covers failure of the source probe
            // after the inner destination driver has returned successfully.
            let retirement = DestinationRetirement::new(session);
            retirement.retire();
            let attempt = Self::prepare_mutation_prepaid(
                session,
                recipes,
                creation_count,
                None,
                [],
                false,
                epoch,
                progress,
                |destination_bytes, current| loop {
                    plan.check(session)?;
                    let overhead =
                        destination_bytes
                            .checked_add(reader_bytes)
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                                crate::ObjectMutationRejection::DynamicReaderAggregateAccounting,
                            )))?;
                    let Some((candidate, mut credit)) = prepare(overhead, current)? else {
                        return Ok(None);
                    };
                    let storage = DynamicReadStorage::allocate(plan.count())?;
                    let actual = storage.allocated_bytes()?;
                    if actual > reader_bytes {
                        drop(storage);
                        drop(candidate);
                        drop(credit);
                        reader_bytes = actual;
                        continue;
                    }
                    let mut readers = storage.bind(&mut credit)?;
                    if let Err(error) = policy
                        .try_once(|| session_policy.try_once(|| plan.pin(session, &mut readers)))
                    {
                        source_contention = matches!(&error, Error::Busy(_));
                        return Err(error);
                    }
                    // Source pins are resident metadata, not read permissions.
                    // The destination transaction still probes all guards once.
                    return Ok(Some(((candidate, readers), credit)));
                },
                |access| {
                    plan.check(session)?;
                    check(access)
                },
            );
            let attempt = attempt.and_then(|(((candidate, readers), reservation), access)| {
                let access = policy.try_once(|| {
                    session_policy.try_once(|| plan.try_access(session, access, readers))
                });
                match access {
                    Ok(access) => Ok(((candidate, reservation), access)),
                    Err(error) => {
                        drop((candidate, reservation));
                        source_contention = matches!(&error, Error::Busy(_));
                        Err(error)
                    }
                }
            });
            match attempt {
                Ok(result) => return Ok(result),
                Err(error @ Error::Busy(_)) => {
                    if !source_contention
                        || crate::notify::in_callback()
                        || (matches!(policy, ResourceAdmission::Immediate)
                            && matches!(session_policy, crate::SessionAdmission::Immediate))
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            // Every failed factory/probe has dropped its private candidate,
            // attribution vector and partial permissions before this wait.
            retirement.retire();
            plan.wait_available(session, &policy, progress)?;
        }
    }
}
