// SPDX-License-Identifier: Apache-2.0
//! Generation and mutations own destinations and native preparation together.
use super::{storage::retention_requested, Reservation};
use crate::{
    managed::mutations::reservation_preparation::{self, DestinationOperands, DestinationRecipe},
    session::{
        activity::{AccessMode, PermissionStorage, RolePlan},
        AdmissionProgress, SessionAccess,
    },
    symmetric::memory::Credit,
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};
use std::sync::Arc;

impl Reservation {
    /// The factory admits its native payload, reference participants and the
    /// supplied destination/possession overhead as one byte group. Only borrowed
    /// destination recipes survive retries. No C call is allowed in the factory.
    pub(crate) fn prepare_generation_prepaid<'a, T>(
        session: &'a Session,
        recipes: &[impl DestinationOperands],
        epoch: u64,
        progress: &AdmissionProgress,
        prepare: impl FnMut(usize, &dyn Fn() -> Result<bool>) -> Result<Option<(T, Credit)>>,
        check: impl FnMut(&SessionAccess<'a>) -> Result<()>,
    ) -> Result<((T, Arc<Self>), SessionAccess<'a>)> {
        crate::session::recovery::observations::context(session, Some(epoch), epoch)?;
        let roles = RolePlan::for_generation(session, epoch, progress)?;
        Self::prepare_source_plan_prepaid(
            session,
            recipes,
            recipes.len(),
            None,
            roles,
            false,
            epoch,
            progress,
            prepare,
            check,
        )
    }

    /// Creation capacity and source-role count are independent of destination
    /// count (for example Copy, SetAttributeValue and TLS auxiliary outputs).
    /// An explicit created destination selects Copy's output; None selects
    /// all reserved destinations. Zero creations stage no ticket.
    /// The factory owns every publication permit as part of its candidate.
    pub(crate) fn prepare_mutation_prepaid<'a, T, const N: usize>(
        session: &'a Session,
        recipes: &[DestinationRecipe<'_>],
        creation_count: usize,
        created_destination: Option<DestinationRecipe<'_>>,
        keys: [(Option<&NativeObjectRef>, AccessMode); N],
        contextual: bool,
        epoch: u64,
        progress: &AdmissionProgress,
        prepare: impl FnMut(usize, &dyn Fn() -> Result<bool>) -> Result<Option<(T, Credit)>>,
        check: impl FnMut(&SessionAccess<'a>) -> Result<()>,
    ) -> Result<((T, Arc<Self>), SessionAccess<'a>)> {
        crate::session::recovery::observations::context(session, Some(epoch), epoch)?;
        let roles = RolePlan::prepare_at_epoch(session, keys, contextual, progress, epoch)?;
        Self::prepare_source_plan_prepaid(
            session,
            recipes,
            creation_count,
            created_destination,
            roles,
            contextual,
            epoch,
            progress,
            prepare,
            check,
        )
    }

    fn prepare_source_plan_prepaid<'a, T, const N: usize>(
        session: &'a Session,
        recipes: &[impl DestinationOperands],
        creation_count: usize,
        created_destination: Option<DestinationRecipe<'_>>,
        roles: RolePlan<'_, N>,
        contextual: bool,
        epoch: u64,
        progress: &AdmissionProgress,
        mut prepare: impl FnMut(usize, &dyn Fn() -> Result<bool>) -> Result<Option<(T, Credit)>>,
        mut check: impl FnMut(&SessionAccess<'a>) -> Result<()>,
    ) -> Result<((T, Arc<Self>), SessionAccess<'a>)> {
        let policy = crate::admission_wait::current();
        let session_policy = session.admission();
        let before =
            || crate::session::recovery::observations::context(session, Some(epoch), epoch);
        before()?;
        let mut overhead = retention_requested(recipes.len())?
            .checked_add(PermissionStorage::requested(N)?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::GenerationCoordinationAccounting,
            )))?;

        loop {
            policy.check_available()?;
            session_policy.check_available()?;
            before()?;
            // This scope outlives every private owner in the iteration, including
            // errors after destination publication. The budget is shared, so
            // clear all dead destination entries before byte admission.
            let retirement = reservation_preparation::DestinationRetirement::new(session);
            retirement.retire();
            let (mut reservation, (candidate, mut credit)) =
                reservation_preparation::prepare_grouped(
                    session,
                    recipes,
                    creation_count,
                    &before,
                    || retirement.retire(),
                    |destination_bytes, current| {
                        let combined =
                            destination_bytes
                                .checked_add(overhead)
                                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                                    crate::ObjectMutationRejection::GenerationDestinationAccounting,
                                )))?;
                        // Query the current map on every wait check, including
                        // activities inserted or retired after initial planning.
                        // False returns through the factory without private owners;
                        // prepare_grouped then retires dead keys outside Wake.
                        let valid = || Ok(current()? && retirement.current()?);
                        let Some((candidate, mut credit)) = prepare(combined, &valid)? else {
                            return Ok(None);
                        };
                        let destination = credit.split(destination_bytes)?;
                        Ok(Some(((candidate, credit), destination)))
                    },
                )?;
            if creation_count != 0 {
                before()?;
                reservation.prepare_creation_before_access(session, created_destination)?;
                before()?;
            }
            let reservation = Arc::new(reservation);
            let retention = reservation.allocate_retention()?;
            let permissions = PermissionStorage::allocate(N)?;
            let actual = retention
                .allocated_bytes()?
                .checked_add(permissions.allocated_bytes()?)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                    crate::ObjectMutationRejection::GenerationCoordinationAccounting,
                )))?;
            if actual > overhead {
                // The allocator rounded a possession vector. Discard destination
                // bookkeeping too before acquiring the quota/bytes again.
                drop((permissions, retention, candidate, reservation, credit));
                overhead = actual;
                continue;
            }
            let retention = retention.bind(&mut credit)?;
            let attempt = policy.try_once(|| {
                session_policy.try_once(|| {
                    let mut retention = Some(retention);
                    roles.access_prepaid(
                        session,
                        &ResourceAdmission::Immediate,
                        permissions,
                        &mut credit,
                        || {
                            let retention =
                                retention
                                    .take()
                                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                                    crate::ObjectMutationRejection::GenerationProbeAlreadyConsumed,
                                )))?;
                            reservation.try_prepaid_access(
                                session, retention, contextual, epoch, progress, &mut check,
                            )
                        },
                    )
                })
            });
            match attempt {
                Ok(access) => return Ok(((candidate, reservation), access)),
                Err(error @ Error::Busy(_)) => {
                    // The failed probe has released all possession. Release the
                    // complete private candidate, including its destination, so
                    // a quota holder cannot wait for our retained byte credit.
                    drop((candidate, reservation, credit));
                    retirement.retire();
                    if matches!(policy, ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }

            // Availability is only a hint. These helpers retain no private
            // candidate; the next iteration rechecks and acquires everything.
            roles.wait_available_in_context(session, &policy, || {
                before()?;
                let access = if contextual {
                    session.context_operation_access_progress_at_epoch(progress, epoch)?
                } else {
                    session.access_progress_at_epoch(progress, epoch)?
                };
                before()?;
                check(&access)?;
                Ok(access)
            })?;
            reservation_preparation::wait_available(session, recipes, &policy, &before)?;
        }
    }
}
