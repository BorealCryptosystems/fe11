// SPDX-License-Identifier: Apache-2.0
//! Destination retention participates in the complete private byte admission.
use super::{PreparedRetention, Reservation};
use crate::{
    session::{
        activity::{AccessMode, PermissionStorage, RolePlan},
        AdmissionProgress, SessionAccess,
    },
    symmetric::memory::Credit,
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};
use std::sync::Arc;

impl Reservation {
    pub(crate) fn prepare_with_roles_prepaid<'a, T, const N: usize>(
        self: &Arc<Self>,
        session: &'a Session,
        keys: [(Option<&crate::ManagedObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &AdmissionProgress,
        prepare: impl FnMut(usize) -> Result<(T, Credit)>,
        check: impl FnMut(&SessionAccess<'a>) -> Result<()>,
    ) -> Result<(T, SessionAccess<'a>)> {
        self.prepare_with_native_roles_prepaid(
            session,
            keys.map(|(key, mode)| (key.map(|key| &**key), mode)),
            contextual,
            progress,
            prepare,
            check,
        )
    }

    /// The factory prepays its own candidate and the supplied coordination
    /// overhead in one reservation. Its returned credit owns that overhead.
    /// No callback may call C or consume an observed response during preparation.
    pub(crate) fn prepare_with_native_roles_prepaid<'a, T, const N: usize>(
        self: &Arc<Self>,
        session: &'a Session,
        keys: [(Option<&NativeObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &AdmissionProgress,
        mut prepare: impl FnMut(usize) -> Result<(T, Credit)>,
        mut check: impl FnMut(&SessionAccess<'a>) -> Result<()>,
    ) -> Result<(T, SessionAccess<'a>)> {
        let policy = crate::admission_wait::current();
        let session_policy = session.admission();
        let roles = RolePlan::prepare(session, keys, contextual, progress)?;
        let authentication = roles.authentication();
        self.check_operation_session(session)?;
        let mut overhead = self
            .retention_bytes()?
            .checked_add(PermissionStorage::requested(N)?)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DestinationAggregateAccounting,
            )))?;
        loop {
            policy.check_available()?;
            session_policy.check_available()?;
            let (candidate, mut credit) = prepare(overhead)?;
            let retention = self.allocate_retention()?;
            let permissions = PermissionStorage::allocate(N)?;
            let actual = retention
                .allocated_bytes()?
                .checked_add(permissions.allocated_bytes()?)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::DestinationAggregateAccounting,
                )))?;
            if actual > overhead {
                drop(permissions);
                drop(retention);
                drop(candidate);
                drop(credit);
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
                                    crate::ObjectMutationRejection::DestinationProbeAlreadyConsumed,
                                )))?;
                            self.try_prepaid_access(
                                session,
                                retention,
                                contextual,
                                authentication,
                                progress,
                                &mut check,
                            )
                        },
                    )
                })
            });
            match attempt {
                Ok(access) => return Ok((candidate, access)),
                Err(error @ Error::Busy(_)) => {
                    drop(candidate);
                    drop(credit);
                    if matches!(policy, ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }

            // Availability checks grant no authority. They retain no private
            // vectors and do not hold one destination while waiting for another.
            // The subsequent nonwaiting probe must still acquire every guard.
            {
                let access = if contextual {
                    session.context_operation_access_progress(progress)?
                } else {
                    session.access_progress(progress)?
                };
                session
                    .snapshot
                    .check_authentication_unchanged(authentication)?;
                self.check_operation_session(session)?;
                check(&access)?;
            }
            for activity in &self.activities {
                activity.wait_operation_writer_checked(&policy, || {
                    crate::advanced::preparation_context(session)?;
                    session
                        .snapshot
                        .observe_authentication_unchanged(authentication)
                })?;
            }
            roles.wait_available(session, &policy, || {
                if contextual {
                    session.context_operation_access_progress(progress)
                } else {
                    session.access_progress(progress)
                }
            })?;
        }
    }

    pub(super) fn try_prepaid_access<'a>(
        self: &Arc<Self>,
        session: &'a Session,
        mut retention: PreparedRetention,
        contextual: bool,
        authentication: u64,
        progress: &AdmissionProgress,
        check: &mut impl FnMut(&SessionAccess<'a>) -> Result<()>,
    ) -> Result<SessionAccess<'a>> {
        let access = session.try_operation_access_progress(contextual, progress)?;
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        check(&access)?;
        if self
            .try_operation_permits_retained(session, &mut retention.writers)?
            .is_some()
        {
            // Session possession leaves before writer/vector destruction.
            drop(access);
            return Err(Error::Busy(crate::BusyReason::ObjectMutation(
                crate::ObjectMutationBusy::ObjectActivity,
            )));
        }
        access.retain_creation_activity(self.clone(), retention)
    }
}
