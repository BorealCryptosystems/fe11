// SPDX-License-Identifier: Apache-2.0
//! Whole-candidate disposal before pre-dispatch possession waits.
use super::{AccessMode, PreparedRoles};
use crate::{
    session::{AdmissionProgress, SessionAccess},
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};

#[derive(Clone, Copy)]
pub(crate) enum PossessionAttempt {
    Admitted,
    Nonwaiting,
}

/// The resident factory holds identity/coordination only. The candidate factory
/// may copy caller inputs but must neither call C nor consume observed output.
/// The grant callback acquires local possession only, using the explicit mode.
/// No callback may dispatch native work, even if its inputs appear unchanged.
fn prepare_possession<'a, R, T, const N: usize>(
    session: &'a Session,
    keys: [(Option<&NativeObjectRef>, AccessMode); N],
    contextual: bool,
    progress: &AdmissionProgress,
    mut resident: impl FnMut() -> Result<R>,
    mut prepare: impl FnMut() -> Result<T>,
    mut grant: impl FnMut(&mut Option<R>, PossessionAttempt) -> Result<SessionAccess<'a>>,
) -> Result<(T, SessionAccess<'a>)> {
    let policy = crate::admission_wait::current();
    let session_policy = session.admission();
    let authentication = session.snapshot.authentication_stamp();
    loop {
        policy.check_available()?;
        session_policy.check_available()?;
        let retained = resident()?;
        let roles = PreparedRoles::prepare(session, keys, contextual, progress)?;
        let candidate = prepare()?;
        let mut retained = Some(retained);
        let attempt = policy.try_once(|| {
            session_policy.try_once(|| {
                roles.access(session, &ResourceAdmission::Immediate, || {
                    let access = grant(&mut retained, PossessionAttempt::Nonwaiting)?;
                    session
                        .snapshot
                        .check_authentication_unchanged(authentication)?;
                    Ok(access)
                })
            })
        });
        match attempt {
            Ok(access) => return Ok((candidate, access)),
            Err(error @ Error::Busy(_)) => {
                // Every partial guard/permission has already left the failed
                // attempt. Free the copied graph before waiting on availability.
                drop(candidate);
                drop(retained);
                if matches!(policy, ResourceAdmission::Immediate)
                    && matches!(session_policy, ResourceAdmission::Immediate)
                {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
        let mut retained = Some(resident()?);
        let roles = PreparedRoles::prepare(session, keys, contextual, progress)?;
        drop(roles.access(session, &policy, || {
            let access = grant(&mut retained, PossessionAttempt::Admitted)?;
            session
                .snapshot
                .check_authentication_unchanged(authentication)?;
            Ok(access)
        })?);
        // Availability is not ownership. Rebuild outside guards and acquire
        // again; no new reader/writer permit is retained while copying.
    }
}

impl Session {
    pub(crate) fn prepare_with_roles<'a, T, const N: usize>(
        &'a self,
        keys: [(Option<&crate::ManagedObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &AdmissionProgress,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, SessionAccess<'a>)> {
        self.prepare_with_native_roles(
            keys.map(|(key, mode)| (key.map(|key| &**key), mode)),
            contextual,
            progress,
            prepare,
        )
    }

    /// Prepare an operation with managed sources but no destination writer.
    /// This is the same transaction used by destination-bearing mutations.
    pub(crate) fn prepare_with_native_roles<'a, T, const N: usize>(
        &'a self,
        keys: [(Option<&NativeObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &AdmissionProgress,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(T, SessionAccess<'a>)> {
        prepare_possession(
            self,
            keys,
            contextual,
            progress,
            || Ok(()),
            prepare,
            |_, attempt| match attempt {
                PossessionAttempt::Nonwaiting => {
                    self.try_operation_access_progress(contextual, progress)
                }
                PossessionAttempt::Admitted if contextual => {
                    self.context_operation_access_progress(progress)
                }
                PossessionAttempt::Admitted => self.access_progress(progress),
            },
        )
    }
}
