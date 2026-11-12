// SPDX-License-Identifier: Apache-2.0
//! One admission for private candidate bytes and their permission storage.
use super::{roles::PermissionStorage, roles::RolePlan, AccessMode};
use crate::{
    session::{AdmissionProgress, SessionAccess},
    symmetric::memory::Credit,
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};

impl Session {
    /// The typed reference view uses the same native identity and fixed epoch.
    pub(crate) fn prepare_with_roles_prepaid_at_epoch<'a, T, const N: usize>(
        &'a self,
        keys: [(Option<&crate::ManagedObjectRef>, AccessMode); N],
        contextual: bool,
        epoch: u64,
        progress: &AdmissionProgress,
        prepare: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<(T, SessionAccess<'a>)> {
        self.prepare_with_native_roles_prepaid_at_epoch(
            keys.map(|(key, mode)| (key.map(|key| &**key), mode)),
            contextual,
            epoch,
            progress,
            prepare,
        )
    }

    /// Keep the initiating context through identity preparation and every local
    /// possession wait. The factory must also check this epoch in its byte wait;
    /// it owns the complete payload and must not capture a separately held quota.
    pub(crate) fn prepare_with_native_roles_prepaid_at_epoch<'a, T, const N: usize>(
        &'a self,
        keys: [(Option<&NativeObjectRef>, AccessMode); N],
        contextual: bool,
        epoch: u64,
        progress: &AdmissionProgress,
        prepare: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<(T, SessionAccess<'a>)> {
        self.prepare_native_roles_prepaid_with_epoch(
            keys,
            contextual,
            progress,
            Some(epoch),
            None,
            prepare,
        )
    }

    /// Preparing a native Init may coexist with a returned, active sequence.
    /// This grants session/key possession. Replacing a ticket additionally needs
    /// the signature driver's inspected native success and resident-owner proof.
    pub(crate) fn prepare_init_with_native_roles_prepaid_at_epoch<'a, T, const N: usize>(
        &'a self,
        keys: [(Option<&NativeObjectRef>, AccessMode); N],
        category: fe11_sys::CK_FLAGS,
        epoch: u64,
        progress: &AdmissionProgress,
        prepare: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<(T, SessionAccess<'a>)> {
        self.prepare_native_roles_prepaid_with_epoch(
            keys,
            false,
            progress,
            Some(epoch),
            Some(category),
            prepare,
        )
    }

    fn prepare_native_roles_prepaid_with_epoch<'a, T, const N: usize>(
        &'a self,
        keys: [(Option<&NativeObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &AdmissionProgress,
        epoch: Option<u64>,
        init_category: Option<fe11_sys::CK_FLAGS>,
        mut prepare: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<(T, SessionAccess<'a>)> {
        let occupied_init = init_category.is_some();
        let policy = crate::admission_wait::current();
        let session_policy = self.admission();
        let before = || match epoch {
            Some(epoch) => {
                crate::session::recovery::observations::context(self, Some(epoch), epoch)
            }
            None => Ok(()),
        };
        before()?;
        let roles = match epoch {
            Some(epoch) if occupied_init => RolePlan::prepare_init_at_epoch(
                self,
                keys,
                progress,
                epoch,
                init_category.expect("Init category"),
            )?,
            Some(epoch) => RolePlan::prepare_at_epoch(self, keys, contextual, progress, epoch)?,
            None => RolePlan::prepare(self, keys, contextual, progress)?,
        };
        let mut overhead = PermissionStorage::requested(N)?;
        loop {
            policy.check_available()?;
            session_policy.check_available()?;
            before()?;
            let (candidate, mut prepaid) = prepare(overhead)?;
            let storage = PermissionStorage::allocate(N)?;
            let actual = storage.allocated_bytes()?;
            if actual > overhead {
                // The allocator rounded capacity upward. Replan the entire
                // aggregate, never wait for an extension of a partial credit.
                drop(storage);
                drop(candidate);
                drop(prepaid);
                overhead = actual;
                continue;
            }
            let attempt = policy.try_once(|| {
                session_policy.try_once(|| {
                    roles.access_prepaid(
                        self,
                        &ResourceAdmission::Immediate,
                        storage,
                        &mut prepaid,
                        || match epoch {
                            None => self.try_operation_access_progress(contextual, progress),
                            Some(epoch) => {
                                crate::with_resource_admission(ResourceAdmission::Immediate, || {
                                    // The surrounding try_once checks preserve both caller
                                    // deadlines; every actual possession probe is nonwaiting.
                                    let access = if occupied_init {
                                        self.advanced_access_with_epoch(
                                            crate::session::CleanupAdmission::Ordinary,
                                            progress,
                                            &crate::SessionAdmission::Immediate,
                                            Some(epoch),
                                        )?
                                    } else if contextual {
                                        self.context_authentication_access_at_epoch(
                                            progress,
                                            &crate::SessionAdmission::Immediate,
                                            Some(epoch),
                                        )?
                                    } else {
                                        self.access_with_epoch(
                                            progress,
                                            &crate::SessionAdmission::Immediate,
                                            Some(epoch),
                                        )?
                                    };
                                    if occupied_init {
                                        self.entry_common(&access)?;
                                    } else {
                                        self.entry(&access)?;
                                    }
                                    before()?;
                                    Ok(access)
                                })
                            }
                        },
                    )
                })
            });
            match attempt {
                Ok(access) => return Ok((candidate, access)),
                Err(error @ Error::Busy(_)) => {
                    // A failed probe has released all guards and permissions.
                    // Drop the whole private candidate before any waiting path.
                    drop(candidate);
                    drop(prepaid);
                    if matches!(policy, ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            if let Some(epoch) = epoch {
                roles.wait_available_in_context(self, &policy, || {
                    before()?;
                    if occupied_init {
                        self.advanced_access_progress_at_epoch(progress, epoch)
                    } else if contextual {
                        self.context_operation_access_progress_at_epoch(progress, epoch)
                    } else {
                        self.access_progress_at_epoch(progress, epoch)
                    }
                })?;
            } else {
                roles.wait_available(self, &policy, || {
                    if contextual {
                        self.context_operation_access_progress(progress)
                    } else {
                        self.access_progress(progress)
                    }
                })?;
            }
            // Availability is not possession. The next attempt rebuilds outside
            // guards and revalidates the same identity/authentication before C.
        }
    }
}
