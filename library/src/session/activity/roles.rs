// SPDX-License-Identifier: Apache-2.0
//! All-or-none possession of aliased managed reader/writer roles before C.
use super::context;
use crate::{
    registry::{Activity, PreparedReader, ReadPermit, WritePermit},
    session::SessionAccess,
    Error, NativeObjectRef, ResourceAdmission, Result, Session,
};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessMode {
    Read,
    Write,
}

// The variant owns its exclusion until Drop; no later access to the permit
// value is needed to keep its resource protected.
pub(crate) enum Permission {
    Read { _permit: ReadPermit },
    Write { _permit: WritePermit },
}

/// Concrete permission storage allocated before final possession. The credit
/// covers actual capacity and leaves after all permits and their vector.
pub(crate) struct Permissions {
    values: Vec<Option<Permission>>,
    _credit: crate::symmetric::memory::Credit,
}
impl crate::symmetric::memory::RetainedStorage for Permissions {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        retained.add_credit(&self._credit)
    }
}
/// Unbound vector storage. Construct only after reserving the complete private
/// candidate; actual allocator capacity is checked before any possession.
pub(crate) struct PermissionStorage {
    values: Vec<Option<Permission>>,
}
impl PermissionStorage {
    pub(crate) fn requested(count: usize) -> Result<usize> {
        count
            .checked_mul(std::mem::size_of::<Option<Permission>>())
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectPermissionStorageAccounting,
            )))
    }

    pub(crate) fn allocate(count: usize) -> Result<Self> {
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectPermissionStorageAllocation,
            ))
        })?;
        values.resize_with(count, || None);
        Ok(Self { values })
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        Self::requested(self.values.capacity())
    }

    pub(crate) fn bind(
        self,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Permissions> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(Permissions {
            values: self.values,
            _credit: credit,
        })
    }
}

impl Permissions {
    pub(in crate::session) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub(in crate::session) fn writer_for(&self, activity: &Arc<Activity>) -> Option<&WritePermit> {
        self.values
            .iter()
            .flatten()
            .find_map(|permission| match permission {
                Permission::Write { _permit } if _permit.owns_activity(activity) => Some(_permit),
                _ => None,
            })
    }
    fn prepare(
        session: &Session,
        count: usize,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        let mut required = PermissionStorage::requested(count)?;
        loop {
            let mut credit =
                crate::advanced::reserve_preparation_with_progress(session, required, progress)?;
            let storage = PermissionStorage::allocate(count)?;
            let actual = storage.allocated_bytes()?;
            if actual > required {
                drop(storage);
                drop(credit);
                required = actual;
                continue;
            }
            return storage.bind(&mut credit);
        }
    }
}
impl Drop for Permissions {
    fn drop(&mut self) {
        // Reverse actual role acquisition without holding the access mutex.
        for value in self.values.iter_mut().rev() {
            drop(value.take());
        }
    }
}

enum Role {
    Read(PreparedReader),
    Write(Arc<Activity>),
}

/// Shared identity preparation only: no private credit or acquired permission.
/// Reader attribution is owned by Activity and can outlive a discarded candidate.
pub(crate) struct RolePlan<'k, const N: usize> {
    keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
    roles: [Option<Role>; N],
    authentication: u64,
    init_category: Option<fe11_sys::CK_FLAGS>,
}

/// Lifetime-free ownership for deferred destruction of a role preparation.
/// Borrowed native references are discarded; attributed readers are retained.
pub(crate) struct RetiredRolePlan<const N: usize> {
    _roles: [Option<Role>; N],
}
impl<const N: usize> RolePlan<'_, N> {
    pub(crate) fn retire(self) -> RetiredRolePlan<N> {
        RetiredRolePlan { _roles: self.roles }
    }
}

pub(crate) struct PreparedRoles<'k, const N: usize> {
    plan: RolePlan<'k, N>,
    permissions: Permissions,
}

impl<'k, const N: usize> PreparedRoles<'k, N> {
    /// Allocate UID attribution and permission storage before copied inputs.
    /// These preparations hold identity, but no reader or writer permission.
    pub(crate) fn prepare(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        Self::prepare_mode(session, keys, contextual, false, progress)
    }

    fn prepare_mode(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        contextual: bool,
        advanced: bool,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        let plan = RolePlan::prepare_mode(session, keys, contextual, advanced, progress, None)?;
        let permissions = Permissions::prepare(session, N, progress)?;
        Ok(Self { plan, permissions })
    }

    pub(crate) fn access<'a>(
        self,
        session: &'a Session,
        policy: &ResourceAdmission,
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<SessionAccess<'a>> {
        let (access, permissions) = self.acquire(session, policy, grant)?;
        access.retain_prepared_permissions(permissions)?;
        Ok(access)
    }

    fn acquire<'a>(
        self,
        session: &'a Session,
        policy: &ResourceAdmission,
        mut grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<(SessionAccess<'a>, Permissions)> {
        let Self {
            plan,
            mut permissions,
        } = self;
        let access = plan.acquire_into(session, policy, &mut permissions.values, &mut grant)?;
        Ok((access, permissions))
    }
}

impl<'k> RolePlan<'k, 0> {
    /// Generation has no existing key role. Preserve its original epoch even
    /// while acquiring the first session guard; do not capture a later stamp.
    pub(crate) fn for_generation(
        session: &Session,
        authentication: u64,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        drop(session.access_progress_at_epoch(progress, authentication)?);
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        Ok(Self {
            keys: [],
            roles: [],
            authentication,
            init_category: None,
        })
    }
}

impl<'k, const N: usize> RolePlan<'k, N> {
    /// Destination availability and final possession share this admission epoch.
    pub(crate) fn authentication(&self) -> u64 {
        self.authentication
    }

    pub(crate) fn prepare(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        // Preserve the context at admission entry, including time spent waiting
        // for the first session access. Public references carry no historical
        // authentication stamp of their own.
        let authentication = session.snapshot.authentication_stamp();
        Self::prepare_mode(
            session,
            keys,
            contextual,
            false,
            progress,
            Some(authentication),
        )
    }

    /// Prepare source identity in the initiating context, including waits
    /// for the first session/token gate. No private permission vector is held.
    pub(crate) fn prepare_at_epoch(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        contextual: bool,
        progress: &crate::session::AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        let access = if contextual {
            session.context_operation_access_progress_at_epoch(progress, authentication)?
        } else {
            session.access_progress_at_epoch(progress, authentication)?
        };
        Self::prepare_identities(session, keys, Some(authentication), access, progress)
    }

    /// Only an Init attempt can borrow readers of its own quiescent category.
    /// Every acquisition revalidates that owner under actual session possession.
    pub(crate) fn prepare_init_at_epoch(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        progress: &crate::session::AdmissionProgress,
        authentication: u64,
        category: fe11_sys::CK_FLAGS,
    ) -> Result<Self> {
        let mut plan = Self::prepare_advanced_at_epoch(session, keys, progress, authentication)?;
        plan.init_category = Some(category);
        Ok(plan)
    }

    /// Restoration permits its registered control owner, but prepares only
    /// shared role identity here. Private permission slots join its aggregate.
    pub(crate) fn prepare_advanced_at_epoch(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        progress: &crate::session::AdmissionProgress,
        authentication: u64,
    ) -> Result<Self> {
        // The first Dispatch acquisition belongs to the original restoration,
        // just like subsequent contention waits. Never recapture its epoch.
        let access = session.advanced_access_progress_at_epoch(progress, authentication)?;
        Self::prepare_identities(session, keys, Some(authentication), access, progress)
    }

    fn prepare_mode(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        contextual: bool,
        advanced: bool,
        progress: &crate::session::AdmissionProgress,
        original_authentication: Option<u64>,
    ) -> Result<Self> {
        let access = if advanced {
            session
                .advanced_access_progress(crate::session::CleanupAdmission::Ordinary, progress)?
        } else if contextual {
            session.context_operation_access_progress(progress)?
        } else {
            session.access_progress(progress)?
        };
        Self::prepare_identities(session, keys, original_authentication, access, progress)
    }

    fn prepare_identities(
        session: &Session,
        keys: [(Option<&'k NativeObjectRef>, AccessMode); N],
        original_authentication: Option<u64>,
        access: SessionAccess<'_>,
        progress: &crate::session::AdmissionProgress,
    ) -> Result<Self> {
        for (key, _) in &keys {
            if let Some(key) = key {
                session.native_object_handle(&access, key)?;
            }
        }
        drop(access);
        let policy = crate::admission_wait::current();
        let authentication =
            original_authentication.unwrap_or_else(|| session.snapshot.authentication_stamp());
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        let check = || {
            context(session)?;
            session
                .snapshot
                .observe_authentication_unchanged(authentication)
        };
        let mut activities = [None; N];
        for (index, (key, _)) in keys.iter().enumerate() {
            if let Some(key) = key {
                activities[index] = Some(key.identity.activity()?);
            }
        }
        let mut roles: [Option<Role>; N] = std::array::from_fn(|_| None);
        for (index, activity) in activities.iter().enumerate() {
            let Some(activity) = *activity else { continue };
            if activities[..index]
                .iter()
                .flatten()
                .any(|previous| Arc::ptr_eq(activity, previous))
            {
                continue;
            }
            // Coalesce native aliases: a writer dominates every read role of
            // the same activity, including generic and descriptive references.
            let write = keys.iter().zip(&activities).any(|((_, mode), other)| {
                *mode == AccessMode::Write
                    && other.is_some_and(|other| Arc::ptr_eq(activity, other))
            });
            roles[index] = Some(if write {
                Role::Write(activity.clone())
            } else {
                Role::Read(activity.prepare_reader_retaining(
                    session.uid,
                    &policy,
                    progress.retained_source(),
                    check,
                )?)
            });
        }
        Ok(Self {
            keys,
            roles,
            authentication,
            init_category: None,
        })
    }

    pub(crate) fn access_prepaid<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        storage: PermissionStorage,
        prepaid: &mut crate::symmetric::memory::Credit,
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<SessionAccess<'a>> {
        self.access_prepared(session, policy, storage.bind(prepaid)?, grant)
    }

    /// Consume the slots already charged to the enclosing preparation. The
    /// retained permission owner carries that credit through final possession.
    pub(crate) fn access_prepared<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        mut permissions: Permissions,
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<SessionAccess<'a>> {
        let access = self.acquire_into(session, policy, &mut permissions.values, grant)?;
        access.retain_prepared_permissions(permissions)?;
        Ok(access)
    }

    /// Wait with stack-only temporary permits, never a private permission credit.
    /// The temporary grant is dropped before returning; it authorizes no C call.
    pub(crate) fn wait_available<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<()> {
        self.wait_available_on(session, policy, None, grant)
    }

    /// Source Activity releases and context invalidation share the catalogue
    /// domain. It is distinct from the module/token/session gate domain.
    pub(crate) fn wait_available_in_context<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<()> {
        if N == 0 {
            return self.wait_available(session, policy, grant);
        }
        let wake = session
            .inner
            .reservations
            .lock()
            .map_err(|_| Error::Poisoned)?
            .scan_wake();
        // Bind before the first wait predicate. Alias bindings are idempotent;
        // an Activity already bound to another catalogue remains an error.
        for (key, _) in &self.keys {
            if let Some(key) = key {
                key.identity.activity()?.bind_context_wake(&wake)?;
            }
        }
        self.wait_available_on(session, policy, Some(&wake), grant)
    }

    fn wait_available_on<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        wake: Option<&Arc<crate::admission_wait::Wake>>,
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<()> {
        let mut permissions: [Option<Permission>; N] = std::array::from_fn(|_| None);
        let outcome = self.acquire_into_on(session, policy, &mut permissions, wake, grant);
        // Drop session possession before the object permissions on every outcome.
        let result = outcome.map(drop);
        for permission in permissions.iter_mut().rev() {
            drop(permission.take());
        }
        result
    }

    fn acquire_into<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        permissions: &mut [Option<Permission>],
        grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<SessionAccess<'a>> {
        self.acquire_into_on(session, policy, permissions, None, grant)
    }

    fn acquire_into_on<'a>(
        &self,
        session: &'a Session,
        policy: &ResourceAdmission,
        permissions: &mut [Option<Permission>],
        wake: Option<&Arc<crate::admission_wait::Wake>>,
        mut grant: impl FnMut() -> Result<SessionAccess<'a>>,
    ) -> Result<SessionAccess<'a>> {
        if permissions.len() != N {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectPermissionStorageShape,
            )));
        }
        let check = || {
            context(session)?;
            session
                .snapshot
                .observe_authentication_unchanged(self.authentication)
        };
        loop {
            let held = grant()?;
            for (key, _) in &self.keys {
                if let Some(key) = key {
                    session.native_object_handle(&held, key)?;
                }
            }
            session
                .snapshot
                .check_authentication_unchanged(self.authentication)?;
            let reader_borrow = self
                .init_category
                .map(|category| crate::advanced::init_reader_borrow(session, &held, category))
                .transpose()?
                .flatten();
            // This UID is only an availability hint after releasing possession.
            // A subsequent attempt must obtain a fresh lifetime-bound proof.
            let borrowed_uid = reader_borrow
                .as_ref()
                .map(crate::advanced::InitReaderBorrow::uid);
            let mut blocked = None;
            for (index, role) in self.roles.iter().enumerate() {
                let Some(role) = role else { continue };
                let acquired = policy.try_once(|| {
                    let permission = match role {
                        Role::Read(reader) => Permission::Read {
                            _permit: reader.acquire_once(&ResourceAdmission::Immediate)?,
                        },
                        Role::Write(activity) => Permission::Write {
                            _permit: match reader_borrow.as_ref() {
                                Some(proof) => activity.write_for_init_admitted(
                                    proof,
                                    &ResourceAdmission::Immediate,
                                )?,
                                None => activity.write_for_operation_admitted(
                                    session.uid,
                                    &ResourceAdmission::Immediate,
                                )?,
                            },
                        },
                    };
                    // The caller's storage outlives held, including a refusal
                    // from the final policy check after successful acquisition.
                    permissions[index] = Some(permission);
                    Ok(())
                });
                match acquired {
                    Ok(()) => (),
                    Err(error @ Error::Busy(_)) => {
                        blocked = Some((index, error));
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            let Some((index, error)) = blocked else {
                return Ok(held);
            };
            drop(held);
            for permission in permissions.iter_mut() {
                drop(permission.take());
            }
            if matches!(policy, ResourceAdmission::Immediate) {
                // One probe means one attempt. Returning the original refusal
                // lets the outer transaction discard its candidate before any
                // re-preparation, even if this role just became available.
                return Err(error);
            }
            match (
                self.roles[index].as_ref().expect("contended managed role"),
                wake,
            ) {
                (Role::Read(reader), Some(_)) => reader.wait_available_in_context(policy, check)?,
                (Role::Write(activity), Some(wake)) => {
                    activity.wait_init_writer_available(Some(wake), policy, borrowed_uid, check)?;
                }
                (Role::Read(reader), None) => reader.wait_available_checked(policy, check)?,
                (Role::Write(activity), None) => {
                    activity.wait_init_writer_available(None, policy, borrowed_uid, check)?;
                }
            }
        }
    }
}
