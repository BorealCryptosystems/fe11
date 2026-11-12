// SPDX-License-Identifier: Apache-2.0
//! Prove possession for local reclamation of current or retained sessions.
//! Maintenance validates the owner and does not itself grant permission to call C.

use super::*;

impl LocalOwnership<'_> {
    pub(crate) fn entry(&self) -> &SessionEntry {
        match self.target {
            LocalTarget::Current(session) => &session.entry,
            LocalTarget::Retained(entry) => entry,
        }
    }

    pub(crate) fn maintain(&self) -> Result<()> {
        self.validate()?;
        self.entry().recovery.observations.maintain()?;
        self.state.operations.maintain_owned(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self.target {
            LocalTarget::Current(session) => session.entry_common(self.state).map(|_| ()),
            LocalTarget::Retained(entry) => {
                // Local reclamation does not revive a retired token context or
                // grant C access. Poison and native uncertainty remain barriers.
                if self.state.native.is_uncertain()
                    || entry.poisoned.load(Ordering::Acquire)
                    || entry.closed.load(Ordering::Acquire)
                    || entry.close_attempted.load(Ordering::Acquire)
                    || entry.close_pending.load(Ordering::Acquire)
                {
                    return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                        crate::SessionLifecycleRejection::SessionStateUncertain,
                    )));
                }
                Ok(())
            }
        }
    }
}

pub(crate) fn maintain_retained_entry(
    state: &State,
    entry: &SessionEntry,
    token: &crate::admission_wait::ReadGuard<'_, ()>,
    session: &crate::admission_wait::ResourceGuard<'_>,
) -> Result<()> {
    let proof = LocalOwnership {
        target: LocalTarget::Retained(entry),
        state,
        _session: session,
        _token: LocalTokenProof::Shared { _guard: token },
    };
    proof.validate()?;
    entry.recovery.observations.maintain()?;
    state.operations.maintain_marked(&proof)
}

impl<'a, 'session> LeaseAdmission<'a, 'session> {
    pub(crate) fn access(&self) -> &'a SessionAccess<'session> {
        self.access
    }

    pub(crate) fn snapshot(&self) -> &crate::module::TokenSnapshot {
        &self.access.guards._owners._snapshot
    }

    pub(crate) fn entry(&self) -> &Arc<SessionEntry> {
        &self.access.guards._owners._entry
    }
}

impl Drop for AccessOwners {
    fn drop(&mut self) {
        // AccessGuards declares this field last. Object, session, token and
        // module guards have already been released; resource predicates can
        // therefore recheck a native-error/close withdrawal without inversion.
        if self._entry.poisoned.load(Ordering::Acquire)
            || self._entry.close_attempted.load(Ordering::Acquire)
            || self._entry.closed.load(Ordering::Acquire)
        {
            self._snapshot.notify_admission();
        }
    }
}

impl ObjectRoleLease {
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self._owner, &other._owner)
    }

    /// Cryptographic continuations acquire this lease only from a prepaid role
    /// plan, never from an observation or a creation transaction. The shared
    /// outer access cell is uncredited; its owned permission tables are not.
    pub(crate) fn retain_role_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> Result<()> {
        use crate::symmetric::memory::RetainedStorage;
        let protections = self._owner.values.get().ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::RetainedRoleProtectionsAbsent,
            ),
        ))?;
        if protections.creation.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CreationProtectionInCryptographicContinuation,
            )));
        }
        match &protections.resources {
            Some(ResourceProtection::Roles { _permissions }) => {
                _permissions.retain_credits(retained)?;
            }
            None => (),
            Some(
                ResourceProtection::One { .. }
                | ResourceProtection::Readers { .. }
                | ResourceProtection::Observation { .. },
            ) => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SessionLifecycle(crate::SessionLifecycleRejection::UnplannedProtectionInCryptographicContinuation),
                ));
            }
        }
        protections.source_free.retain_credits(retained)
    }

    pub(crate) fn transfer_writer(
        &self,
        activity: &Arc<crate::registry::Activity>,
        destination: &crate::registry::PreparedReader,
    ) -> Result<crate::registry::TransferredWritePermit> {
        let protections = self._owner.values.get().ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SignatureWriterNotInstalled,
            ),
        ))?;
        let writer = match protections.resources.as_ref() {
            Some(ResourceProtection::One {
                _permit: activity::Permission::Write { _permit },
            }) if _permit.owns_activity(activity) => Some(_permit),
            Some(ResourceProtection::Roles { _permissions }) => _permissions.writer_for(activity),
            _ => None,
        }
        .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SignatureWriterCapabilityAbsent,
        )))?;
        writer.share_for(destination)
    }
}

impl RetainedObjects {
    pub(super) fn quarantine(&self) {
        self.quarantined.store(true, Ordering::Release);
    }

    pub(super) fn is_quarantined(&self) -> bool {
        self.quarantined.load(Ordering::Acquire)
    }
}
