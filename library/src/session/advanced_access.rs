// SPDX-License-Identifier: Apache-2.0
//! Acquire advanced-operation access under the caller’s admission policy.
//! Context and authentication are revalidated around possession and local maintenance.

use super::*;

impl Session {
    pub(crate) fn advanced_access(&self) -> Result<SessionAccess<'_>> {
        self.advanced_access_admitted(CleanupAdmission::Ordinary)
    }

    pub(crate) fn advanced_access_admitted(
        &self,
        admission: CleanupAdmission,
    ) -> Result<SessionAccess<'_>> {
        self.advanced_access_progress(admission, &AdmissionProgress::default())
    }

    pub(crate) fn advanced_access_progress(
        &self,
        admission: CleanupAdmission,
        progress: &AdmissionProgress,
    ) -> Result<SessionAccess<'_>> {
        self.advanced_access_with_policy(admission, progress, &self.admission())
    }

    /// Local-only acquisition probe for an unpublished advanced candidate.
    /// Original deadlines are checked; the probe itself acquires no waiting gate.
    pub(crate) fn try_advanced_access_progress(
        &self,
        progress: &AdmissionProgress,
    ) -> Result<SessionAccess<'_>> {
        let resources = crate::admission_wait::current();
        let session = self.admission();
        resources.try_once(|| {
            session.try_once(|| {
                crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
                    self.advanced_access_with_policy(
                        CleanupAdmission::Ordinary,
                        progress,
                        &crate::SessionAdmission::Immediate,
                    )
                })
            })
        })
    }

    /// Advanced starts revalidate their initial context while preserving the
    /// advanced entry contract and its local maintenance opportunity.
    pub(crate) fn advanced_access_progress_at_epoch(
        &self,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<SessionAccess<'_>> {
        self.advanced_access_with_epoch(
            CleanupAdmission::Ordinary,
            progress,
            &self.admission(),
            Some(epoch),
        )
    }

    pub(crate) fn try_advanced_access_progress_at_epoch(
        &self,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<SessionAccess<'_>> {
        let resources = crate::admission_wait::current();
        let session = self.admission();
        resources.try_once(|| {
            session.try_once(|| {
                crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
                    self.advanced_access_with_epoch(
                        CleanupAdmission::Ordinary,
                        progress,
                        &crate::SessionAdmission::Immediate,
                        Some(epoch),
                    )
                })
            })
        })
    }

    pub(super) fn advanced_access_with_policy(
        &self,
        admission: CleanupAdmission,
        progress: &AdmissionProgress,
        session_policy: &crate::SessionAdmission,
    ) -> Result<SessionAccess<'_>> {
        self.advanced_access_with_epoch(admission, progress, session_policy, None)
    }

    pub(super) fn advanced_access_with_epoch(
        &self,
        admission: CleanupAdmission,
        progress: &AdmissionProgress,
        session_policy: &crate::SessionAdmission,
        epoch: Option<u64>,
    ) -> Result<SessionAccess<'_>> {
        let domain = epoch.map(|_| self.epoch_domain()).transpose()?;
        let check = || match epoch {
            Some(epoch) => recovery::observations::context(self, Some(epoch), epoch),
            None => Ok(()),
        };
        let state = if let Some(epoch) = epoch {
            self.read_at_epoch(epoch)?
        } else if matches!(admission, CleanupAdmission::Module) {
            self.inner.read_module_cleanup()?
        } else {
            self.inner.read()?
        };
        let token = if let Some(domain) = &domain {
            self.snapshot.read_activity_in_context(domain, &check)?
        } else {
            match admission {
                CleanupAdmission::Module => self.snapshot.module_cleanup_activity()?,
                CleanupAdmission::Token => self.snapshot.cleanup_activity(true)?,
                CleanupAdmission::Ordinary => self.snapshot.read_activity()?,
            }
        };
        let session = match &domain {
            Some(domain) => {
                self.entry
                    .operation
                    .acquire_in_context(domain, session_policy, &check)?
            }
            None => self.entry.operation.acquire(session_policy)?,
        };
        check()?;
        progress.maintain_owned(&LocalOwnership {
            target: LocalTarget::Current(self),
            state: &state,
            _session: &session,
            _token: LocalTokenProof::Shared { _guard: &token },
        })?;
        self.entry_common(&state)?;
        check()?;
        Ok(SessionAccess {
            guards: Arc::new(AccessGuards {
                provenance: match admission {
                    CleanupAdmission::Ordinary => AccessProvenance::Ordinary,
                    CleanupAdmission::Token | CleanupAdmission::Module => AccessProvenance::Cleanup,
                },
                recovery_required: AtomicBool::new(false),
                objects: std::sync::Mutex::new(ObjectProtections::default()),
                retained_objects: Arc::new(RetainedObjects::default()),
                _session: session,
                _token: TokenActivity::Shared { _guard: token },
                state,
                revocations: std::sync::Mutex::new(crate::managed::RevocationRetentions::default()),
                _owners: self.access_owners(),
            }),
        })
    }
}
