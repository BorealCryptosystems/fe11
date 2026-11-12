// SPDX-License-Identifier: Apache-2.0
//! Acquire session access for contextual authentication.
//! Authentication failures are observed in the context of the exact native operation.

use super::*;

impl Session {
    pub(super) fn context_authentication_access_progress(
        &self,
        progress: &AdmissionProgress,
    ) -> Result<SessionAccess<'_>> {
        self.context_authentication_access_with_policy(progress, &self.admission())
    }

    pub(super) fn context_authentication_access_with_policy(
        &self,
        progress: &AdmissionProgress,
        admission: &crate::SessionAdmission,
    ) -> Result<SessionAccess<'_>> {
        self.context_authentication_access_at_epoch(progress, admission, None)
    }

    pub(super) fn context_authentication_access_at_epoch(
        &self,
        progress: &AdmissionProgress,
        admission: &crate::SessionAdmission,
        epoch: Option<u64>,
    ) -> Result<SessionAccess<'_>> {
        let domain = epoch.map(|_| self.epoch_domain()).transpose()?;
        let before = || {
            if let Some(epoch) = epoch {
                crate::session::recovery::observations::context(self, Some(epoch), epoch)?;
            }
            Ok(())
        };
        before()?;
        let state = match epoch {
            Some(epoch) => self.read_at_epoch(epoch)?,
            None => self.inner.read()?,
        };
        let token = match &domain {
            Some(domain) => self
                .snapshot
                .context_authentication_activity_in_context(domain, &before)?,
            None => self.snapshot.context_authentication_activity()?,
        };
        let session = match &domain {
            Some(domain) => self
                .entry
                .operation
                .acquire_in_context(domain, admission, &before)?,
            None => self.entry.operation.acquire(admission)?,
        };
        before()?;
        progress.maintain_owned(&LocalOwnership {
            target: LocalTarget::Current(self),
            state: &state,
            _session: &session,
            _token: LocalTokenProof::Exclusive { _guard: &token },
        })?;
        before()?;
        self.entry_common(&state)?;
        Ok(SessionAccess {
            guards: Arc::new(AccessGuards {
                provenance: AccessProvenance::ContextAuthentication,
                recovery_required: AtomicBool::new(false),
                objects: std::sync::Mutex::new(ObjectProtections::default()),
                retained_objects: Arc::new(RetainedObjects::default()),
                _session: session,
                _token: TokenActivity::ContextAuthentication { _guard: token },
                state,
                revocations: std::sync::Mutex::new(crate::managed::RevocationRetentions::default()),
                _owners: self.access_owners(),
            }),
        })
    }

    pub(crate) fn observe_authentication_error(&self, error: &Error) {
        if error.authentication_lost() {
            let _ = self.snapshot.forget_authentication();
        }
    }
}
