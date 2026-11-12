// SPDX-License-Identifier: Apache-2.0
//! Prepare an administrative candidate before acquiring token and session guards.
//! The returned access owns the protections required for the ensuing native call.

use super::*;

impl Session {
    pub(crate) fn prepare_administrative_access<T>(
        &self,
        permit: bool,
        prepare: impl FnMut() -> Result<T>,
    ) -> Result<(
        T,
        SessionAccess<'_, crate::admission_wait::WriteGuard<'_, ()>>,
    )> {
        let (candidate, token) =
            crate::module::TokenAccess::prepare(&self.inner, &self.snapshot, permit, prepare)?;
        let (state, token) = token.into_guards();
        let session = self.entry.operation.try_lock().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionActivity,
            )),
            _ => Error::Poisoned,
        })?;
        self.entry(&state)?;
        Ok((
            candidate,
            SessionAccess {
                guards: Arc::new(AccessGuards {
                    provenance: AccessProvenance::Administrative,
                    recovery_required: AtomicBool::new(false),
                    objects: std::sync::Mutex::new(ObjectProtections::default()),
                    retained_objects: Arc::new(RetainedObjects::default()),
                    _session: session,
                    _token: token,
                    state,
                    revocations: std::sync::Mutex::new(
                        crate::managed::RevocationRetentions::default(),
                    ),
                    _owners: self.access_owners(),
                }),
            },
        ))
    }
}
