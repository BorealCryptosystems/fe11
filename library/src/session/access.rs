// SPDX-License-Identifier: Apache-2.0
//! Own session-access guards, drop policy and retained object protections.
//! Access clones share the same possession rather than acquiring a second native session.

use super::*;

impl Session {
    /// Select destructor behavior without changing native state. Keep the owner
    /// until explicit close when using KeepOpen, especially with an active
    /// operation. Dropping it without cleanup can deliberately retain resources.
    /// Conversion into AdvancedSession preserves this choice.
    pub fn set_drop_behavior(&mut self, behavior: SessionDropBehavior) {
        self.drop_behavior = behavior;
    }

    /// Observe the caller's cleanup choice without a native call.
    pub fn drop_behavior(&self) -> SessionDropBehavior {
        self.drop_behavior
    }
}

impl<T> SessionAccess<'_, T> {
    pub(crate) fn retain_revocation_references(
        &self,
        candidate: &mut Option<Box<crate::managed::RevocationRetention>>,
    ) -> Result<()> {
        // On poison the preparation still owns the node; its access-first
        // caller releases guards before dropping the failed preparation.
        self.guards
            .revocations
            .lock()
            .map_err(|_| Error::Poisoned)?
            .retain(candidate);
        Ok(())
    }
}

impl<T> std::ops::Deref for SessionAccess<'_, T> {
    type Target = State;

    fn deref(&self) -> &State {
        &self.guards.state
    }
}

impl<T> Clone for SessionAccess<'_, T> {
    fn clone(&self) -> Self {
        Self {
            guards: self.guards.clone(),
        }
    }
}

impl SessionAccess<'_> {
    pub(crate) fn lease_admission(&self) -> Result<LeaseAdmission<'_, '_>> {
        match self.guards.provenance {
            AccessProvenance::Ordinary => {
                // A drain may have started while acquiring the session gate.
                self.guards._owners._snapshot.check_drain(false)?;
                Ok(LeaseAdmission { access: self })
            }
            AccessProvenance::Cleanup
            | AccessProvenance::Administrative
            | AccessProvenance::ContextAuthentication => {
                Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::OperationLeaseRequiresOrdinaryAdmission,
                )))
            }
        }
    }

    pub(crate) fn context_writer_held(&self) -> bool {
        matches!(
            &self.guards._token,
            TokenActivity::ContextAuthentication { .. }
        )
    }

    pub(crate) fn owns_session(&self, session: &Session) -> bool {
        Arc::ptr_eq(&self.guards._owners._entry, &session.entry)
            && Arc::ptr_eq(&self.guards._owners._snapshot, &session.snapshot)
            && Arc::ptr_eq(&self.guards._owners._inner, &session.inner)
    }
}

impl<T> SessionAccess<'_, T> {
    pub(super) fn retain_dynamic_readers(
        &self,
        readers: activity::dynamic::DynamicReaders,
    ) -> Result<()> {
        self.retain_resources(ResourceProtection::Readers { _readers: readers })
    }

    pub(crate) fn recovery_requested(&self) -> bool {
        self.guards.recovery_required.load(Ordering::Acquire)
    }

    pub(crate) fn recovery_ticket(&self) -> Result<recovery::Ticket> {
        recovery::Ticket::reserve(self.guards._owners._entry.clone())
    }

    pub(super) fn retained_protections(&self) -> Arc<RetainedObjects> {
        self.guards.retained_objects.values.get_or_init(|| {
            std::mem::take(
                &mut *self
                    .guards
                    .objects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            )
        });
        self.guards.retained_objects.clone()
    }

    /// Transfer prepared roles into a resident operation before its first C
    /// call. Native uncertainty is still governed by the operation ledger.
    pub(crate) fn retain_role_lease(&self) -> ObjectRoleLease {
        ObjectRoleLease {
            _owner: self.retained_protections(),
        }
    }

    pub(super) fn object_protections(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, ObjectProtections>> {
        let objects = self.guards.objects.lock().map_err(|_| Error::Poisoned)?;
        if self.guards.retained_objects.values.get().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectProtectionsAlreadyRetained,
            )));
        }
        Ok(objects)
    }

    /// Transfer the complete set without allocating or reacquiring Activity.
    pub(super) fn retain_prepared_permissions(
        &self,
        permissions: activity::roles::Permissions,
    ) -> Result<()> {
        // Zero roles is an admitted plan, distinct from missing preparation.
        // Keep its storage until access is released without occupying the slot
        // used by a separately prepared dynamic reader set.
        if permissions.is_empty() {
            let mut objects = self.object_protections()?;
            if objects.source_free.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::SourceFreeRolesAlreadyRetained,
                )));
            }
            objects.source_free = Some(permissions);
            return Ok(());
        }
        self.retain_resources(ResourceProtection::Roles {
            _permissions: permissions,
        })
    }

    pub(crate) fn retain_prepared_reader(&self, permit: crate::registry::ReadPermit) -> Result<()> {
        self.retain_resources(ResourceProtection::One {
            _permit: activity::Permission::Read { _permit: permit },
        })
    }

    /// A resident parent keeps the original exclusion while a proof uses this
    /// possession. Every native frame cloned from it retains the same proof,
    /// including frames whose completion cannot be established.
    pub(crate) fn retain_observation_protection(
        &self,
        protection: observation_protection::ObservationProtection,
    ) -> Result<()> {
        self.retain_resources(ResourceProtection::Observation {
            _protection: protection,
        })
    }

    pub(super) fn retain_resources(&self, resources: ResourceProtection) -> Result<()> {
        let mut objects = self.object_protections()?;
        if objects.resources.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ObjectResourceRolesAlreadyRetained,
            )));
        }
        objects.resources = Some(resources);
        Ok(())
    }

    /// Consume access together with the candidate so every refusal releases
    /// session/module guards before partial writers or retained destinations.
    pub(crate) fn retain_creation_activity(
        self,
        reservation: Arc<crate::managed::Reservation>,
        prepared: crate::managed::PreparedRetention,
    ) -> Result<Self> {
        struct Attempt<'a, T> {
            access: Option<SessionAccess<'a, T>>,
            prepared: Option<crate::managed::PreparedRetention>,
            bound: Option<CreationProtection>,
        }
        let mut attempt = Attempt {
            access: Some(self),
            prepared: Some(prepared),
            bound: None,
        };
        let access = attempt.access.as_ref().expect("owned creation access");
        let (reservation, writers) = reservation.retain_for_operation(
            &access.guards._owners._inner,
            &access.guards._owners._entry,
            &mut attempt.prepared,
        )?;
        attempt.bound = Some(CreationProtection {
            _writers: writers,
            _reservation: reservation,
        });
        let mut objects = access.object_protections()?;
        if objects.creation.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::OperationDestinationsAlreadyRetained,
            )));
        }
        objects.creation = attempt.bound.take();
        drop(objects);
        Ok(attempt.access.take().expect("owned creation access"))
    }
}

impl Session {
    pub(super) fn access_owners(&self) -> AccessOwners {
        AccessOwners {
            _entry: self.entry.clone(),
            _snapshot: self.snapshot.clone(),
            _inner: self.inner.clone(),
        }
    }

    pub(crate) fn maintain_local(&self) -> Result<bool> {
        self.try_local_cleanup(|proof| proof.maintain())
            .map(|result| result.is_some())
    }

    pub(crate) fn access(&self) -> Result<SessionAccess<'_>> {
        self.access_progress(&AdmissionProgress::default())
    }

    pub(crate) fn access_progress(
        &self,
        progress: &AdmissionProgress,
    ) -> Result<SessionAccess<'_>> {
        self.access_with_policy(progress, &self.admission())
    }

    pub(super) fn access_with_policy(
        &self,
        progress: &AdmissionProgress,
        admission: &crate::SessionAdmission,
    ) -> Result<SessionAccess<'_>> {
        self.access_with_epoch(progress, admission, None)
    }

    pub(crate) fn read_at_epoch(
        &self,
        epoch: u64,
    ) -> Result<crate::admission_wait::ReadGuard<'_, State>> {
        let _context = self.epoch_domain()?;
        let check = || recovery::observations::context(self, Some(epoch), epoch);
        let state = self.inner.state.read_checked(&check)?;
        Inner::validate(&state)?;
        Ok(state)
    }

    pub(crate) fn access_progress_at_epoch(
        &self,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<SessionAccess<'_>> {
        self.access_with_epoch(progress, &self.admission(), Some(epoch))
    }

    pub(super) fn access_with_epoch(
        &self,
        progress: &AdmissionProgress,
        admission: &crate::SessionAdmission,
        epoch: Option<u64>,
    ) -> Result<SessionAccess<'_>> {
        let domain = epoch.map(|_| self.epoch_domain()).transpose()?;
        let check = || match epoch {
            Some(epoch) => recovery::observations::context(self, Some(epoch), epoch),
            None => Ok(()),
        };
        let state = match epoch {
            Some(epoch) => self.read_at_epoch(epoch)?,
            None => self.inner.read()?,
        };
        let token = match &domain {
            Some(domain) => self.snapshot.read_activity_in_context(domain, &check)?,
            None => self.snapshot.read_activity()?,
        };
        let session = match &domain {
            Some(domain) => self
                .entry
                .operation
                .acquire_in_context(domain, admission, &check)?,
            None => self.entry.operation.acquire(admission)?,
        };
        check()?;
        progress.maintain_owned(&LocalOwnership {
            target: LocalTarget::Current(self),
            state: &state,
            _session: &session,
            _token: LocalTokenProof::Shared { _guard: &token },
        })?;
        self.entry(&state)?;
        check()?;
        Ok(SessionAccess {
            guards: Arc::new(AccessGuards {
                provenance: AccessProvenance::Ordinary,
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

    pub(crate) fn context_operation_access_progress(
        &self,
        progress: &AdmissionProgress,
    ) -> Result<SessionAccess<'_>> {
        let access = self.context_authentication_access_progress(progress)?;
        self.entry(&access)?;
        Ok(access)
    }

    /// Preserve the initiating epoch while waiting for the exclusive token
    /// activity required by contextual login. This remains a writer route.
    pub(crate) fn context_operation_access_progress_at_epoch(
        &self,
        progress: &AdmissionProgress,
        epoch: u64,
    ) -> Result<SessionAccess<'_>> {
        let access =
            self.context_authentication_access_at_epoch(progress, &self.admission(), Some(epoch))?;
        self.entry(&access)?;
        Ok(access)
    }

    /// Probe ordinary possession while a reconstructible candidate exists.
    /// Both caller policies are checked around the nonwaiting acquisition. The
    /// temporary resource scope changes only this probe, never the later wait.
    /// This helper performs local maintenance at most once and dispatches no C.
    pub(crate) fn try_operation_access_progress(
        &self,
        contextual: bool,
        progress: &AdmissionProgress,
    ) -> Result<SessionAccess<'_>> {
        let resources = crate::admission_wait::current();
        let session = self.admission();
        resources.try_once(|| {
            session.try_once(|| {
                crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
                    let access = if contextual {
                        self.context_authentication_access_with_policy(
                            progress,
                            &crate::SessionAdmission::Immediate,
                        )?
                    } else {
                        self.access_with_policy(progress, &crate::SessionAdmission::Immediate)?
                    };
                    self.entry(&access)?;
                    Ok(access)
                })
            })
        })
    }

    /// Synchronous observations and ordinary calls cannot dispatch on an
    /// asynchronous session. Cooperative tickets do not change this mode.
    pub(crate) fn check_synchronous_dispatch(&self) -> Result<()> {
        if self.entry.mode == crate::AdvancedSessionMode::Asynchronous {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::AsynchronousSessionRequiresOwnedDispatch,
            )));
        }
        Ok(())
    }

    pub(crate) fn entry(&self, s: &State) -> Result<&SessionEntry> {
        self.check_synchronous_dispatch()?;
        if self.entry.advanced_operation.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                crate::OperationOwnershipBusy::AdvancedOperation,
            )));
        }
        self.entry_common(s)
    }

    pub(crate) fn entry_common(&self, s: &State) -> Result<&SessionEntry> {
        if s.native.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        self.snapshot.check()?;
        let e = &self.entry;
        if let Some(notification) = &e.notification {
            notification.check()?;
        }
        if e.closed.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionClosed,
            )));
        }
        if e.close_attempted.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionClosingOrCloseFailed,
            )));
        }
        if e.generation != self.snapshot.generation
            || e.slot as u64 != self.snapshot.capabilities.identity.slot
        {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionGenerationMismatch,
            )));
        }
        if e.poisoned.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SessionStateUncertain,
            )));
        }
        Ok(e)
    }
}
