// SPDX-License-Identifier: Apache-2.0
//! Acquire activity against a specific token-context snapshot.
//! Drain and authentication observations are revalidated at the required access boundaries.

use super::*;

impl TokenSnapshot {
    pub(crate) fn check_drain(&self, permit: bool) -> Result<()> {
        if self.domain.draining.load(Ordering::Acquire) != permit {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::TokenDraining,
            )));
        }
        Ok(())
    }

    pub fn read_activity(&self) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        let guard = self.read_activity_checked(false, true)?;
        self.check()?;
        Ok(guard)
    }

    pub fn observation_activity(&self) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        self.cleanup_activity(false)
    }

    pub fn cleanup_activity(
        &self,
        permit: bool,
    ) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        self.read_activity_checked(permit, false)
    }

    pub(super) fn read_activity_checked(
        &self,
        permit: bool,
        require_current: bool,
    ) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        self.read_activity_on(permit, require_current, None, &|| Ok(()))
    }

    pub(crate) fn read_activity_in_context(
        &self,
        context: &Arc<crate::admission_wait::Wake>,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        let guard = self.read_activity_on(false, true, Some(context), validate)?;
        self.check()?;
        Ok(guard)
    }

    pub(super) fn read_activity_on(
        &self,
        permit: bool,
        require_current: bool,
        context: Option<&Arc<crate::admission_wait::Wake>>,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        self.check_drain(permit)?;
        validate()?;
        let policy = crate::admission_wait::current();
        let check = || {
            validate()?;
            self.check_drain(permit)?;
            if require_current {
                self.check()?;
            }
            Ok(
                (self.domain.closing_active.load(Ordering::Acquire) != 0).then_some(
                    crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::SessionClosePending,
                    ),
                ),
            )
        };
        let guard = match context {
            Some(context) => self.domain.activity.read_in_context(
                context,
                &policy,
                crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenAdministration),
                check,
            )?,
            None => self.domain.activity.read(
                &policy,
                crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenAdministration),
                check,
            )?,
        };
        self.check_drain(permit)?;
        if self.domain.closing_active.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionClosePending,
            )));
        }
        validate()?;
        Ok(guard)
    }

    pub fn module_cleanup_activity(&self) -> Result<crate::admission_wait::ReadGuard<'_, ()>> {
        let guard = self.domain.activity.read(
            &crate::admission_wait::current(),
            crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenAdministration),
            || {
                Ok(
                    (self.domain.closing_active.load(Ordering::Acquire) != 0).then_some(
                        crate::BusyReason::ModuleLifecycle(
                            crate::ModuleLifecycleBusy::SessionClosePending,
                        ),
                    ),
                )
            },
        )?;
        if self.domain.closing_active.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionClosePending,
            )));
        }
        Ok(guard)
    }

    // Called under the slot writer after resource reservations, before native
    // close. No wraparound can make an old unpublished handle current again.
    pub(crate) fn advance_close_epoch(&self) -> Result<()> {
        self.domain
            .close_epoch
            .update_checked(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::SessionCloseEpochExhausted,
                ))
            })?;
        Ok(())
    }

    // A potentially destructive close takes the slot writer to prevent an
    // unregistered alias appearing between the object snapshot and C. A proven
    // non-creator close instead holds a reader through publication.
    pub(crate) fn close_activity(
        &self,
        permit: Option<bool>,
    ) -> Result<crate::admission_wait::WriteGuard<'_, ()>> {
        if let Some(permit) = permit {
            self.check_drain(permit)?;
        }
        let guard = self.domain.activity.try_write().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::TokenActivityDuringSessionClose,
            )),
            _ => Error::Poisoned,
        })?;
        if let Some(permit) = permit {
            self.check_drain(permit)?;
        }
        Ok(guard)
    }

    // Context-specific login belongs to an already initialized operation. Use
    // the same slot writer as administration/destructive close, but do not wait for paused
    // advanced owners to disappear: the requesting owner is one of them.
    // Readers exclude every in-flight session call, including native creation;
    // the writer also excludes Open/Close and token-wide authentication.
    pub(crate) fn context_authentication_activity(
        &self,
    ) -> Result<crate::admission_wait::WriteGuard<'_, ()>> {
        self.context_authentication_activity_on(None, || Ok(()))
    }

    pub(crate) fn context_authentication_activity_in_context(
        &self,
        domain: &Arc<crate::admission_wait::Wake>,
        before: impl Fn() -> Result<()>,
    ) -> Result<crate::admission_wait::WriteGuard<'_, ()>> {
        self.context_authentication_activity_on(Some(domain), before)
    }

    pub(super) fn context_authentication_activity_on(
        &self,
        domain: Option<&Arc<crate::admission_wait::Wake>>,
        before: impl Fn() -> Result<()>,
    ) -> Result<crate::admission_wait::WriteGuard<'_, ()>> {
        let admission = crate::admission_wait::current();
        let validate = || {
            before()?;
            self.check_drain(false)?;
            self.check()?;
            Ok(
                (self.domain.closing_active.load(Ordering::Acquire) != 0).then_some(
                    crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::SessionClosePending,
                    ),
                ),
            )
        };
        let guard = match domain {
            Some(domain) => self.domain.activity.write_in_context(
                domain,
                &admission,
                crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::TokenActivityDuringContextAuthentication,
                ),
                validate,
            )?,
            None => self.domain.activity.write(
                &admission,
                crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::TokenActivityDuringContextAuthentication,
                ),
                validate,
            )?,
        };
        before()?;
        self.check_drain(false)?;
        self.check()?;
        if self.domain.closing_active.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionClosePending,
            )));
        }
        Ok(guard)
    }

    pub fn maintenance_activity(
        &self,
        permit: bool,
    ) -> Result<crate::admission_wait::WriteGuard<'_, ()>> {
        self.maintenance_activity_with_policy(permit, &crate::admission_wait::current())
    }

    pub(crate) fn maintenance_activity_with_policy(
        &self,
        permit: bool,
        admission: &crate::ResourceAdmission,
    ) -> Result<crate::admission_wait::WriteGuard<'_, ()>> {
        // Replacement publication, not native token administration: callers
        // must inspect retained execution before retiring admission leases.
        // Memory ownership alone does not exclude this shared physical writer.
        self.check_drain(permit)?;
        if self.domain.advanced_count_invalid.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        let guard = self.domain.activity.write(
            admission,
            crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenActivity),
            || {
                self.check_drain(permit)?;
                if self.domain.advanced_count_invalid.load(Ordering::Acquire) {
                    return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
                    )));
                }
                if self.domain.closing_active.load(Ordering::Acquire) != 0 {
                    return Ok(Some(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::SessionClosePending,
                    )));
                }
                Ok(None)
            },
        )?;
        if self.domain.advanced_count_invalid.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        if self.domain.closing_active.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::SessionClosePending,
            )));
        }
        self.check_drain(permit)?;
        Ok(guard)
    }

    // Private to explicit collective recovery. Ordinary writers continue to
    // require A == 0. Read A before S because lease Drop decrements S then A.
    pub(super) fn recovery_population(&self) -> Result<(usize, usize)> {
        self.check_drain(true)?;
        if self.domain.advanced_count_invalid.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::RecoveryOwnerMismatch,
            )));
        }
        Ok((
            self.domain.advanced_active.load(Ordering::Acquire),
            self.domain.advanced_stranded.load(Ordering::Acquire),
        ))
    }

    pub(super) fn wait_recovery_population(
        &self,
        admission: &crate::ResourceAdmission,
        previous: Option<(usize, usize)>,
        allow_maintenance: bool,
    ) -> Result<crate::admission_wait::WriterReadiness> {
        self.domain.activity.wait_write_ready(
            admission,
            crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::TokenActivity),
            || {
                let (active, stranded) = self.recovery_population()?;
                if self.domain.closing_active.load(Ordering::Acquire) != 0 {
                    return Ok(Some(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::SessionClosePending,
                    )));
                }
                if active != stranded || previous == Some((active, stranded)) {
                    return Ok(Some(crate::BusyReason::ModuleLifecycle(
                        crate::ModuleLifecycleBusy::AdvancedTokenActivity,
                    )));
                }
                Ok(None)
            },
            || {
                allow_maintenance
                    && self.domain.closing_active.load(Ordering::Acquire) == 0
                    && self.domain.needs_local_cleanup.load(Ordering::Acquire)
            },
        )
    }

    pub fn authentication_stamp(&self) -> u64 {
        self.authentication.stamp()
    }

    pub(crate) fn recorded_user(&self) -> Result<crate::Observation<bool>> {
        self.authentication.recorded_user()
    }

    pub(crate) fn forget_authentication(&self) -> Result<()> {
        let result = self.authentication.forget().map_err(|error| {
            self.invalidate();
            error
        });
        self.notify_admission();
        result
    }

    pub(crate) fn observe_session_state(&self, state: CK_STATE) -> Result<()> {
        let result = self
            .authentication
            .observe_session_state(state)
            .map_err(|error| {
                self.invalidate();
                error
            });
        self.notify_admission();
        result
    }

    pub fn check_authentication(&self, stamp: u64) -> Result<()> {
        self.check()?;
        self.authentication.check_private(stamp)
    }

    pub fn check_authentication_unchanged(&self, stamp: u64) -> Result<()> {
        self.check()?;
        self.authentication.check_unchanged(stamp)
    }

    pub(crate) fn observe_authentication_unchanged(&self, stamp: u64) -> Result<()> {
        self.check()?;
        self.authentication.observe_unchanged(stamp)
    }

    pub fn set_role(&self, role: Option<LoginRole>) -> Result<()> {
        let result = self.authentication.transition(role).map_err(|e| {
            self.invalidate();
            e
        });
        // Authentication::transition has released its role mutex before waking
        // pure admission predicates in the resource domains.
        self.notify_admission();
        result
    }

    pub fn replacement(&self, capabilities: Capabilities, generation: u64) -> Result<Self> {
        if capabilities.identity.slot != self.capabilities.identity.slot {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ReplacementSlotMismatch,
            )));
        }
        Ok(Self::with_domain(
            capabilities,
            generation,
            self.domain.clone(),
        ))
    }

    pub(crate) fn with_domain(
        capabilities: Capabilities,
        generation: u64,
        domain: Arc<SlotDomain>,
    ) -> Self {
        Self {
            unknown_close: crate::managed::CloseResident::new(&domain, true),
            capabilities,
            generation,
            valid: AtomicBool::new(true),
            admission_withdrawn: AtomicBool::new(false),
            retirement: Mutex::new(token_retirement::Retirement::Current),
            domain,
            authentication: crate::authentication::Authentication::new(),
        }
    }

    pub(super) fn bind_admission(
        &self,
        wake: &Arc<crate::admission_wait::ContextWakes>,
    ) -> Result<()> {
        let registered = self.domain.admission.get_or_init(|| Arc::downgrade(wake));
        if !registered.ptr_eq(&Arc::downgrade(wake)) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::TokenAdmissionOwnerMismatch,
            )));
        }
        Ok(())
    }

    pub(crate) fn notify_admission(&self) {
        if let Some(wake) = self
            .domain
            .admission
            .get()
            .and_then(std::sync::Weak::upgrade)
        {
            wake.notify();
        }
    }

    pub fn check(&self) -> Result<()> {
        if !self.admission_available() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::TokenContextStale,
            )));
        }
        Ok(())
    }
}
