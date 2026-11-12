// SPDX-License-Identifier: Apache-2.0
//! Open sessions under discovered limits and manage collective lifecycle calls.
//! Session admission, drain ownership and native return publication remain separate.

use super::*;

impl TokenContext {
    /// Token ceilings calculated from the caller's selection and this context's
    /// snapshot. Module-wide ceilings also apply; no native query is performed.
    pub fn effective_session_limits(&self) -> crate::SessionLimit {
        self.inner.session_policy.effective(self.capabilities())
    }

    /// Stop new token admissions without cancelling native calls.
    /// Only one permit may exist. Module possession and subsequent maintenance
    /// follow the caller's admission scope; Immediate returns Busy if occupied.
    /// No native retry or timeout-based recycling is performed here.
    /// For shared runtimes, obtain the administrative context from
    /// RuntimeOwner::module; ordinary client contexts have no collective authority.
    pub fn begin_drain(&self) -> Result<TokenDrain> {
        self.lifecycle_access.require_owner()?;
        self.inner.check_lifecycle_reentry()?;
        let state = self.inner.read()?;
        let permit = self.reserve_drain()?;
        if !state
            .token_registry()?
            .tokens
            .iter()
            .any(|t| Arc::ptr_eq(t, &self.snapshot))
        {
            return Err(Error::Rejected(
                crate::RejectionReason::TokenAdministration(
                    crate::TokenAdministrationRejection::TokenContextReplaced,
                ),
            ));
        }
        Ok(permit)
    }

    // Caller holds module lifecycle. Refresh also needs to drain a stale context.
    pub(crate) fn reserve_drain(&self) -> Result<TokenDrain> {
        self.snapshot
            .domain
            .draining
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                Error::Busy(crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::TokenDraining,
                ))
            })?;
        self.snapshot.domain.activity.notify();
        self.inner.session_ledger.notify_admission();
        self.snapshot.notify_admission();
        Ok(TokenDrain {
            context: TokenContext {
                inner: self.inner.clone(),
                snapshot: self.snapshot.clone(),
                lifecycle_access: self.lifecycle_access,
            },
        })
    }

    /// Initial, immutable capabilities; does not probe the provider.
    pub fn capabilities(&self) -> &Capabilities {
        &self.snapshot.capabilities
    }

    /// Open a serial session with explicit read/write permission.
    /// Returns Busy without dispatch while this token is being administered.
    pub fn open_session(&self, read_write: bool) -> Result<crate::Session> {
        self.open_session_mode(read_write, crate::AdvancedSessionMode::Synchronous)
    }

    /// Open with an explicit destructor policy. KeepOpen matches native
    /// caller-managed cleanup: call Session::close explicitly before discarding
    /// the owner. It does not release ledger credits or bypass module shutdown
    /// preconditions. Opening itself uses the same C_OpenSession request.
    pub fn open_session_with_drop_behavior(
        &self,
        read_write: bool,
        behavior: crate::SessionDropBehavior,
    ) -> Result<crate::Session> {
        let mut session = self.open_session(read_write)?;
        session.set_drop_behavior(behavior);
        Ok(session)
    }

    /// Open a session with an owned application notification callback.
    /// A callback may arrive before this method returns its session.
    pub fn open_session_with_notify(
        &self,
        read_write: bool,
        notify: crate::NotifyHandler,
    ) -> Result<crate::Session> {
        self.open_session_mode_with_notify(
            read_write,
            crate::AdvancedSessionMode::Synchronous,
            Some(notify),
        )
    }

    pub(crate) fn open_session_mode(
        &self,
        read_write: bool,
        mode: crate::AdvancedSessionMode,
    ) -> Result<crate::Session> {
        self.open_session_mode_with_notify(read_write, mode, None)
    }

    pub(crate) fn open_session_mode_with_notify(
        &self,
        read_write: bool,
        mode: crate::AdvancedSessionMode,
        notify: Option<crate::NotifyHandler>,
    ) -> Result<crate::Session> {
        // Preflight current module/capability, then release every native gate
        // before waiting for quota. A close must remain able to return credit.
        {
            let s = self.inner.read()?;
            if mode == crate::AdvancedSessionMode::Asynchronous
                && ((s.native.table.version.major, s.native.table.version.minor) != (3, 2)
                    || s.native.asynchronous.is_none())
            {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::AsynchronousSessionCapability,
                )));
            }
            self.snapshot.check()?;
            self.snapshot.check_drain(false)?;
        }
        self.snapshot.bind_admission(&self.inner.context_wakes)?;
        let credit = self.inner.session_ledger.reserve_waiting(
            &self.capabilities().identity,
            self.snapshot.generation,
            read_write,
            self.inner.session_policy.effective(self.capabilities()),
            || {
                self.inner.state.check_admission(false)?;
                self.inner.availability.check_available()?;
                self.snapshot.check_drain(false)?;
                self.snapshot.check()
            },
        )?;
        let credit = credit.for_client(self.lifecycle_access.client_id());
        let admission = crate::admission_wait::current();
        let context_check = || {
            self.inner.state.check_admission(false)?;
            self.inner.availability.check_available()?;
            self.snapshot.check_drain(false)?;
            self.snapshot.check()
        };
        // Fixed lifecycle and optional notification owners are admitted as one
        // graph. A closed callback can release quota only after its registry Arc
        // is retired; revision changes therefore replan outside all guards.
        let fixed_bytes = crate::session::lifecycle_diagnostics::Store::allocation_bytes()
            .checked_add(if notify.is_some() {
                crate::notify::PreparedNotification::allocation_bytes()?
            } else {
                0
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::SessionOpeningStorageAccounting,
            )))?;
        let (lifecycle_diagnostics, mut prepared_notification) = loop {
            admission.check_available()?;
            let revision = {
                let state = self.inner.read()?;
                state.native.notifications.opening_revision()?
            };
            loop {
                let retired = {
                    let state = self.inner.read()?;
                    state.native.notifications.take_retired()?
                };
                if retired.is_none() {
                    break;
                }
                // Last application captures are destroyed outside every guard.
                drop(retired);
            }
            context_check()?;
            if !revision.current()? {
                continue;
            }
            let reserved = self.inner.symmetric_budget.reserve_controlled(
                fixed_bytes,
                &admission,
                || {
                    context_check()?;
                    Ok((!revision.current()?).then_some(()))
                },
                || Ok(None),
            )?;
            let mut prepaid = match reserved {
                crate::symmetric::memory::ControlledReservation::Acquired(credit) => credit,
                crate::symmetric::memory::ControlledReservation::Redirect(()) => continue,
            };
            let lifecycle =
                crate::session::lifecycle_diagnostics::Store::from_prepaid(&mut prepaid)?;
            let notification = if notify.is_some() {
                Some(crate::notify::PreparedNotification::from_prepaid(
                    &mut prepaid,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                )?)
            } else {
                None
            };
            break (lifecycle, notification);
        };
        let mut retired_notification_storage = None;
        let mut notify = notify;
        let mut handle =
            crate::native::frame::NativeFrame::new(CK_INVALID_HANDLE as CK_SESSION_HANDLE)?;
        // The session quota survives local replanning and excludes finalization.
        // No entry/context is published and no native call is recorded until
        // the fixed credits and current registry capacity are both prepared.
        let (s, _token, _transition, notification) = loop {
            let state = self.inner.read()?;
            let token = self.snapshot.read_activity()?;
            let transition = self
                .snapshot
                .domain
                .transition
                .acquire_checked(&admission, || self.snapshot.check())?;
            self.snapshot.check()?;
            // The module decides whether this session mode is valid for its
            // current login state; the cached role is not an admission policy.
            Inner::validate(&state)?;
            let Some(prepared) = prepared_notification.as_mut() else {
                break (state, token, transition, None);
            };
            match state.native.notifications.register_prepared(
                &mut notify,
                &state.native.image,
                state.native.dispatch.clone(),
                prepared,
            )? {
                crate::notify::Registration::Ready { context, retired } => {
                    retired_notification_storage = retired;
                    break (state, token, transition, Some(context));
                }
                crate::notify::Registration::Retired(context) => {
                    drop(transition);
                    drop(token);
                    drop(state);
                    drop(context);
                }
                crate::notify::Registration::NeedCapacity(plan) => {
                    drop(transition);
                    drop(token);
                    drop(state);
                    prepared.prepare_capacity(
                        plan,
                        &self.inner.symmetric_budget,
                        &admission,
                        context_check,
                    )?;
                }
            }
        };
        // Keep the old empty vector/credit in the outer scope until all guards
        // above are released, including every error and native-return path.
        let _ = &retired_notification_storage;
        let slot = self.capabilities().identity.slot as CK_SLOT_ID;
        let flags = CKF_SERIAL_SESSION as CK_FLAGS
            | if mode == crate::AdvancedSessionMode::Asynchronous {
                CKF_ASYNC_SESSION as CK_FLAGS
            } else {
                0
            }
            | if read_write {
                CKF_RW_SESSION as CK_FLAGS
            } else {
                0
            };
        let uid = credit.uid();
        // Allocate the stable entry before native dispatch. It is uniquely held
        // until its returned handle has been validated and published. Neither
        // notification arguments nor ledger dispatch receive this Arc. Its first
        // clone is credit.opened below, after the last get_mut; callbacks cannot
        // introduce a strong or weak reference before these unique mutations.
        let mut entry = Arc::new(SessionEntry {
            lifecycle_diagnostics,
            creator_close: crate::managed::CloseResident::new(&self.snapshot.domain, false),
            recovery: crate::session::recovery::Ledger::default(),
            notification: None,
            mode,
            advanced_operation: std::sync::atomic::AtomicU64::new(0),
            advanced_progress: crate::advanced::progress::Progress::default(),
            close_control: Mutex::new(None),
            close_pending: AtomicBool::new(false),
            creation_attempted: AtomicBool::new(false),
            credit,
            operation: crate::admission_wait::ResourceGate::new(
                crate::BusyReason::ModuleLifecycle(crate::ModuleLifecycleBusy::SessionActivity),
            ),
            snapshot: self.snapshot.clone(),
            close_attempted: AtomicBool::new(false),
            deferred_close: AtomicBool::new(false),
            handle: 0,
            slot,
            poisoned: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            unpublished_object: AtomicBool::new(false),
            read_write,
            generation: self.snapshot.generation,
        });
        // The ledger already reserved counts under its short mutex. No global
        // allocation lock is held while independent tokens enter native code.
        let (application, callback) = notification
            .as_ref()
            .map(|context| context.arguments())
            .unwrap_or((std::ptr::null_mut(), None));
        Arc::get_mut(&mut entry)
            .expect("unpublished session entry")
            .notification = notification;
        if let Err(error) = Arc::get_mut(&mut entry)
            .expect("unpublished session entry")
            .credit
            .dispatch()
        {
            if let Some(notification) = &entry.notification {
                notification.close();
            }
            return Err(error);
        }
        let open_session =
            match crate::native::functions::resolve(s.native.table.C_OpenSession, "C_OpenSession")
                .and_then(|call| {
                    s.native.record("C_OpenSession")?;
                    Ok(call)
                }) {
                Ok(call) => call,
                Err(error) => {
                    // No native dispatch occurred: return the local reservation, not an
                    // uncertain native handle. Keep a broken credit ledger withdrawn.
                    if let Some(notification) = &entry.notification {
                        notification.close();
                    }
                    if entry.credit.release().is_err() {
                        s.native.mark_uncertain();
                    }
                    return Err(error);
                }
            };
        // SAFETY: handle and optional application context have stable owned
        // addresses before dispatch. The registry retains the context through
        // every unproven outcome, independently of the session's publication.
        let rv = unsafe { open_session(slot, flags, application, callback, &mut *handle) };
        handle.retain_if_pending(rv, &s.native);

        if rv != CKR_OK {
            let failure = crate::native_return::open_failure(rv);
            s.apply_failure_scope(&self.snapshot, failure.scope);
            if failure.non_creation {
                if let Some(notification) = &entry.notification {
                    notification.close();
                }
                if entry.credit.release().is_err() {
                    s.native.mark_uncertain();
                }
            }
            // Native failure output is unspecified, not a usable session. The
            // credit remains counted after unknown/possibly partial effects.
            return check(rv, "C_OpenSession", !failure.non_creation).map(|_| unreachable!());
        }
        if *handle == CK_INVALID_HANDLE as fe11_sys::CK_ULONG {
            s.native.mark_uncertain();
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::InvalidOrDuplicateProviderSession,
            )));
        }
        Arc::get_mut(&mut entry)
            .expect("unpublished session entry")
            .handle = *handle;
        if let Err(error) = entry.credit.opened(entry.clone()) {
            s.native.mark_uncertain();
            return Err(error);
        }
        if let Some(notification) = &entry.notification {
            if let Err(error) = notification.bind(*handle) {
                // Open succeeded: preserve the real session and cleanup credit
                // even though the callback's session binding prevents use.
                entry.poisoned.store(true, Ordering::Release);
                entry.deferred_close.store(true, Ordering::Release);
                entry.snapshot.notify_admission();
                return Err(error);
            }
        }
        // The native resource already exists and is ledger-owned. A concurrent
        // withdrawal must withhold publication without discarding its credit.
        let publication = if s.native.is_uncertain() {
            Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )))
        } else {
            self.snapshot.check()
        };
        if let Err(error) = publication {
            entry.deferred_close.store(true, Ordering::Release);
            return Err(error);
        }
        Ok(crate::Session {
            drop_behavior: crate::SessionDropBehavior::Close,
            admission: None,
            entry,
            inner: self.inner.clone(),
            uid,
            snapshot: self.snapshot.clone(),
        })
    }

    /// Authenticate CKU_USER using an existing session. The owned PIN is erased
    /// on release. PENDING or a native boundary anomaly instead
    /// quarantine its storage; no erasure is promised then. Already logged in
    /// is never PIN verification.
    pub fn login(&self, pin: impl Into<crate::PinRequest>) -> Result<()> {
        let mut diagnostic = None;
        self.login_admitted(LoginRole::User, pin.into(), None, false, &mut diagnostic)
    }

    /// Authenticate the requested native role; already logged in never validates a PIN.
    /// Returns Busy without dispatch while this token has active operations.
    pub fn login_as(&self, role: LoginRole, pin: impl Into<crate::PinRequest>) -> Result<()> {
        let mut diagnostic = None;
        self.login_admitted(role, pin.into(), None, false, &mut diagnostic)
    }

    /// Authenticate a named user through the selected table's C_LoginUser.
    /// The user name is owned separately from the PIN and erased on release.
    /// Absence or refusal of C_LoginUser never calls C_Login as a substitute.
    pub fn login_user(
        &self,
        role: LoginRole,
        pin: impl Into<crate::PinRequest>,
        user_name: Vec<u8>,
    ) -> Result<()> {
        let mut diagnostic = None;
        self.login_admitted(role, pin.into(), Some(user_name), false, &mut diagnostic)
    }

    pub(super) fn login_admitted(
        &self,
        role: LoginRole,
        pin: crate::PinRequest,
        user_name: Option<Vec<u8>>,
        permit: bool,
        diagnostic_root: &mut Option<crate::error::PreparedCompletion>,
    ) -> Result<()> {
        self.login_on(role, pin, user_name, permit, None, diagnostic_root)
    }

    pub(super) fn login_on(
        &self,
        role: LoginRole,
        pin: crate::PinRequest,
        user_name: Option<Vec<u8>>,
        permit: bool,
        selected: Option<&crate::Session>,
        diagnostic_root: &mut Option<crate::error::PreparedCompletion>,
    ) -> Result<()> {
        let input = crate::pin::LoginFrame::new(pin, user_name);
        let call = if input.user_name.is_some() {
            crate::native_return::SessionCall::LoginUser
        } else {
            crate::native_return::SessionCall::Login
        };
        type Data = crate::pin::Credited<LoginCall>;
        let fixed = std::mem::size_of::<Data>() + TokenCallFrame::<'_, Data>::allocation_bytes();
        let ((prepared, diagnostic), access) =
            TokenAccess::prepare(&self.inner, &self.snapshot, permit, || {
                crate::pin::PreparedPins::prepare_with_completion(
                    fixed,
                    [Some(&input.pin), None],
                    input.user_name.as_ref().map(|name| &**name),
                    call.function(),
                    |bytes| {
                        TokenAccess::reserve_preparation(
                            &self.inner,
                            &self.snapshot,
                            permit,
                            bytes,
                            selected.map_or(0, |_| {
                                crate::session::lifecycle_diagnostics::Store::allocation_bytes()
                            }),
                        )
                    },
                )
            })?;
        let diagnostic = diagnostic_root.insert(diagnostic);
        // Select a live owner, not a locally predicted login outcome. The
        // module validates the requested role against all of its sessions.
        let entry = self.authentication_entry(&access, selected)?;
        let handle = entry.handle;
        let user_type = role.native()?;
        let (input, witnesses) = prepared.bind(LoginCall { entry, input });
        let mut frame = crate::native::frame::NativeFrame::token(access, input)?;
        let (returned, body) = frame.parts();
        let s = &body.access;
        let data = &mut **body.data;
        let input = &mut data.input;
        let rv = if matches!(call, crate::native_return::SessionCall::LoginUser) {
            let native = s.native.login_user.ok_or(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction {
                    function: "C_LoginUser",
                },
            ))?;
            let (pointer, length) = input.pin.arguments()?;
            // LoginUser was selected from this same owned name before binding.
            // Preparation moves the frame without taking the name; no native
            // call has yet occurred and no other owner can mutate this Option.
            let name = input.user_name.as_mut().expect("named login selected");
            let name_length = bounds::ck_length(name.len())?;
            let name_pointer = if name.is_empty() {
                &mut input.empty_name
            } else {
                name.as_mut_ptr()
            };
            Inner::validate(s)?;
            s.native.record(call.function())?;
            returned.arm();
            // SAFETY: PIN/name/sentinels, selected session, token writer and
            // module guard with their referents all belong to this stable frame.
            returned.observe(
                unsafe {
                    native(
                        handle,
                        user_type,
                        pointer,
                        length,
                        name_pointer,
                        name_length,
                    )
                },
                &s.native,
            )
        } else {
            let native = s.native.table.C_Login.ok_or(Error::Rejected(
                crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::CLoginUnavailable,
                ),
            ))?;
            let (pointer, length) = input.pin.arguments()?;
            Inner::validate(s)?;
            s.native.record(call.function())?;
            returned.arm();
            // SAFETY: the same complete owner covers the ordinary login route;
            // no fallback from a named login or protected PIN source is taken.
            returned.observe(
                unsafe { native(handle, user_type, pointer, length) },
                &s.native,
            )
        };
        let certain = call.completion_known(rv);
        if certain {
            returned.terminated();
        }
        // Even a failed login can consume a PIN attempt. Preserve that possible
        // effect independently of whether a new role was established.
        let native_result = s.check_session_return(&data.entry, call, rv, true);
        if certain
            && (!witnesses.pins[0].unchanged(&input.pin) || !input.name_unchanged(&witnesses.name))
        {
            returned.quarantine(&s.native);
            return Err(diagnostic.take()?.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeAuthenticationInputChanged,
                )),
            ));
        }
        native_result?;
        let publication = (|| {
            self.snapshot.set_role(Some(role))?;
            self.authentication_result(s, Ok(()))
        })();
        diagnostic.take()?.finish(publication)
    }

    /// End authentication for all sessions of this token, including when a
    /// cryptographic operation is suspended between native calls. Actual native
    /// execution and session closure remain mutually exclusive with Logout.
    /// A successful Logout does not prove that previous operations terminated;
    /// their buffers remain owned and their old authentication epoch is revoked.
    pub fn logout(&self) -> Result<()> {
        let mut diagnostics = None;
        self.logout_admitted(false, &mut diagnostics)
    }

    pub(super) fn logout_admitted(
        &self,
        permit: bool,
        diagnostics: &mut Option<crate::session::lifecycle_diagnostics::Loan>,
    ) -> Result<()> {
        self.logout_on(permit, None, diagnostics)
    }

    pub(super) fn logout_on(
        &self,
        permit: bool,
        selected: Option<&crate::Session>,
        diagnostics: &mut Option<crate::session::lifecycle_diagnostics::Loan>,
    ) -> Result<()> {
        // Selection needs token ownership, but replenishing diagnostic leaves
        // must not allocate under it. Revalidate the exact selected entry after
        // preparing its loan; a changed selection is a local replan, not a C call.
        let (access, entry) = loop {
            let access = TokenAccess::logout(&self.inner, &self.snapshot, permit)?;
            let entry = self.logout_entry(&access, selected)?;
            if diagnostics.as_ref().is_some_and(|loan| loan.owns(&entry)) {
                break (access, entry);
            }
            drop(access);
            drop(diagnostics.take());
            *diagnostics = Some(crate::session::lifecycle_diagnostics::Store::loan_checked(
                &entry,
                &crate::admission_wait::current(),
                &|| {
                    self.inner.check_logout_admission()?;
                    self.snapshot.check_drain(permit)?;
                    self.snapshot.check()
                },
            )?);
        };
        let slot = self.capabilities().identity.slot as CK_SLOT_ID;
        let handle = entry.handle;
        let native = access.native.table.C_Logout.ok_or(Error::Rejected(
            crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::CLogoutUnavailable,
            ),
        ))?;
        let (diagnostic, secondary) = diagnostics
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::LogoutDiagnosticAbsent,
            )))?
            .completions("C_Logout")?;
        let frame = crate::native::frame::LogoutFrame::new(access, entry);
        let (returned, s, entry) = frame.parts();
        Inner::validate_logout(s, &self.snapshot)?;
        s.native
            .record_checked("C_Logout", &self.inner.state.admission_wake(), &|| {
                self.inner.check_logout_admission()
            })?;
        Inner::validate_logout(s, &self.snapshot)?;
        returned.arm();
        // SAFETY: the frame owns the selected session through the call. After
        // a returned PENDING its token-wide marker excludes dependent closes;
        // only a call without a return retains the coordination guards.
        let rv = returned.observe(unsafe { native(handle) }, &s.native);
        let call = crate::native_return::SessionCall::Logout;
        if call.completion_known(rv) {
            returned.terminated();
        }
        let native_result = s.check_session_return(entry, call, rv, true);
        // A refused logout withdraws evidence without inventing a public native
        // state. Only CKR_OK records logout; neither outcome ends buffer loans.
        let local_result: Result<()> = (|| {
            if rv == CKR_OK {
                self.snapshot.set_role(None)?;
            } else {
                self.snapshot.forget_authentication()?;
            }
            // Expire descriptive observations, not the native handle or the
            // right to request the next step of a possessed operation.
            if rv == CKR_OK {
                crate::managed::forget_private_origins(
                    &self.inner,
                    s,
                    slot,
                    self.snapshot.generation,
                )?;
            }
            Ok(())
        })();
        if local_result.is_err() {
            s.native.mark_uncertain();
        }
        if let Err(operation) = native_result {
            return match local_result {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(diagnostic.pair_with(secondary).finish(operation, cleanup)),
            };
        }
        diagnostic.finish(local_result.and_then(|()| {
            Inner::validate_logout(s, &self.snapshot)?;
            self.snapshot.check()
        }))
    }

    pub(super) fn authentication_result(&self, s: &State, result: Result<()>) -> Result<()> {
        result?;

        Inner::validate(s)?;
        self.snapshot.check()
    }
}
