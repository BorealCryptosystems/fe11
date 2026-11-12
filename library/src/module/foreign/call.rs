// SPDX-License-Identifier: Apache-2.0
//! One foreign invocation, with thread-bound admission and an explicit receipt.

use super::*;
use crate::admission_wait::{ReadGuard, ResourceGuard, WriteGuard};
use std::sync::atomic::Ordering;

#[derive(Clone, Copy)]
pub(super) enum AdmissionMode {
    Ordinary,
    Module,
    Token,
}

enum TokenGuard<'a> {
    Read { _guard: ReadGuard<'a, ()> },
    Write { _guard: WriteGuard<'a, ()> },
}

// Reverse acquisition order; no opaque graph is owned by these guard fields.
pub(super) struct Admission<'a> {
    _session: Option<ResourceGuard<'a>>,
    _token: Option<TokenGuard<'a>>,
    _state: ReadGuard<'a, super::super::State>,
}

fn validate(inner: &Inner, domain: Option<&SlotDomain>, mode: AdmissionMode) -> Result<()> {
    inner
        .state
        .check_admission(matches!(mode, AdmissionMode::Module))?;
    if !matches!(mode, AdmissionMode::Module) {
        inner.availability.check_available()?;
    }
    if let Some(domain) = domain {
        if !matches!(mode, AdmissionMode::Module)
            && domain.draining.load(Ordering::Acquire) != matches!(mode, AdmissionMode::Token)
        {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::TokenDraining,
            )));
        }
    }
    Ok(())
}

pub(super) fn admit<'a>(
    inner: &'a Inner,
    domain: Option<&'a SlotDomain>,
    gate: Option<&'a crate::admission_wait::ResourceGate>,
    access: ForeignAccess,
    mode: AdmissionMode,
) -> Result<Admission<'a>> {
    let policy = crate::admission_wait::current();
    let wake = inner.state.admission_wake();
    let check = || validate(inner, domain, mode);
    loop {
        policy.check_available()?;
        check()?;
        let state = if matches!(mode, AdmissionMode::Module) {
            inner.read_module_cleanup()?
        } else {
            inner.read()?
        };
        let token = if let Some(domain) = domain {
            let acquired = match access {
                ForeignAccess::Session => domain
                    .activity
                    .try_read()
                    .map(|guard| TokenGuard::Read { _guard: guard })
                    .map_err(contention),
                ForeignAccess::Token => domain
                    .activity
                    .try_write()
                    .map(|guard| TokenGuard::Write { _guard: guard })
                    .map_err(contention),
            };
            match acquired {
                Ok(guard) => Some(guard),
                Err(Error::Busy(_)) => {
                    // Wait only after releasing module/dispatch possession. The
                    // acquired probe is dropped before revalidating the full set.
                    drop(state);
                    match access {
                        ForeignAccess::Session => drop(domain.activity.read_in_context(
                            &wake,
                            &policy,
                            crate::BusyReason::ExternalExecution(
                                crate::ExternalExecutionBusy::ForeignTokenActivity,
                            ),
                            || {
                                check()?;
                                Ok(None)
                            },
                        )?),
                        ForeignAccess::Token => drop(domain.activity.write_in_context(
                            &wake,
                            &policy,
                            crate::BusyReason::ExternalExecution(
                                crate::ExternalExecutionBusy::ForeignTokenActivity,
                            ),
                            || {
                                check()?;
                                Ok(None)
                            },
                        )?),
                    }
                    continue;
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        check()?;
        let session = if let Some(gate) = gate {
            match gate.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(Error::Poisoned),
                Err(std::sync::TryLockError::WouldBlock) => {
                    drop(token);
                    drop(state);
                    drop(gate.acquire_in_context(&wake, &policy, check)?);
                    continue;
                }
            }
        } else {
            None
        };
        check()?;
        return Ok(Admission {
            _session: session,
            _token: token,
            _state: state,
        });
    }
}

fn contention<T>(error: std::sync::TryLockError<T>) -> Error {
    match error {
        std::sync::TryLockError::WouldBlock => Error::Busy(crate::BusyReason::ExternalExecution(
            crate::ExternalExecutionBusy::ForeignTokenActivity,
        )),
        std::sync::TryLockError::Poisoned(_) => Error::Poisoned,
    }
}

pub(crate) use super::call_scope::in_call;
use super::call_scope::{CallScope, PreparedScope};

/// Thread-bound permission for one native step on one registered graph.
/// Mark dispatch before calling C, then record the actual return. Dropping before
/// dispatch restores admission; dropping after dispatch without a receipt retains
/// the graph and withdraws the runtime. It never cancels or calls C itself.
pub struct ForeignCall<'a> {
    work: &'a ForeignWork,
    step: ForeignStep,
    prior: Phase,
    admission: Option<Admission<'a>>,
    callbacks: Option<registry::CallbackSeal<'a>>,
    scope: Option<CallScope>,
    retired: registry::Retired,
    state: CallState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallState {
    Prepared,
    Dispatched,
    Recorded,
}

impl ForeignWork {
    /// Admit one step outside a lifecycle drain. No native function is invoked.
    /// The graph's exact native function and parameter validity remain the
    /// unsafe adapter's responsibility.
    pub fn begin(&mut self, step: ForeignStep) -> Result<ForeignCall<'_>> {
        self.begin_admitted(step, AdmissionMode::Ordinary)
    }

    pub(super) fn begin_admitted(
        &mut self,
        step: ForeignStep,
        mode: AdmissionMode,
    ) -> Result<ForeignCall<'_>> {
        if step == ForeignStep::CloseSession && self.work.kind != ForeignWorkKind::Session {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignCloseSessionOwnerRequired,
            )));
        }
        self.inner.check_lifecycle_reentry()?;
        if step == ForeignStep::CloseSession {
            self.inner
                .foreign
                .wait_callbacks(&self.inner, self.work.scope.slot())?;
        }
        let mut retired = registry::Retired::default();
        let session = self.work.session.as_ref().unwrap_or(&self.work);
        // Declared before admission so every error releases guards before
        // destroying the prepared node and refunding its storage.
        let prepared_scope;
        let policy = crate::admission_wait::current();
        let acquire = || {
            admit(
                &self.inner,
                self.work.domain.as_deref(),
                (self.work.kind == ForeignWorkKind::Session || self.work.session.is_some())
                    .then_some(&session.gate),
                self.work.access,
                mode,
            )
        };
        let (admission, callbacks) = loop {
            let candidate = PreparedScope::new(
                self.inner.foreign.image_id(),
                &self.inner.symmetric_budget,
                || {
                    validate(&self.inner, self.work.domain.as_deref(), mode)?;
                    if registry::native_context_retired(&self.work) {
                        return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                            crate::ExternalExecutionRejection::ForeignNativeContextRetired,
                        )));
                    }
                    Ok(())
                },
            )?;
            let admission = match policy.try_once(|| {
                crate::with_resource_admission(crate::ResourceAdmission::Immediate, acquire)
            }) {
                Ok(admission) => admission,
                Err(Error::Busy(_)) => {
                    drop(candidate);
                    drop(acquire()?);
                    continue;
                }
                Err(error) => return Err(error),
            };
            self.inner.foreign.check_session(&self.work)?;
            if step != ForeignStep::CloseSession {
                prepared_scope = candidate;
                break (admission, None);
            }
            self.inner.foreign.prepare_retirement(&mut retired)?;
            // CloseSession was restricted to Session work above. Its only
            // constructors supply a slot, and register_work resolves that slot
            // to a domain before publication. Neither immutable field can be
            // changed by a native return, a callback, or a previous failed call.
            match self.inner.foreign.seal_callbacks(Some((
                self.work.scope.slot().expect("session slot"),
                self.work.domain.as_ref().expect("session domain").clone(),
            ))) {
                Ok(seal) => {
                    prepared_scope = candidate;
                    break (admission, Some(seal));
                }
                Err(Error::Busy(crate::BusyReason::ExternalExecution(
                    crate::ExternalExecutionBusy::ForeignCallbackActiveOrClosing,
                ))) => {
                    drop(admission);
                    drop(candidate);
                    self.inner
                        .foreign
                        .wait_callbacks(&self.inner, self.work.scope.slot())?;
                }
                Err(error) => return Err(error),
            }
        };
        if step == ForeignStep::CloseSession {
            self.inner.foreign.session_close_ready(&self.work)?;
        }
        let prior = {
            let mut state = self.work.state.lock().map_err(|_| Error::Poisoned)?;
            let prior = state.phase;
            let applicable = match (prior, self.work.kind, step) {
                (Phase::Prepared, _, ForeignStep::Start) => matches!(mode, AdmissionMode::Ordinary),
                (Phase::PreparedJoin, ForeignWorkKind::Operation, ForeignStep::Join) => true,
                (
                    Phase::Progressable(_),
                    _,
                    ForeignStep::Continue
                    | ForeignStep::Complete
                    | ForeignStep::Cancel
                    | ForeignStep::GetId,
                ) => true,
                (Phase::SessionOpen, ForeignWorkKind::Session, ForeignStep::CloseSession) => true,
                _ => false,
            };
            if !applicable {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignWorkStepNotAdmitted,
                )));
            }
            if step == ForeignStep::Join {
                let source = self.work.join_source.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::ExternalExecution(
                        crate::ExternalExecutionRejection::ForeignJoinSourceMissing,
                    ),
                ))?;
                let mut source = source.state.lock().map_err(|_| Error::Poisoned)?;
                if source.phase != Phase::Detached {
                    return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                        crate::ExternalExecutionBusy::ForeignJoinSourceClaimed,
                    )));
                }
                source.phase = Phase::JoinReserved;
            }
            state.phase = Phase::Reserved(step);
            prior
        };
        let scope = prepared_scope.enter();
        Ok(ForeignCall {
            work: self,
            step,
            prior,
            admission: Some(admission),
            callbacks,
            scope: Some(scope),
            retired,
            state: CallState::Prepared,
        })
    }
}

impl ForeignCall<'_> {
    /// Record OpenSession's actual handle under its original admission. This
    /// same work becomes the session owner, preserving its callback identity.
    ///
    /// # Safety
    /// The exact C_OpenSession must have returned code and, on CKR_OK, handle.
    /// The graph must satisfy prepare_session_open's stable lifetime contract.
    /// For an ordinary error that returns its memory loans, the adapter must
    /// also establish that no native callback registration survives the failure.
    /// If that cannot be established, use `returned(code, Uncertain)` instead:
    /// an error code alone must not certify the end of a callback's lifetime.
    pub unsafe fn opened(mut self, code: u64, handle: u64) -> ForeignReceipt {
        let publication = (|| {
            if self.work.work.kind != ForeignWorkKind::Session || self.step != ForeignStep::Start {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignOpenSessionOwnerRequired,
                )));
            }
            if code != fe11_sys::CKR_OK as u64 {
                return self.record_return(code, ForeignCompletion::Returned);
            }
            let native = fe11_sys::CK_SESSION_HANDLE::try_from(handle).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignSessionHandleConversion,
                ))
            })?;
            if native == fe11_sys::CK_INVALID_HANDLE {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignSessionHandleInvalid,
                )));
            }
            self.work
                .inner
                .foreign
                .check_opened_handle(&self.work.work, handle)?;
            let mut state = self.work.work.state.lock().map_err(|_| Error::Poisoned)?;
            state.last_return = Some(NativeReturn {
                step: self.step,
                code,
            });
            if self.state != CallState::Dispatched
                || state.phase != Phase::Issued(ForeignStep::Start)
            {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignOpenWithoutDispatch,
                )));
            }
            self.work
                .work
                .session_handle
                .store(handle, Ordering::Release);
            state.phase = Phase::SessionOpen;
            Ok(())
        })();
        self.finish_receipt(code, publication)
    }

    /// Record the dispatch boundary immediately before the one native invocation.
    /// It cannot be used to authorize a second call through the same permit.
    pub fn dispatched(&mut self) -> Result<()> {
        if self.state != CallState::Prepared {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignCallAlreadyDispatched,
            )));
        }
        let mut state = self.work.work.state.lock().map_err(|_| Error::Poisoned)?;
        if state.phase != Phase::Reserved(self.step) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignCallReservationChanged,
            )));
        }
        state.phase = Phase::Issued(self.step);
        self.state = CallState::Dispatched;
        if let Some(callbacks) = &self.callbacks {
            callbacks.begin_native();
        }
        Ok(())
    }

    /// Record this invocation's actual code and lifetime proof. The returned
    /// receipt always preserves that code, even when local publication fails.
    ///
    /// # Safety
    /// The invocation must have returned, on the declared runtime/scope/step.
    /// Returned proves the end of EVERY loan in this registered graph; Pending
    /// and Continue retain it. Detached requires successful C_AsyncGetID and its
    /// buffer-return guarantee, not proof that the job ended. Native sub-graphs
    /// still used by other invocations must never be covered by a false proof.
    /// Register any newly opened session before returning its OpenSession call.
    /// No timeout, cache value or token-removal notification is a memory proof.
    /// Pending requires the native asynchronous protocol to be supported by
    /// this session/operation, with a real completion path for this same graph.
    /// An unexpected pending from a synchronous call is Uncertain, not Pending.
    pub unsafe fn returned(mut self, code: u64, completion: ForeignCompletion) -> ForeignReceipt {
        let publication = self.record_return(code, completion);
        self.finish_receipt(code, publication)
    }

    fn finish_receipt(mut self, code: u64, publication: Result<()>) -> ForeignReceipt {
        // Discovery withdraws authority only. It does not certify that any
        // unrelated pending graph or callback has returned its memory loan.
        let retirement = (|| {
            use crate::native_return::FailureScope;
            let Some(admission) = &self.admission else {
                return Ok(());
            };
            let pending_parent = self.prior == Phase::Progressable(Progress::Pending);
            if self.step.controls_parent(pending_parent) {
                self.work.inner.availability.observe_async_return(code);
            } else {
                self.work.inner.availability.observe_runtime_return(code);
            }
            if publication.is_ok()
                && code == fe11_sys::CKR_PENDING as u64
                && self.work.work.kind == ForeignWorkKind::Operation
                && self.work.work.access == ForeignAccess::Session
            {
                let state = self.work.work.state.lock().map_err(|_| Error::Poisoned)?;
                if state.phase == Phase::Progressable(Progress::Pending) && state.graph.is_some() {
                    // record_return validated this exact dispatch and retained
                    // its graph. This pending belongs to the operation's
                    // progression protocol, not to an unscoped runtime failure.
                    // Other receipts, publication failures and unexpected
                    // synchronous pending retain their conservative withdrawal.
                    return Ok(());
                }
            }
            match self.step.context_scope(code, pending_parent) {
                FailureScope::Session => {
                    self.work
                        .work
                        .session
                        .as_ref()
                        .unwrap_or(&self.work.work)
                        .native_retired
                        .store(true, Ordering::Release);
                }
                FailureScope::Token => {
                    if let Some(slot) = self.work.work.scope.slot() {
                        if let (Some(domain), Some(epoch)) =
                            (&self.work.work.domain, self.work.work.token_epoch)
                        {
                            if domain.foreign_epoch.load(Ordering::Acquire) != epoch {
                                return Ok(());
                            }
                        }
                        admission._state.retire_slot(
                            fe11_sys::CK_SLOT_ID::try_from(slot).map_err(|_| {
                                Error::Rejected(crate::RejectionReason::ExternalExecution(
                                    crate::ExternalExecutionRejection::ForeignSlotConversion,
                                ))
                            })?,
                        )?;
                        if let (Some(domain), Some(epoch)) =
                            (&self.work.work.domain, self.work.work.token_epoch)
                        {
                            domain.retire_foreign_epoch(epoch);
                        }
                    }
                }
                FailureScope::Module => self.work.inner.availability.mark(),
                FailureScope::None => {}
            }
            Ok(())
        })();
        let publication = publication.and(retirement);
        if let Some(callbacks) = &self.callbacks {
            callbacks.end_native();
        }
        if publication.is_err() {
            let mut state = self
                .work
                .work
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.last_return = Some(NativeReturn {
                step: self.step,
                code,
            });
            state.phase = Phase::Uncertain;
            drop(state);
            self.work.inner.availability.mark();
        }
        self.state = CallState::Recorded;
        // Destructors of application graphs run after all possession and TLS
        // scopes, including on a local publication error.
        drop(self.callbacks.take());
        drop(self.admission.take());
        drop(self.scope.take());
        self.work.inner.context_wakes.notify();
        ForeignReceipt { code, publication }
    }

    fn record_return(&mut self, code: u64, completion: ForeignCompletion) -> Result<()> {
        // Cancel of a returned multipart step has no outstanding asynchronous
        // parent loan. The prior phase survives publication of this receipt.
        let pending_parent = self.prior == Phase::Progressable(Progress::Pending);
        let rv = fe11_sys::CK_RV::try_from(code).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignReturnCodeConversion,
            ))
        })?;
        let mut graph = None;
        {
            let mut state = self.work.work.state.lock().map_err(|_| Error::Poisoned)?;
            state.last_return = Some(NativeReturn {
                step: self.step,
                code,
            });
            if self.state != CallState::Dispatched || state.phase != Phase::Issued(self.step) {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignNativeReturnWithoutMatchingDispatch,
                )));
            }
            state.phase = match completion {
                ForeignCompletion::Pending
                    if rv == fe11_sys::CKR_PENDING
                        && self.work.work.kind == ForeignWorkKind::Operation
                        && self.work.work.access == ForeignAccess::Session =>
                {
                    Phase::Progressable(Progress::Pending)
                }
                ForeignCompletion::Continue
                    if self.step.memory_returned(code, pending_parent)
                        && self.work.work.kind != ForeignWorkKind::Session =>
                {
                    Phase::Progressable(Progress::Sequence)
                }
                ForeignCompletion::Detached
                    if self.step == ForeignStep::GetId && rv == fe11_sys::CKR_OK =>
                {
                    if self.work.work.callbacks.load(Ordering::Acquire) == 0 {
                        graph = state.graph.take();
                    }
                    Phase::Detached
                }
                ForeignCompletion::Returned if self.step.memory_returned(code, pending_parent) => {
                    if self.work.work.kind == ForeignWorkKind::Session
                        && self.step == ForeignStep::Start
                        && rv == fe11_sys::CKR_OK
                    {
                        return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                            crate::ExternalExecutionRejection::ForeignOpenSessionReceiptRequired,
                        )));
                    } else if self.work.work.kind == ForeignWorkKind::Session
                        && self.step == ForeignStep::CloseSession
                        && rv != fe11_sys::CKR_OK
                    {
                        // A failed CloseSession does not retire the session.
                        Phase::SessionOpen
                    } else {
                        if self.work.work.callbacks.load(Ordering::Acquire) == 0 {
                            graph = state.graph.take();
                        }
                        Phase::Returned
                    }
                }
                ForeignCompletion::Uncertain => Phase::Uncertain,
                _ => return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignReturnDoesNotProveDeclaredCompletion,
                ))),
            };
        }
        // Transfer this graph into a single fixed retirement slot, outside the
        // resource mutex, without running application code under native guards.
        self.retired.current = graph;
        if let Some(source) = &self.work.work.join_source {
            let mut source = source.state.lock().map_err(|_| Error::Poisoned)?;
            if source.phase == Phase::JoinReserved {
                source.phase = match completion {
                    ForeignCompletion::Returned
                        if self.step == ForeignStep::Join && rv != fe11_sys::CKR_OK =>
                    {
                        Phase::Detached
                    }
                    ForeignCompletion::Returned | ForeignCompletion::Detached => Phase::Returned,
                    ForeignCompletion::Uncertain => Phase::Uncertain,
                    _ => Phase::JoinReserved,
                };
            }
        }
        if completion == ForeignCompletion::Uncertain {
            self.work.inner.availability.mark();
        }
        if self.step == ForeignStep::CloseSession
            && rv == fe11_sys::CKR_OK
            && completion == ForeignCompletion::Returned
        {
            self.work
                .inner
                .foreign
                .retire_session(&self.work.work, &mut self.retired)?;
        }
        Ok(())
    }
}

impl Drop for ForeignCall<'_> {
    fn drop(&mut self) {
        if self.state != CallState::Recorded {
            let mut state = self
                .work
                .work
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.phase = if self.state == CallState::Prepared {
                self.prior
            } else {
                Phase::Uncertain
            };
            drop(state);
            if self.state == CallState::Dispatched {
                self.work.inner.availability.mark();
            }
            if self.step == ForeignStep::Join {
                if let Some(source) = &self.work.work.join_source {
                    let mut source = source.state.lock().unwrap_or_else(|e| e.into_inner());
                    if source.phase == Phase::JoinReserved {
                        source.phase = if self.state == CallState::Prepared {
                            Phase::Detached
                        } else {
                            Phase::Uncertain
                        };
                    }
                }
            }
        }
        drop(self.callbacks.take());
        drop(self.admission.take());
        drop(self.scope.take());
        self.work.inner.context_wakes.notify();
    }
}

/// Weak callback enrollment: storing this handle in an adapter does not form a
/// cycle through Inner. Enter it at native callback entry, before application work.
pub struct ForeignCallbackHandle {
    inner: std::sync::Weak<Inner>,
    participant: std::sync::Weak<Participant>,
    work: Option<std::sync::Weak<Work>>,
}

/// Active callback on its native thread. Drop leaves counters and wakes waiters;
/// it performs no native call. It must live until the callback is ready to return.
pub struct ForeignCallback {
    scope: Option<crate::notify::CallbackScope>,
    dispatch: Option<crate::native::dispatch::Callback>,
    inner: Arc<Inner>,
    participant: Arc<Participant>,
    work: Option<Arc<Work>>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ForeignParticipant {
    /// Callback entry for initialization/runtime state, not a session callback.
    pub fn callback_handle(&self) -> ForeignCallbackHandle {
        ForeignCallbackHandle {
            inner: Arc::downgrade(&self.inner),
            participant: Arc::downgrade(&self.participant),
            work: None,
        }
    }
}
impl ForeignWork {
    /// Callback entry tied to this exact session/operation graph.
    pub fn callback_handle(&self) -> ForeignCallbackHandle {
        ForeignCallbackHandle {
            inner: Arc::downgrade(&self.inner),
            participant: Arc::downgrade(&self.work.participant),
            work: Some(Arc::downgrade(&self.work)),
        }
    }
}
impl ForeignCallbackHandle {
    /// Enter the callback without waiting for State held by its initiating call.
    /// An error must be translated by the adapter into the callback ABI's refusal;
    /// it does not authorize accessing already retired graph state.
    pub fn enter(&self) -> Result<ForeignCallback> {
        let inner = self.inner.upgrade().ok_or(Error::Rejected(
            crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignRuntimeRetired,
            ),
        ))?;
        let participant = self.participant.upgrade().ok_or(Error::Rejected(
            crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignParticipantRetired,
            ),
        ))?;
        if participant.finalized.load(Ordering::Acquire) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignInitializationFinalized,
            )));
        }
        let work = self
            .work
            .as_ref()
            .map(|work| {
                work.upgrade()
                    .ok_or(Error::Rejected(crate::RejectionReason::ExternalExecution(
                        crate::ExternalExecutionRejection::ForeignGraphRetired,
                    )))
            })
            .transpose()?;
        let scope = crate::notify::CallbackScope::enter(
            Some(inner.foreign.image_id()),
            &inner.symmetric_budget,
        )
        .ok_or(Error::Rejected(crate::RejectionReason::ExternalExecution(
            crate::ExternalExecutionRejection::ForeignCallbackScopeAllocation,
        )))?;
        let dispatch = inner.foreign.callback_dispatch()?;
        let counter = work
            .as_ref()
            .map_or(&participant.callbacks, |work| &work.callbacks);
        let callback_admission = inner.foreign.callback_admission(work.as_ref())?;
        // Couple admission to retirement of this exact graph. Existing callbacks
        // keep it retained; no callback may enter after its terminal publication.
        let work_state = work
            .as_ref()
            .map(|work| work.state.lock().map_err(|_| Error::Poisoned))
            .transpose()?;
        if work_state.as_ref().is_some_and(|state| {
            matches!(
                state.phase,
                Phase::Prepared
                    | Phase::PreparedJoin
                    | Phase::Returned
                    | Phase::Detached
                    | Phase::JoinReserved
            )
        }) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignCallbackGraphRetired,
            )));
        }
        let mut previous = counter.load(Ordering::Acquire);
        loop {
            let entered = previous.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignCallbackCountExhausted,
                ),
            ))?;
            // Preserve checked acquisition and memory ordering on both the
            // minimum Rust version and compilers deprecating fetch_update.
            match counter.compare_exchange_weak(
                previous,
                entered,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        drop(work_state);
        drop(callback_admission);
        Ok(ForeignCallback {
            scope: Some(scope),
            dispatch,
            inner,
            participant,
            work,
            _thread: std::marker::PhantomData,
        })
    }
}
impl Drop for ForeignCallback {
    fn drop(&mut self) {
        drop(self.dispatch.take());
        drop(self.scope.take());
        let counter = self
            .work
            .as_ref()
            .map_or(&self.participant.callbacks, |work| &work.callbacks);
        counter.fetch_sub(1, Ordering::AcqRel);
        self.inner.context_wakes.notify();
    }
}
