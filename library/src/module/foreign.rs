// SPDX-License-Identifier: Apache-2.0
//! Participation of an unsafe native adapter in the shared runtime.
//!
//! Fe11 coordinates admission and retains opaque owners. It does not inspect
//! foreign buffers or call application-supplied function pointers. The adapter
//! remains responsible for faithfully describing its native calls and proofs.

mod call;
mod call_scope;
mod event;
mod registry;
pub use call::{ForeignCall, ForeignCallback, ForeignCallbackHandle};
pub use event::ForeignEvent;
pub(crate) use registry::Registry;
pub(crate) use registry::Retired;

use super::{ClientId, Inner, RuntimeOwner, SlotDomain};
use crate::{Error, Result};
use std::sync::{Arc, Mutex};

/// Native scope of a registered foreign resource. The handle is diagnostic
/// identity inside this runtime, not permission to access a Fe11-owned session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignScope {
    /// Functions that do not access a token/session, such as C_GetInfo.
    Module,
    /// A token/slot function or an OpenSession before its handle is available.
    Slot(u64),
    /// A session privately owned by this participant.
    Session {
        /// Native slot identifier for this private session.
        slot: u64,
        /// Native handle, used only within this initialization.
        handle: u64,
    },
}
impl ForeignScope {
    pub(super) fn slot(self) -> Option<u64> {
        match self {
            Self::Module => None,
            Self::Slot(slot) | Self::Session { slot, .. } => Some(slot),
        }
    }
}

/// Purpose of the graph retained by a ForeignWork. These are lifetime contracts,
/// not a substitute for the native operation's actual return code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignWorkKind {
    /// An ordinary native call. Use prepare_session_open for C_OpenSession so
    /// its callback graph is registered before native dispatch.
    Call,
    /// A live native session and its callback/application owner.
    Session,
    /// An operation whose buffers may survive a returned CKR_PENDING or a
    /// multipart continuation. Progress refers to this same retained graph.
    /// The adapter declares that successful CloseSession/CloseAllSessions ends
    /// these session-associated loans under the applicable PKCS#11 contract.
    Operation,
}

/// Whether this call uses a private session or changes token-wide state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignAccess {
    /// Ordinary work on a distinct session, sharing the token's activity gate.
    Session,
    /// Token-wide action such as Login/Logout, using the token writer. Finalize,
    /// CloseAllSessions and InitToken still belong to RuntimeOwner exclusively.
    Token,
}

/// A requested step for the exact registered graph. The unsafe adapter must
/// invoke only the corresponding native action while holding its call permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignStep {
    /// Initial call, before any native use of this operation's graph.
    Start,
    /// Continue an already admitted multipart operation.
    Continue,
    /// Obtain native completion of an asynchronous operation.
    Complete,
    /// Explicitly cancel the registered operation according to its native API.
    Cancel,
    /// C_AsyncGetID for this source; success may return its old buffers.
    GetId,
    /// C_AsyncJoin, with a new graph bound to its detached source.
    Join,
    /// C_CloseSession for the registered Session resource.
    CloseSession,
}

impl ForeignStep {
    fn controls_parent(self, pending_parent: bool) -> bool {
        matches!(self, Self::Complete | Self::GetId | Self::Join)
            || self == Self::Cancel && pending_parent
    }

    fn memory_returned(self, code: u64, pending_parent: bool) -> bool {
        if self.controls_parent(pending_parent) {
            crate::native_return::async_memory_returned(code)
        } else {
            crate::native_return::diagnostic_memory_returned(code)
        }
    }

    fn context_scope(self, code: u64, pending_parent: bool) -> crate::native_return::FailureScope {
        if !self.memory_returned(code, pending_parent) {
            crate::native_return::FailureScope::Module
        } else {
            crate::native_return::diagnostic_context_scope(code)
        }
    }
}

/// Interpretation supplied by the unsafe adapter after a real native return.
/// The recorder checks code/step consistency; the adapter must establish the
/// stronger, function-specific memory proof described by each variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignCompletion {
    /// This entire registered graph is no longer borrowed by native code.
    Returned,
    /// CKR_PENDING: all graph referents remain live and a native completion,
    /// cancellation or other declared continuation can make progress.
    Pending,
    /// The step returned but the registered operation still owns its graph.
    /// The adapter may retire only its own sub-buffers with independent proof.
    Continue,
    /// C_AsyncGetID succeeded: the old borrowed buffers have been returned,
    /// while the detached job persists independently of this initialization.
    Detached,
    /// No valid termination/progression contract can currently be established.
    /// This retains the graph and withdraws the runtime; it is not completion.
    Uncertain,
}

/// Native execution state of an existing operation declared during attachment.
/// This describes the last real return; it cannot certify the end of a loan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForeignProgress {
    /// CKR_PENDING was actually returned for this registered operation.
    Pending,
    /// A multipart step returned; the sequence and its graph remain live.
    Sequence,
}

/// Exact native return plus any local recording failure. A local failure never
/// overwrites the code or claims that the native invocation did not occur.
pub struct ForeignReceipt {
    /// Exact code supplied by the adapter for its actual native invocation.
    pub code: u64,
    /// Whether the graph/phase transition was recorded successfully.
    pub publication: Result<()>,
}

/// Stable key for an adapter's argument-owner map, unique within this runtime.
/// It is not a native handle or authority transferable to another runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ForeignWorkId(u64);

#[derive(Clone, Copy)]
struct NativeReturn {
    step: ForeignStep,
    code: u64,
}

/// Local foreign-resource inventory. Counts describe registered participants,
/// never every session or job held by the native provider or other processes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForeignStatus {
    /// Adapters retained by this runtime.
    pub participants: usize,
    /// Registered live native sessions.
    pub sessions: usize,
    /// Operations with an explicit progress owner.
    pub progressable: usize,
    /// Graphs without a sufficient native termination proof.
    pub uncertain: usize,
    /// Callback bodies entered through the adapter protocol.
    pub callbacks: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Sequence,
    Pending,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prepared,
    PreparedJoin,
    Reserved(ForeignStep),
    Issued(ForeignStep),
    Progressable(Progress),
    SessionOpen,
    Detached,
    JoinReserved,
    Returned,
    Uncertain,
}

struct Participant {
    id: ClientId,
    image: Arc<crate::native::image::LoadedImage>,
    // Independent of Inner: callbacks and quarantined records must never form
    // an ownership cycle back through the runtime registry.
    owner: Mutex<Option<Box<dyn Send + Sync>>>,
    finalized: std::sync::atomic::AtomicBool,
    callbacks: std::sync::atomic::AtomicUsize,
    untracked: Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for Participant {
    fn drop(&mut self) {
        let owner = self
            .owner
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if !self.finalized.load(std::sync::atomic::Ordering::Acquire) {
            if let Some(owner) = owner {
                std::mem::forget(owner);
            }
        } else {
            drop(owner);
        }
    }
}

struct WorkState {
    phase: Phase,
    last_return: Option<NativeReturn>,
    graph: Option<Box<dyn Send + Sync>>,
}

struct Work {
    native_retired: std::sync::atomic::AtomicBool,
    token_epoch: Option<u64>,
    id: ForeignWorkId,
    participant: Arc<Participant>,
    kind: ForeignWorkKind,
    scope: ForeignScope,
    // Set under original admission by OpenSession's receipt, without replacing
    // the callback owner or leaving an unregistered interval.
    session_handle: std::sync::atomic::AtomicU64,
    access: ForeignAccess,
    domain: Option<Arc<SlotDomain>>,
    state: Mutex<WorkState>,
    // Session serialization is shared by child operations. Owning a work does
    // not make its session concurrently callable, even in Concurrent mode.
    session: Option<Arc<Work>>,
    join_source: Option<Arc<Work>>,
    gate: crate::admission_wait::ResourceGate,
    held: std::sync::atomic::AtomicBool,
    callbacks: std::sync::atomic::AtomicUsize,
}

impl ForeignParticipant {
    /// Register a previously admitted foreign operation during quiescent
    /// integration. No new native operation is issued.
    ///
    /// # Safety
    /// The session, graph and native execution must be exact and private to
    /// this participant. step/last_return/progress must describe the real most recent
    /// native invocation, which has returned. Retain every outstanding referent.
    /// All other clients must remain quiescent until adoption is complete. The
    /// kind Operation additionally declares the session-closure proof documented
    /// on ForeignWorkKind. Failed adoption retains native-owned code and data.
    /// Pending requires this native session/operation's supported asynchronous
    /// protocol and a completion path for this exact graph; it cannot describe
    /// an unexpected pending from an ordinary synchronous invocation.
    /// Sequence requires every earlier asynchronous loan to have returned;
    /// a refused cancellation of a pending parent cannot establish Sequence.
    pub unsafe fn adopt_operation<T: Send + Sync + 'static>(
        &self,
        session: &ForeignWork,
        kind: ForeignWorkKind,
        access: ForeignAccess,
        progress: ForeignProgress,
        step: ForeignStep,
        last_return: u64,
        owner: T,
    ) -> Result<ForeignWork> {
        let mut unpublished = UnpublishedGraph {
            graph: Some(Box::new(owner)),
            participant: self.participant.clone(),
            native: true,
        };
        if !Arc::ptr_eq(&self.inner, &session.inner)
            || !Arc::ptr_eq(&self.participant, &session.work.participant)
            || session.work.kind != ForeignWorkKind::Session
            || kind == ForeignWorkKind::Session
        {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignOperationSessionMismatch,
            )));
        }
        let rv = fe11_sys::CK_RV::try_from(last_return).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignReturnCodeConversion,
            ))
        })?;
        let phase = match progress {
            ForeignProgress::Pending
                if rv == fe11_sys::CKR_PENDING
                    && kind == ForeignWorkKind::Operation
                    && access == ForeignAccess::Session =>
            {
                Progress::Pending
            }
            ForeignProgress::Sequence if step.memory_returned(last_return, false) => {
                Progress::Sequence
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignAdoptedProgressMismatch,
                )))
            }
        };
        // This local guard was constructed with Some(graph). Validation above
        // neither borrows it to other owners nor takes it; the only transfer is
        // into register_work, whose unpublished guard preserves failed adoption.
        let work = self.register_work(
            session.work.scope(),
            kind,
            access,
            Some(session.work.clone()),
            Phase::Progressable(phase),
            unpublished.graph.take().expect("adopted graph"),
            None,
            call::AdmissionMode::Ordinary,
        )?;
        work.work
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .last_return = Some(NativeReturn {
            step,
            code: last_return,
        });
        Ok(work)
    }

    /// Prepare session opening and its callback/application graph before native
    /// dispatch. Complete the invocation with ForeignCall::opened.
    ///
    /// # Safety
    /// owner must retain pApplication, callbacks, pSession and every native
    /// referent at stable addresses. Invoke only C_OpenSession on this slot;
    /// the owner must not close the session in its destructor.
    pub unsafe fn prepare_session_open<T: Send + Sync + 'static>(
        &self,
        slot: u64,
        owner: T,
    ) -> Result<ForeignWork> {
        self.register_work(
            ForeignScope::Slot(slot),
            ForeignWorkKind::Session,
            ForeignAccess::Token,
            None,
            Phase::Prepared,
            Box::new(owner),
            None,
            call::AdmissionMode::Ordinary,
        )
    }

    /// Register an existing, quiescent native session owned by this adapter.
    /// No native call occurs and the session is not entered in Fe11's ledger.
    ///
    /// # Safety
    /// The exact handle must be live in this initialization and on this slot,
    /// privately owned by this participant. No call may be in flight and any
    /// retained operation must be registered before releasing integration's
    /// quiescence. `owner` must retain all session callback/application data at
    /// stable addresses. It must not close/finalize the native owner in Drop.
    pub unsafe fn adopt_session<T: Send + Sync + 'static>(
        &self,
        slot: u64,
        handle: u64,
        owner: T,
    ) -> Result<ForeignWork> {
        self.register_work(
            ForeignScope::Session { slot, handle },
            ForeignWorkKind::Session,
            ForeignAccess::Token,
            None,
            Phase::SessionOpen,
            Box::new(owner),
            None,
            call::AdmissionMode::Ordinary,
        )
    }

    /// Prepare an ordinary module/slot call and retain its entire argument graph.
    /// The later call permit must be marked dispatched before entering C.
    ///
    /// # Safety
    /// The scope must describe every token touched by the actual call. Module
    /// scope cannot be used for a token/session call. Use prepare_operation for
    /// an already registered session, and prepare_session_open for OpenSession.
    /// The owner must keep every borrowed native
    /// address stable until a function-specific termination proof is recorded.
    /// No global lifecycle action may be issued through this ordinary permit.
    pub unsafe fn prepare_call<T: Send + Sync + 'static>(
        &self,
        scope: ForeignScope,
        owner: T,
    ) -> Result<ForeignWork> {
        if matches!(scope, ForeignScope::Session { .. }) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignSessionOwnerRequired,
            )));
        }
        self.register_work(
            scope,
            ForeignWorkKind::Call,
            ForeignAccess::Token,
            None,
            Phase::Prepared,
            Box::new(owner),
            None,
            call::AdmissionMode::Ordinary,
        )
    }

    /// Prepare a graph on this participant's exact registered session.
    /// This permits native refusals such as OPERATION_ACTIVE; it does not claim
    /// that another already initialized sequence is absent from the module.
    ///
    /// # Safety
    /// The graph/lifetime contract of prepare_call applies. `access` must declare
    /// token-wide effects; kind Operation additionally declares that successful
    /// native session closure terminates every loan in this graph. Use Call when
    /// that collective-closure proof does not apply. Never pass Session as kind.
    /// C_CloseSession must use the session work's CloseSession step; OpenSession
    /// uses prepare_session_open. Finalize, CloseAllSessions and InitToken remain
    /// the runtime owner's global actions, never ordinary adapter calls.
    pub unsafe fn prepare_operation<T: Send + Sync + 'static>(
        &self,
        session: &ForeignWork,
        kind: ForeignWorkKind,
        access: ForeignAccess,
        owner: T,
    ) -> Result<ForeignWork> {
        if !Arc::ptr_eq(&self.inner, &session.inner)
            || !Arc::ptr_eq(&self.participant, &session.work.participant)
            || session.work.kind != ForeignWorkKind::Session
            || kind == ForeignWorkKind::Session
        {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignOperationSessionMismatch,
            )));
        }
        self.register_work(
            session.work.scope(),
            kind,
            access,
            Some(session.work.clone()),
            Phase::Prepared,
            Box::new(owner),
            None,
            call::AdmissionMode::Ordinary,
        )
    }

    /// Prepare a new Join loan tied to a successful GetID source. The source is
    /// claimed at dispatch admission, so two preparations cannot join it twice.
    ///
    /// # Safety
    /// owner must retain the new Join arguments, including the exact identifier
    /// returned by source's GetID and valid destination buffers. This is a new
    /// loan: the earlier GetID does not prove its completion. The destination
    /// session must be valid for that job under the native contract.
    pub unsafe fn prepare_join<T: Send + Sync + 'static>(
        &self,
        source: &ForeignWork,
        session: &ForeignWork,
        owner: T,
    ) -> Result<ForeignWork> {
        self.prepare_join_admitted(
            source,
            session,
            Box::new(owner),
            call::AdmissionMode::Ordinary,
        )
    }

    fn prepare_join_admitted(
        &self,
        source: &ForeignWork,
        session: &ForeignWork,
        owner: Box<dyn Send + Sync>,
        mode: call::AdmissionMode,
    ) -> Result<ForeignWork> {
        if !Arc::ptr_eq(&self.inner, &source.inner)
            || !Arc::ptr_eq(&self.inner, &session.inner)
            || !Arc::ptr_eq(&self.participant, &source.work.participant)
            || !Arc::ptr_eq(&self.participant, &session.work.participant)
            || session.work.kind != ForeignWorkKind::Session
        {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignJoinOwnerMismatch,
            )));
        }
        if source.work.state.lock().map_err(|_| Error::Poisoned)?.phase != Phase::Detached {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignJoinSourceNotDetached,
            )));
        }
        self.register_work(
            session.work.scope(),
            ForeignWorkKind::Operation,
            ForeignAccess::Session,
            Some(session.work.clone()),
            Phase::PreparedJoin,
            owner,
            Some(source.work.clone()),
            mode,
        )
    }

    fn register_work(
        &self,
        scope: ForeignScope,
        kind: ForeignWorkKind,
        access: ForeignAccess,
        session: Option<Arc<Work>>,
        phase: Phase,
        graph: Box<dyn Send + Sync>,
        join_source: Option<Arc<Work>>,
        mode: call::AdmissionMode,
    ) -> Result<ForeignWork> {
        // An adopted session already borrows its graph, even if registration
        // fails. Preserve its code and data instead of running their destructor.
        let mut unpublished = UnpublishedGraph {
            graph: Some(graph),
            participant: self.participant.clone(),
            native: matches!(phase, Phase::SessionOpen | Phase::Progressable(_)),
        };
        self.inner.check_lifecycle_reentry()?;
        if let ForeignScope::Session { handle, .. } = scope {
            let handle = fe11_sys::CK_SESSION_HANDLE::try_from(handle).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignSessionHandleConversion,
                ))
            })?;
            if handle == fe11_sys::CK_INVALID_HANDLE {
                return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                    crate::ExternalExecutionRejection::ForeignSessionHandleInvalid,
                )));
            }
        }
        let domain = scope
            .slot()
            .map(|slot| self.inner.foreign.domain(slot))
            .transpose()?;
        let work = Arc::new(Work {
            native_retired: std::sync::atomic::AtomicBool::new(false),
            token_epoch: domain.as_ref().map(|domain| {
                domain
                    .foreign_epoch
                    .load(std::sync::atomic::Ordering::Acquire)
            }),
            id: ForeignWorkId(ClientId::allocate(&self.inner.next_client)?.value()),
            participant: self.participant.clone(),
            kind,
            scope,
            access,
            domain,
            session_handle: std::sync::atomic::AtomicU64::new(match scope {
                ForeignScope::Session { handle, .. } if kind == ForeignWorkKind::Session => handle,
                _ => 0,
            }),
            state: Mutex::new(WorkState {
                phase,
                last_return: None,
                graph: unpublished.graph.take(),
            }),
            session,
            join_source,
            gate: crate::admission_wait::ResourceGate::new(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::ForeignSessionActivity,
            )),
            held: std::sync::atomic::AtomicBool::new(true),
            callbacks: std::sync::atomic::AtomicUsize::new(0),
        });
        let admission = call::admit(
            &self.inner,
            work.domain.as_deref(),
            None,
            ForeignAccess::Session,
            mode,
        )?;
        self.inner.foreign.check_session(&work)?;
        self.inner.foreign.publish(&work)?;
        drop(admission);
        Ok(ForeignWork {
            inner: self.inner.clone(),
            work,
        })
    }

    /// Reacquire one progress capability relinquished by this participant.
    /// No native call, cancellation or graph release is performed.
    pub fn take_abandoned_work(&self) -> Result<Option<ForeignWork>> {
        self.inner.foreign.abandoned(&self.participant).map(|work| {
            work.map(|work| ForeignWork {
                inner: self.inner.clone(),
                work,
            })
        })
    }
}

impl ForeignWork {
    /// Recover the exact typed argument owner in the adapter's own map, including
    /// when this capability is obtained through take_abandoned_work.
    pub fn id(&self) -> ForeignWorkId {
        self.work.id
    }

    /// Step corresponding to last_native_return, never an inferred native call.
    pub fn last_native_step(&self) -> Result<Option<ForeignStep>> {
        Ok(self
            .work
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .last_return
            .map(|value| value.step))
    }

    /// Scope registered at creation; this is not a current native-state query.
    pub fn scope(&self) -> ForeignScope {
        self.work.scope()
    }

    /// Last real code supplied to the recorder, including publication failures.
    pub fn last_native_return(&self) -> Result<Option<u64>> {
        Ok(self
            .work
            .state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .last_return
            .map(|value| value.code))
    }
}

impl Work {
    // Session work is constructed only by prepare_session_open/adopt_session,
    // both with a slot. scope/kind never change; publishing a native handle
    // cannot remove that slot or its domain. Other work preserves its scope.
    fn scope(&self) -> ForeignScope {
        let handle = self
            .session_handle
            .load(std::sync::atomic::Ordering::Acquire);
        if self.kind == ForeignWorkKind::Session && handle != 0 {
            ForeignScope::Session {
                slot: self.scope.slot().expect("session slot"),
                handle,
            }
        } else {
            self.scope
        }
    }
}

struct UnpublishedGraph {
    graph: Option<Box<dyn Send + Sync>>,
    participant: Arc<Participant>,
    native: bool,
}
impl Drop for UnpublishedGraph {
    fn drop(&mut self) {
        if self.native {
            if let Some(graph) = self.graph.take() {
                self.participant
                    .untracked
                    .store(true, std::sync::atomic::Ordering::Release);
                std::mem::forget(graph);
                std::mem::forget(self.participant.clone());
            }
        }
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        let graph = state.graph.take();
        if !matches!(
            state.phase,
            Phase::Prepared
                | Phase::PreparedJoin
                | Phase::Returned
                | Phase::Detached
                | Phase::JoinReserved
        ) {
            // Keep the code/initialization graph too, even if another successful
            // lifecycle receipt could otherwise let its image lease unload.
            std::mem::forget(self.participant.clone());
            self.participant
                .untracked
                .store(true, std::sync::atomic::Ordering::Release);
            if let Some(graph) = graph {
                std::mem::forget(graph);
            }
        } else {
            drop(graph);
        }
    }
}

/// A native adapter enrolled in one runtime. It is not Clone; callback handles
/// use weak links, and each registered work retains its own participant.
pub struct ForeignParticipant {
    inner: Arc<Inner>,
    participant: Arc<Participant>,
}

/// Unique progress capability for a foreign graph. Dropping it does not cancel
/// native work. Pending/uncertain graphs remain anchored in the runtime registry.
pub struct ForeignWork {
    inner: Arc<Inner>,
    work: Arc<Work>,
}

impl Drop for ForeignWork {
    fn drop(&mut self) {
        self.work
            .held
            .store(false, std::sync::atomic::Ordering::Release);
        self.inner.context_wakes.notify();
    }
}

impl RuntimeOwner {
    /// Register a foreign adapter in this same initialization and dispatch domain.
    /// No foreign native function is invoked and no new initialization occurs.
    ///
    /// # Safety
    /// The owner must retain all foreign code/state required until finalization.
    /// Every foreign call and callback must use a matching runtime permit; every
    /// pending argument graph must remain owned by its registered ForeignWork.
    /// Global actions go through this RuntimeOwner. No other library destructor
    /// may finalize or unload it. Register existing sessions before distributing
    /// clients or invoking ordinary/global actions through the owner. No callback
    /// may originate outside an admitted native invocation, its registered pending
    /// work, or the coordinated lifecycle function itself. Use weak callback
    /// handles to avoid cycles through this registry. Opaque owner destructors
    /// must not call native lifecycle functions or retain strong client cycles.
    pub unsafe fn register_foreign<T: Send + Sync + 'static>(
        &self,
        owner: T,
    ) -> Result<ForeignParticipant> {
        self.module()
            .inner
            .foreign
            .register(&self.module().inner, Box::new(owner))
    }

    /// Inspect registered foreign ownership without querying the native module.
    pub fn foreign_status(&self) -> Result<ForeignStatus> {
        self.module().inner.foreign.status()
    }

    /// Release completed foreign argument graphs and retired records outside
    /// native and local guards. Returns the number of argument graphs released.
    /// This never cancels pending work or calls the native module. Invoke this
    /// after callbacks leave when their graph could not be released at return.
    pub fn collect_foreign(&self) -> Result<usize> {
        self.module().inner.check_lifecycle_reentry()?;
        self.module().inner.foreign.collect_completed()
    }
}

impl Inner {
    pub(crate) fn check_lifecycle_reentry(&self) -> Result<()> {
        let image = self.foreign.image_id();
        if crate::notify::in_callback_for(image) || call::in_call(image) {
            return Err(Error::Busy(crate::BusyReason::ExternalExecution(
                crate::ExternalExecutionBusy::NativeLifecycleReentry,
            )));
        }
        Ok(())
    }
}

impl super::ModuleDrain {
    /// Prepare only a Join linked to an already detached foreign source.
    ///
    /// # Safety
    /// The adapter must satisfy ForeignParticipant::prepare_join's contract.
    pub unsafe fn prepare_foreign_join<T: Send + Sync + 'static>(
        &self,
        participant: &ForeignParticipant,
        source: &ForeignWork,
        session: &ForeignWork,
        owner: T,
    ) -> Result<ForeignWork> {
        if !Arc::ptr_eq(&self.inner, &participant.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignDrainingRuntime,
            )));
        }
        participant.prepare_join_admitted(
            source,
            session,
            Box::new(owner),
            call::AdmissionMode::Module,
        )
    }
    /// Progress an exact previously admitted foreign graph while draining.
    pub fn begin_foreign<'a>(
        &'a self,
        work: &'a mut ForeignWork,
        step: ForeignStep,
    ) -> Result<ForeignCall<'a>> {
        if !Arc::ptr_eq(&self.inner, &work.inner) {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignDrainingRuntime,
            )));
        }
        work.begin_admitted(step, call::AdmissionMode::Module)
    }
}

impl super::TokenDrain {
    /// Prepare a new Join loan on this drained slot for an existing detached job.
    ///
    /// # Safety
    /// The adapter must satisfy ForeignParticipant::prepare_join's contract.
    pub unsafe fn prepare_foreign_join<T: Send + Sync + 'static>(
        &self,
        participant: &ForeignParticipant,
        source: &ForeignWork,
        session: &ForeignWork,
        owner: T,
    ) -> Result<ForeignWork> {
        if !Arc::ptr_eq(&self.context.inner, &participant.inner)
            || !session
                .work
                .domain
                .as_ref()
                .is_some_and(|domain| Arc::ptr_eq(domain, &self.context.snapshot.domain))
        {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignDrainingSlot,
            )));
        }
        participant.prepare_join_admitted(
            source,
            session,
            Box::new(owner),
            call::AdmissionMode::Token,
        )
    }
    /// Progress a graph on this drained slot; other slots remain independent.
    pub fn begin_foreign<'a>(
        &'a self,
        work: &'a mut ForeignWork,
        step: ForeignStep,
    ) -> Result<ForeignCall<'a>> {
        if !Arc::ptr_eq(&self.context.inner, &work.inner)
            || !work
                .work
                .domain
                .as_ref()
                .is_some_and(|domain| Arc::ptr_eq(domain, &self.context.snapshot.domain))
        {
            return Err(Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignDrainingSlot,
            )));
        }
        work.begin_admitted(step, call::AdmissionMode::Token)
    }
}
