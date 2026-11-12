// SPDX-License-Identifier: Apache-2.0

use crate::{
    admission_wait::{Attempt, Wake},
    Capabilities, Error, Result, TokenIdentity,
};
use fe11_sys::*;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
};

/// Caller-selected local session ceilings. Read/write sessions also count toward total.
/// Zero disables the corresponding openings; usize::MAX adds no ceiling below
/// the representation of the local counter. Both dimensions apply independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionLimit {
    /// Maximum across read-only and read/write sessions.
    pub total: usize,
    /// Maximum read/write sessions; zero explicitly disables them.
    pub read_write: usize,
}

/// Whether native capacity announcements participate in local admission.
/// Neither choice predicts the outcome of C_OpenSession.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnouncedSessionLimits {
    /// Use only the caller's local ceilings; let the native operation decide.
    Ignore,
    /// Also apply finite observed total/RW maxima. Unknown and infinite native
    /// values add no local ceiling; they never remove the caller's ceilings.
    IntersectWithAnnounced,
}

/// Override bound to the full observed token identity, never a provider name.
#[derive(Clone, Debug)]
pub struct TokenSessionLimit {
    /// Exact token selector to which the override applies.
    pub identity: TokenIdentity,
    /// Local ceilings for this token across all of its retained contexts.
    pub limit: SessionLimit,
}

/// Owned local admission choices, immutable after the module is opened.
/// Limits are not reservations against sessions opened by other processes.
#[derive(Clone, Debug)]
pub struct SessionPolicy {
    /// Module read/write ceiling; total remains `Limits::sessions`.
    pub module_read_write: usize,
    /// Ceiling for every token without an exact override.
    pub default_token: SessionLimit,
    /// Unique exact overrides. These may include tokens not currently present.
    pub tokens: Vec<TokenSessionLimit>,
    /// Explicit activation of the prefilter on native capacity announcements.
    pub announced_limits: AnnouncedSessionLimits,
}

/// Local reservations, including resources not currently usable.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SessionUsage {
    /// Total reserved native quota, including every state below. A zero total
    /// does not prove that retained native frames or notification payloads are
    /// gone: handle reuse can settle quota before native-lifetime proof.
    pub total: usize,
    /// Read/write resources included in total.
    pub read_write: usize,
    /// Local capacity owned before any C_OpenSession dispatch.
    pub reserved: usize,
    /// Openings entering native dispatch whose outcome is not yet published.
    pub opening: usize,
    /// Published resources; this is not a promise of token/module availability.
    pub open: usize,
    /// Closures in progress; their credits have not been released.
    pub closing: usize,
    /// Reservations captured by an explicit slot recovery.
    pub recovering: usize,
    /// Owned resources awaiting an explicit first close after Drop found them busy.
    pub deferred_close: usize,
    /// Uncertain resources retained until disappearance is established.
    pub quarantined: usize,
    /// Withdrawn synchronous owners sealed for explicit instance finalization.
    /// Their native quota remains counted until a terminal proof is published.
    pub retained_returned: usize,
}
/// Local usage for one observed token context with outstanding reservations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenResourceStatus {
    /// Full token identity associated with the reservations.
    pub identity: TokenIdentity,
    /// Local context generation, not a native handle.
    pub generation: u64,
    /// Outstanding resources for this context.
    pub usage: SessionUsage,
}
/// Bounded local snapshot; no provider call or operational secret is included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleResourceStatus {
    /// Usage across all contexts, including retired contexts with retained credits.
    pub usage: SessionUsage,
    /// Contexts with at least one outstanding reservation, sorted by generation.
    pub tokens: Vec<TokenResourceStatus>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Opening,
    Open,
    Closing,
    Recovering,
    Quarantined,
    DeferredClose,
}
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Counts {
    total: usize,
    read_write: usize,
}

// These values describe local credit settlement, not native CloseSession.
// A retained record can outlive quota settlement while its recovery owns data.
const QUOTA_UNSETTLED: u8 = 0;
const RECORD_REMOVED: u8 = 1;
const QUOTA_SETTLED_RETAINED: u8 = 2;

// Settlement evidence lives with the unique credit and any captured recovery;
// it is not an unbounded history map. Only the short ledger mutates it.
struct CreditProof {
    terminal: AtomicU8,
    ticket: AtomicU64,
    // Withdrawal is not a close receipt. Quota settlement is separately
    // recorded by terminal; this flag prevents old-handle cleanup dispatch.
    native_retired: std::sync::atomic::AtomicBool,
}
struct RecordIdentity {
    token: TokenIdentity,
    generation: u64,
    read_write: bool,
    proof: Arc<CreditProof>,
    close: CloseAttempt,
}

// Quota settlement and native lifetime are different evidence. A reused handle
// settles the old quota but keeps the original Entry, frames and Notify payload.
// Only Live has a session phase or may be selected for a new targeted close.
#[derive(Clone, Copy)]
enum HandleLoss {
    Reused,
    NativeInvalid,
    RuntimeRetired,
}

enum Record {
    Live {
        identity: RecordIdentity,
        phase: Phase,
        entry: Option<Arc<crate::module::SessionEntry>>,
    },
    RetainedWithoutHandle {
        _cause: HandleLoss,
        identity: RecordIdentity,
        entry: Arc<crate::module::SessionEntry>,
        recovery: RetentionRecovery,
    },
    RetainedReturned {
        identity: RecordIdentity,
        entry: Arc<crate::module::SessionEntry>,
        recovery: RetentionRecovery,
    },
}

#[derive(Clone, Copy)]
enum RetentionRecovery {
    AwaitingProof,
    Closing { ticket: u64 },
    Recovering { ticket: u64 },
}

// Origin and returned execution are independent of quota settlement. This
// evidence stays with the exact UID/proof through handle loss and succession.
#[derive(Clone, Copy)]
enum CloseAttempt {
    Unrecorded,
    Individual,
    Collective {
        ticket: u64,
        completion: RecoveryCompletion,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryCompletion {
    NotDispatched,
    Returned { closed: bool },
    Unproven,
}

impl RecoveryCompletion {
    pub(crate) fn return_known(self) -> bool {
        !matches!(self, Self::Unproven)
    }
}

struct Captured {
    uid: u64,
    proof: Arc<CreditProof>,
    entry: Option<Arc<crate::module::SessionEntry>>,
}
pub(crate) struct RecoveryBatch {
    ticket: u64,
    items: Vec<Captured>,
    removed: Vec<Record>,
    active: bool,
    started: bool,
}

#[derive(Clone, Copy, Default)]
enum ReservationAdmission {
    #[default]
    Open,
    Sealed,
}

#[derive(Default)]
struct LedgerState {
    admission: ReservationAdmission,
    next_uid: u64,
    next_ticket: u64,
    total: Counts,
    tokens: HashMap<TokenIdentity, Counts>,
    records: HashMap<u64, Record>,
}
/// A candidate retains only an Arc control block, never a notification handler.
pub(crate) struct LocalCandidate {
    uid: u64,
    entry: Weak<crate::module::SessionEntry>,
    pub(crate) blocked: bool,
}

pub(crate) struct SessionLedger {
    // Predecessors are sealed before linkage. Their counts can only decrease;
    // they keep credits and owners without participating in successor dispatch.
    // The link may skip only a permanently empty ledger. Lock nesting follows
    // generations strictly backwards, never from an ancestor to its successor.
    predecessor: Mutex<Option<Arc<SessionLedger>>>,
    wake: Arc<Wake>,
    state: Mutex<LedgerState>,
    module: SessionLimit,
}

/// Short, allocation-free view used under the token writer for Logout.
/// The only nested inspections are recovery metadata and the advanced ledger;
/// they must not dispatch, mutate session accounting or call application code.
pub(crate) struct LogoutEntries<'a> {
    state: std::sync::MutexGuard<'a, LedgerState>,
    domain: &'a Arc<crate::module::SlotDomain>,
}

pub(crate) struct SessionSeal<'a> {
    ledger: &'a SessionLedger,
    previous: ReservationAdmission,
    committed: bool,
}

/// Owns extracted entries after Finalize. Declare outside module possession so
/// frame/notification/close-reservation destructors cannot reenter its writer.
pub(crate) struct FinalizedSessions {
    records: HashMap<u64, Record>,
    image: Arc<crate::native::image::LoadedImage>,
    quarantined: bool,
}

/// Declare before registry guards so error/unwind exits notify after unlocking.
pub(crate) struct AdmissionChange<'a>(&'a SessionLedger);

// A credit is never cloned. Dropping before dispatch rolls back; after dispatch
// only an explicit proof of non-creation/disappearance permits release.
pub(crate) struct SessionCredit {
    ledger: Weak<SessionLedger>,
    uid: u64,
    proof: Arc<CreditProof>,
    dispatched: bool,
    client: crate::module::ClientId,
}

mod access;
mod close;
mod collective;
mod finalization;
mod policy;
mod record;
mod recovery;
mod reservation;
mod selection;
mod status;
