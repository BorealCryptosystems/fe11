// SPDX-License-Identifier: Apache-2.0
use crate::{
    bounds,
    error::check,
    module::{Inner, SessionEntry, State},
    native_return::sequence::{Completion, OutputRequest},
    Error, ObjectClass, ObjectRef, Result,
};
use fe11_sys::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
pub(crate) mod activity;
mod admission_progress;
pub(crate) use admission_progress::AdmissionProgress;
mod context_authentication;
mod control_preparation;
mod legacy;
pub(crate) mod lifecycle_diagnostics;
mod pss_preparation;
mod references;
mod validation_observation;

pub(crate) use references::{ManagedReferences, ReferenceAdmission, ReferenceMode};
pub(crate) mod observation_protection;
pub(crate) mod recovery;
pub use context_authentication::ContextAuthentication;
pub(crate) use context_authentication::{
    ContextDiagnostics, ContextLoginOutcome, ContextLoginPlan, PreparedContextLogin,
};

/// Session resource. Crypto sequences serialize per session; targeted close
/// protects that session and its created objects. A failed
/// operation with uncertain state withdraws the session until explicit close.
pub struct Session {
    pub(crate) drop_behavior: SessionDropBehavior,
    pub(crate) admission: Option<crate::SessionAdmission>,
    pub(crate) entry: std::sync::Arc<SessionEntry>,
    pub(crate) inner: Arc<Inner>,
    pub(crate) uid: u64,
    pub(crate) snapshot: Arc<crate::module::TokenSnapshot>,
}
/// Caller-selected native session cleanup when its Rust owner is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDropBehavior {
    /// Attempt the existing immediate close, retaining deferred cleanup on Busy.
    Close,
    /// Do not initiate native closure or schedule it merely because of Drop.
    /// Explicit close remains the caller's responsibility. Native resources and
    /// their ledger credits stay retained until established closure; this does
    /// not detach ownership or make finalization possible with live sessions.
    KeepOpen,
}

/// Public session state without its native handle.
#[derive(Debug)]
pub struct SessionInfo {
    /// Token slot.
    pub slot: u64,
    /// PKCS#11 session state.
    pub state: u64,
    /// PKCS#11 flags.
    pub flags: u64,
    /// Public device error code.
    pub device_error: u64,
}
/// Explicit PSS parameters for the named Digest32 (SHA-256) adapter.
#[derive(Clone, Copy, Debug)]
pub struct PssParams {
    /// PKCS#11 hash mechanism identifier (CKM_SHA256 for this profile).
    pub hash: u64,
    /// Caller-selected PKCS#11 mask-generation identifier.
    pub mgf: u64,
    /// Caller-selected salt length in bytes.
    pub salt_length: usize,
}
/// Explicit SHA-256 digest input; the library does not hash it again.
pub struct Digest32([u8; 32]);

// PSS parameters and native output slots must share the stable call allocation.
// Digest32 erases its bytes on ordinary destruction; an uncompleted frame owns
// the digest and object activity for as long as native references may survive.
struct PssCall {
    parameters: CK_RSA_PKCS_PSS_PARAMS,
    mechanism: CK_MECHANISM,
    digest: Digest32,
    signature: Vec<u8>,
    length: CK_ULONG,
    _object: crate::registry::ReadPermit,
    // Keep the catalogue's weak identity alive as well as its lock state.
    _activity: Arc<crate::registry::Activity>,
    // Includes native data/frame storage and signature capacity until transfer.
    _credit: crate::symmetric::memory::Credit,
}
// SAFETY: descriptors address only this frame's owned parameters/digest/output;
// native use is confined to its stable allocation, retained until termination.
unsafe impl Send for PssCall {}

/// Native verification result; provider failures remain errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Verification {
    /// Signature verified with the explicit parameters.
    Valid,
    /// Signature value or length is invalid.
    Invalid,
}

pub(crate) enum TokenActivity<'a> {
    Shared {
        _guard: crate::admission_wait::ReadGuard<'a, ()>,
    },
    ContextAuthentication {
        _guard: crate::admission_wait::WriteGuard<'a, ()>,
    },
}
pub(crate) struct SessionAccess<'a, T = TokenActivity<'a>> {
    guards: Arc<AccessGuards<'a, T>>,
}

// Provenance is established by acquisition, never supplied by a caller.
enum AccessProvenance {
    Ordinary,
    Cleanup,
    Administrative,
    ContextAuthentication,
}

/// A borrowed capability to create an advanced owner under an ordinary access.
/// Its lifetime cannot outlive the guards which established the admission.
pub(crate) struct LeaseAdmission<'a, 'session> {
    access: &'a SessionAccess<'session>,
}

enum LocalTokenProof<'a> {
    Shared {
        _guard: &'a crate::admission_wait::ReadGuard<'a, ()>,
    },
    Exclusive {
        _guard: &'a crate::admission_wait::WriteGuard<'a, ()>,
    },
}

/// Constructed only at an access boundary after module/token/session possession.
/// It lends that possession; local maintenance must acquire none of it again.
#[derive(Clone, Copy)]
enum LocalTarget<'a> {
    Current(&'a Session),
    Retained(&'a SessionEntry),
}

pub(crate) struct LocalOwnership<'a> {
    target: LocalTarget<'a>,
    state: &'a State,
    _session: &'a crate::admission_wait::ResourceGuard<'a>,
    _token: LocalTokenProof<'a>,
}

struct AccessGuards<'a, T> {
    provenance: AccessProvenance,
    recovery_required: AtomicBool,
    // Object activity is acquired after session access and released first.
    // The short collection lock is never held across native dispatch.
    objects: std::sync::Mutex<ObjectProtections>,
    // Prepared before dispatch. Every retained child shares the same frozen
    // resource owner, without retaining the coordination mutex or its guards.
    // This fixed access cell is session coordination metadata, not a second
    // credit for its already credited object owners. Entry withdrawal prevents
    // another access after retention; Close uses its own preexisting control.
    retained_objects: Arc<RetainedObjects>,
    _session: crate::admission_wait::ResourceGuard<'a>,
    _token: T,
    state: crate::admission_wait::ReadGuard<'a, State>,
    // Unrelated snapshot owners must leave after session/token/module guards.
    revocations: std::sync::Mutex<crate::managed::RevocationRetentions>,
    // Declared last: guards must unlock before their referent owners can drop.
    // Only a call without a recorded return may retain these guards forever.
    _owners: AccessOwners,
}
struct AccessOwners {
    _entry: Arc<SessionEntry>,
    _snapshot: Arc<crate::module::TokenSnapshot>,
    _inner: Arc<Inner>,
}

// Each access owns one prepared set of resource roles. Its cardinality is
// determined by the caller, not by an inline limit or growth under possession.
// These fields are RAII owners: retaining them, rather than reading them, holds
// the exclusions until the last native frame can safely release its graph.
enum ResourceProtection {
    One {
        _permit: activity::Permission,
    },
    Roles {
        _permissions: activity::roles::Permissions,
    },
    Readers {
        _readers: activity::dynamic::DynamicReaders,
    },
    Observation {
        _protection: observation_protection::ObservationProtection,
    },
}
struct CreationProtection {
    // Release exclusive activity before releasing the destination names.
    _writers: Vec<crate::registry::WritePermit>,
    _reservation: crate::managed::DurableReservation,
}
// Field order releases resource roles before destination possession.
// Every field is populated at most once before C; nested frames share this owner.
#[derive(Default)]
struct ObjectProtections {
    resources: Option<ResourceProtection>,
    // A prepared plan may have no source objects. Retain that proof and its
    // credited storage separately so dynamic readers can still fill resources.
    // None means no such plan was admitted, not an implicit zero-source grant.
    source_free: Option<activity::roles::Permissions>,
    creation: Option<CreationProtection>,
}

/// Nested native frames share protections and one monotonic quarantine flag.
/// A boundary failure in a child also protects its parent's Init storage, even
/// if the parent was already retained with an ordinary close lifetime.
#[derive(Default)]
struct RetainedObjects {
    values: std::sync::OnceLock<ObjectProtections>,
    quarantined: AtomicBool,
}

/// An operation may retain its already acquired roles without retaining the
/// session guards or Inner. This is the same owner used by native call frames;
/// cloning it shares an exclusion and never acquires a second reader/writer.
#[derive(Clone)]
pub(crate) struct ObjectRoleLease {
    _owner: Arc<RetainedObjects>,
}

#[derive(Clone, Copy)]
pub(crate) enum CleanupAdmission {
    Ordinary,

    Token,
    Module,
}

/// Possession established only by close_entry. The two borrowed guards belong
/// to the same Entry and prevent classification racing lease release/replacement.
pub(crate) struct CloseOwnership<'a> {
    entry: &'a SessionEntry,
    _token: &'a crate::admission_wait::WriteGuard<'a, ()>,
    _session: &'a crate::admission_wait::ResourceGuard<'a>,
}

// Armed only when a native sequence is about to start. In particular, an
// unwind under a shared state lock must withdraw the session for exclusive
// operations too; poisoning only the session mutex would not do that.
/// Every sequence borrows a prepaid completion leaf.
enum SequenceDiagnostic<'a> {
    Prepared(&'a crate::error::CompletionCell),
}

pub(crate) struct Sequence<'a> {
    poison: &'a AtomicBool,
    completion: std::cell::Cell<Completion>,
    // A returned Init attempt is locally releasable without a native end proof.
    initialization_refused: std::cell::Cell<bool>,
    output_function: std::cell::Cell<Option<&'static str>>,
    context: Option<(&'a State, &'a Session)>,
    frame: Option<crate::native::frame::FrameReturn<'a>>,
    diagnostic: SequenceDiagnostic<'a>,
}

mod access;
mod advanced_access;
mod close;
mod close_admission;
pub(crate) mod close_scope;
mod context_access;
mod observation;
mod ownership;
mod preparation;
mod pss;
mod publication;
mod sequence;
pub(crate) use close::close_entry;
pub(crate) use close::reap_entries;
pub(crate) use ownership::maintain_retained_entry;
