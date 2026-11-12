// SPDX-License-Identifier: Apache-2.0
use crate::atomic_update::AtomicUpdate;
mod authentication;
mod external_initialization;
pub(crate) mod foreign;

pub use external_initialization::{
    ExternalConcurrency, ExternalInitialization, ExternalModuleIdentity,
};
pub use foreign::{
    ForeignAccess, ForeignCall, ForeignCallback, ForeignCallbackHandle, ForeignCompletion,
    ForeignEvent, ForeignParticipant, ForeignProgress, ForeignReceipt, ForeignScope, ForeignStatus,
    ForeignStep, ForeignWork, ForeignWorkId, ForeignWorkKind,
};
mod integrity;
mod loader;
mod loader_observations;
mod local_maintenance;
mod observations;
mod runtime;
use crate::{bounds, error::check, native::Native, Error, Result, SecretPin};
use fe11_sys::*;
pub use integrity::{
    ModuleDigestMismatch, ModuleDigestObservation, ModuleIntegrity, ModuleIntegrityReport,
};
pub use loader::{
    WindowsDependencySearch, WindowsFilePinning, WindowsFilePinningReport, WindowsImageConsistency,
    WindowsImageConsistencyReport, WindowsReparseHandling,
};
pub use loader_observations::{
    WindowsActivationAssembly, WindowsActivationContext, WindowsActivationFile,
    WindowsLoaderChannel, WindowsLoaderObservation, WindowsLoaderObservationLimits,
    WindowsLoaderObservations, WindowsLoaderPath, WindowsLoaderPathKind,
    WindowsLoaderRegistryValue, WindowsLoaderReport, WindowsLoaderRequest, WindowsLoaderRequests,
    WindowsLoaderSearchDirectories, WindowsLoaderUnavailable,
};
pub use observations::{NativeLibraryInfo, NativeSlotInfo, NativeTokenInfo};
pub(crate) use runtime::ClientId;
use runtime::LifecycleAccess;
pub use runtime::RuntimeOwner;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::SystemTime,
};

pub(crate) mod initialization;
pub use initialization::{
    InitializationMutexFunctions, InitializationMutexes, InitializationReserved,
};
pub(crate) mod provenance;
pub use provenance::{ModuleFileObservation, ModuleProvenance};
mod configuration;
pub use configuration::{
    InitializationOptions, ModuleBuilder, ModuleOptions, NativeConcurrency, ObjectLimits,
};

/// Caller-selected discovery and resource ceilings, without an implicit policy.
/// Zero forbids positive consumption; usize::MAX adds no lower policy ceiling.
/// Allocation and ABI representation can still limit an individual request.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum slots per enumeration, whether token-present or unfiltered.
    pub slots: usize,
    /// Maximum mechanisms per token.
    pub mechanisms: usize,
    /// Maximum sizing/fill attempts per slot or mechanism enumeration.
    /// Zero prevents enumeration. A size-change retry consumes another attempt.
    pub discovery_attempts: usize,
    /// Maximum sessions across this module, including opening and uncertain resources.
    pub sessions: usize,
}
/// Explicit trusted module selection. Native modules execute inside this process.
pub struct ModuleConfig {
    /// Absolute module path. No implicit search is performed.
    pub path: PathBuf,
    /// Explicit comparison of the observed module-file identity.
    pub integrity: ModuleIntegrity,
    /// Resource ceilings.
    pub limits: Limits,
}
/// Observed public token identity, with fixed-width PKCS#11 bytes preserved.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenIdentity {
    /// Slot identifier (not an object handle).
    pub slot: u64,
    /// Space-padded manufacturer field.
    pub manufacturer: [u8; 32],
    /// Space-padded model field.
    pub model: [u8; 16],
    /// Space-padded serial number field.
    pub serial: [u8; 16],
}
/// Announced mechanism properties; announcement is not parameter qualification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismInfo {
    /// Minimum key size in the mechanism's PKCS#11 units.
    pub minimum: u64,
    /// Maximum key size in the mechanism's PKCS#11 units.
    pub maximum: u64,
    /// Public CKF bit flags.
    pub flags: u64,
}
/// Immutable discovery snapshot. Operations consult it without native rediscovery.
/// It describes the completed discovery, not current token-wide state. External
/// changes need not be signalled; refresh is explicit and never rebinds old owners.
#[derive(Clone, Debug)]
pub struct Capabilities {
    /// Token identity bound to this snapshot.
    pub identity: TokenIdentity,
    /// Observed token label; never automatically logged.
    pub label: [u8; 32],
    /// Native token flags.
    pub flags: u64,
    /// Observed minimum PIN length, in bytes.
    pub minimum_pin_length: u64,
    /// Observed maximum PIN length, in bytes; unavailable values remain explicit.
    pub maximum_pin_length: u64,
    /// Announced total-session maximum; PKCS#11 sentinel values remain explicit.
    pub maximum_sessions: u64,
    /// Announced read/write-session maximum; sentinel values remain explicit.
    pub maximum_read_write_sessions: u64,
    /// Slot description.
    pub slot_description: [u8; 64],
    /// Advertised mechanism observations, including local native refusals.
    pub mechanisms: crate::MechanismCatalog,
    /// Time of discovery in this process.
    pub observed_at: SystemTime,
}
/// Public module information from C_GetInfo and verified file provenance.
#[derive(Clone, Debug)]
pub struct ModuleInfo {
    /// File loading or process-scope loading, with actual file observations.
    pub provenance: ModuleProvenance,
    /// Whether the table-selection exports were observed in that file's mapping.
    /// NotRequested is not a successful identity comparison; dependencies and
    /// code trust are outside this observation on every platform.
    pub export_file_identity: crate::Observation<bool>,
    /// Selected Windows file/ancestor retention and its independent observation.
    pub windows_file_pinning: WindowsFilePinningReport,
    /// Exact local directory-search selection; not an observation of dependencies.
    pub windows_dependency_search: WindowsDependencySearch,
    /// Exact per-channel requirements and resource limits for this load.
    pub windows_loader_observations: WindowsLoaderObservations,
    /// Dated pre-load observations; unavailable is never interpreted as absent.
    pub windows_loader_report: WindowsLoaderReport,
    /// Explicit post-load comparison; never a guarantee about native initializers.
    pub windows_image_consistency: WindowsImageConsistencyReport,
    /// Reported Cryptoki version from C_GetInfo, retained without normalization.
    /// Compatibility policy belongs to the caller; dispatch uses function_list_version.
    pub interface_version: (u8, u8),
    /// Function table actually consumed, independently checked before layout access.
    pub function_list_version: (u8, u8),
    /// Flags returned for the selected interface (zero for historical loading).
    pub interface_flags: u64,
    /// Presence in the selected table, independently of API or mechanism support.
    pub functions: crate::FunctionCatalog,
    /// Reported implementation version.
    pub library_version: (u8, u8),
    /// Fixed-width public manufacturer bytes.
    pub manufacturer: [u8; 32],
    /// Fixed-width public description bytes.
    pub description: [u8; 32],
}
/// Module view, either its lifecycle owner or an ordinary shared client.
/// This type is deliberately not Clone. Shared clients are created explicitly
/// through RuntimeOwner and do not acquire global lifecycle authority.
pub struct Module {
    pub(crate) inner: Arc<Inner>,
    info: Arc<ModuleInfo>,
    initial_discovery: Arc<DiscoveryReport>,
    lifecycle_access: LifecycleAccess,
}

/// Explicit scope of a token discovery request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoverySelection {
    /// Enumerate token-present slots within the caller's discovery limits.
    AllPresentSlots,
    /// Observe only these slots. No preliminary slot-list call is made.
    Slots(Vec<u64>),
    /// Open the module without querying slots, tokens or mechanisms.
    Deferred,
}

/// A slot-specific observation failure, with its original error.
#[derive(Clone, Debug)]
pub struct SlotDiscoveryFailure {
    /// Requested or enumerated slot.
    pub slot: u64,
    /// Exact failed observation, never a successful empty result.
    pub error: Error,
}

/// Completed observations and local failures from one explicit discovery.
#[derive(Clone, Debug)]
pub struct DiscoveryReport {
    /// Scope requested by the caller; Deferred is not an empty discovery.
    pub selection: DiscoverySelection,
    /// Successfully observed tokens, including blank administrative targets.
    pub tokens: Vec<Capabilities>,
    /// Slots whose observation failed. Other successful slots remain available.
    pub failures: Vec<SlotDiscoveryFailure>,
}
/// Token context sharing the module lifecycle and immutable discovery.
pub struct TokenContext {
    pub(crate) inner: Arc<Inner>,
    pub(crate) snapshot: Arc<TokenSnapshot>,
    lifecycle_access: LifecycleAccess,
}

/// Exclusive token-call possession. Guards release in reverse acquisition
/// order, before the Arc owners of their referents. A returned uncertain call
/// retains its separate data/image graph, never these coordination guards.
pub(crate) struct TokenAccess<'a> {
    _token: crate::admission_wait::WriteGuard<'a, ()>,
    state: crate::admission_wait::ReadGuard<'a, State>,
    _snapshot: Arc<TokenSnapshot>,
    _inner: Arc<Inner>,
}

pub(crate) struct TokenCallFrame<'a, T> {
    pub(crate) data: crate::native::frame::CallData<T>,
    pub(crate) access: TokenAccess<'a>,
}
struct LoginCall {
    entry: Arc<SessionEntry>,
    input: crate::pin::LoginFrame,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModuleBinding {
    pub identity: provenance::BindingIdentity,
    pub table_version: (u8, u8),
    pub interface_flags: u64,
}

pub(crate) struct Inner {
    pub(crate) foreign: Arc<foreign::Registry>,
    // Monotonic within this kernel. Children retain both their identity and
    // Inner, so detaching a view cannot reassign its sessions to a new client.
    next_client: std::sync::atomic::AtomicU64,
    // Lazily assigned, never-reused identity for explicit attribute ABI contracts.
    pub(crate) attribute_extension_scope: std::sync::OnceLock<u64>,
    pub(crate) availability: Arc<crate::native::Uncertainty>,
    pub slot_events: Arc<crate::native::events::EventRegistry>,
    pub(crate) module_binding: ModuleBinding,
    pub(crate) object_limits: ObjectLimits,
    pub reservations: Mutex<crate::managed::Catalog>,
    pub state: crate::state_lock::StateLock<State>,
    finalization: crate::admission_wait::ResourceRwLock<FinalizationDiagnostics>,
    // Serializes handle allocation/publication, never ordinary crypto calls.
    pub tokens: Vec<Capabilities>,
    pub(crate) limits: Limits,
    pub(crate) session_policy: crate::SessionPolicy,
    pub(crate) session_ledger: Arc<crate::session_budget::SessionLedger>,
    pub(crate) crypto_options: crate::CryptoOptions,
    pub(crate) verify_engine: Option<crate::VerifyEngine>,
    pub(crate) symmetric_budget: Arc<crate::symmetric::memory::Budget>,
    pub(crate) context_wakes: Arc<crate::admission_wait::ContextWakes>,
    pub(crate) chacha_nonce_length_encoding: crate::ChaChaNonceLengthEncoding,
}
/// Explicit token-wide PKCS#11 login role, independent of application authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginRole {
    /// CKU_USER, for permitted private object operations.
    User,
    /// CKU_SO, for token administration; not a private key user.
    SecurityOfficer,
    /// Exact non-standard CK_USER_TYPE selected by the caller. Standard USER,
    /// SO and CONTEXT_SPECIFIC values must use their dedicated entry points.
    /// The library does not infer privileges or USER identity from this value.
    VendorExtension(u64),
}

// Slot-scoped admission and activity survive context generations. No extra
// lock is taken by nominal operations; snapshots share these existing guards.
pub(crate) struct SlotDomain {
    pub(crate) foreign_epoch: std::sync::atomic::AtomicU64,
    pub(crate) foreign_callbacks_closed: AtomicBool,
    pub(crate) foreign_callback_window: AtomicBool,
    pub activity: crate::admission_wait::ResourceRwLock<()>,
    // A returned token-wide PENDING still excludes every close on this slot.
    // No supported synchronous operation can establish its later completion.
    pending_token_call: AtomicBool,
    pub advanced_active: std::sync::atomic::AtomicUsize,
    pub advanced_stranded: std::sync::atomic::AtomicUsize,
    pub advanced_count_invalid: AtomicBool,
    pub needs_local_cleanup: AtomicBool,
    closing_active: std::sync::atomic::AtomicUsize,
    pub close_epoch: std::sync::atomic::AtomicU64,
    pub transition: crate::admission_wait::ResourceGate,
    admission: std::sync::OnceLock<std::sync::Weak<crate::admission_wait::ContextWakes>>,
    draining: AtomicBool,
}

// Durable close exclusion spans CKR_PENDING without retaining a borrowed lock.
// Stack-only recovery unwind protection, armed before native observation and
// before recording any session as Recovering. It adds no implicit native call.
struct RecoverySequence<'a> {
    native: &'a Native,
    armed: bool,
    native_inflight: bool,
}

pub(crate) struct SlotClose(Arc<SlotDomain>);

pub(crate) struct TokenSnapshot {
    pub(crate) unknown_close: Arc<crate::managed::CloseResident>,
    pub capabilities: Capabilities,
    pub generation: u64,
    pub valid: AtomicBool,
    admission_withdrawn: AtomicBool,
    retirement: Mutex<token_retirement::Retirement>,
    pub domain: Arc<SlotDomain>,
    authentication: crate::authentication::Authentication,
}

pub(crate) struct SessionEntry {
    pub(crate) lifecycle_diagnostics: crate::session::lifecycle_diagnostics::Store,
    pub(crate) creator_close: Arc<crate::managed::CloseResident>,
    pub(crate) recovery: crate::session::recovery::Ledger,
    pub notification: Option<Arc<crate::notify::NotifyContext>>,
    pub mode: crate::AdvancedSessionMode,
    pub advanced_operation: std::sync::atomic::AtomicU64,
    pub advanced_progress: crate::advanced::progress::Progress,
    pub close_control: Mutex<Option<crate::advanced::CloseState>>,
    pub close_pending: AtomicBool,
    // Monotone for this Entry: a creation-family call may have affected objects,
    // even when no handle was published or all known objects were destroyed.
    pub(crate) creation_attempted: AtomicBool,
    pub credit: crate::session_budget::SessionCredit,
    pub operation: crate::admission_wait::ResourceGate,
    pub snapshot: Arc<TokenSnapshot>,
    pub close_attempted: AtomicBool,
    pub deferred_close: AtomicBool,
    pub handle: CK_SESSION_HANDLE,
    pub slot: CK_SLOT_ID,
    pub poisoned: AtomicBool,
    pub closed: AtomicBool,
    // Public admission probe, never published as an alias; retained on uncertain cleanup.
    pub unpublished_object: AtomicBool,
    pub read_write: bool,
    pub generation: u64,
}
pub(crate) struct State {
    pub(crate) foreign: Arc<foreign::Registry>,
    pub operations: crate::advanced::Ledger,
    pub native: Native,
    pub closed: bool,
    pub session_ledger: Arc<crate::session_budget::SessionLedger>,
    pub current_tokens: Arc<Mutex<TokenRegistry>>,
    pub objects: crate::registry::Registry<crate::managed::NativeIdentity>,
    pub managed: crate::registry::Registry<crate::managed::NativeIdentity>,
}

pub(crate) struct TokenRegistry {
    pub tokens: Vec<Arc<TokenSnapshot>>,
    pub next_generation: u64,
    pub revision: u64,
}

/// Two reusable leaves are earmarked before Initialize. Finalize can therefore
/// release a full byte budget without first waiting for the bytes it must free.
struct FinalizationDiagnostics {
    native: Option<crate::error::CompletionStorage>,
    publication: Option<crate::error::CompletionStorage>,
    _credit: crate::symmetric::memory::ResidentCredit,
}

#[derive(Default)]
struct FinalizationRetired {
    foreign: foreign::Retired,
    entries: Vec<Arc<SessionEntry>>,
    operations: Option<crate::advanced::FinalizedOperations>,
    sessions: Option<crate::session_budget::FinalizedSessions>,
    notifications: crate::notify::RetiredNotifications,
}

/// Unique admission drain for a complete native owner, not token recovery.
/// Already admitted calls retain their resources. Methods never cancel them.
pub struct ModuleDrain {
    inner: Arc<Inner>,
}

/// Exclusive owner of a token's admission drain. Drop releases admission ownership;
/// a stale or withdrawn context remains unusable through its independent validity gates.
/// Existing native calls retain their resources; this permit cannot cancel them.
/// Keep the permit while retrying a Busy administration explicitly, then drop it.
pub struct TokenDrain {
    context: TokenContext,
}

struct DiscoveryListFrame<T> {
    count: CK_ULONG,
    values: Vec<T>,
}

mod access;
mod discovery;
mod drain;
mod finalization;
mod open;
mod recovery;
mod sessions;
mod state;
mod token_retirement;
mod token_snapshot;
pub(crate) use discovery::check_discovery;
pub(crate) use discovery::discover_selected;
pub(crate) use discovery::discover_slot;

use discovery::list;
use finalization::close_owner;

use finalization::validate_finalization_entry;
