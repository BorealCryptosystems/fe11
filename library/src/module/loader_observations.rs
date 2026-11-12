// SPDX-License-Identifier: Apache-2.0
//! Optional, dated observations of the application's trusted Windows loader.
use super::WindowsDependencySearch;
use std::{ffi::OsString, num::NonZeroUsize, path::PathBuf, time::SystemTime};

/// Availability requirement for one named observation, not a security profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsLoaderRequest {
    /// Do not inspect this channel.
    NotRequested,
    /// Retain an unavailable result without refusing the load.
    Report,
    /// Refuse before loading unless the requested observation is known.
    RequireKnown,
}

/// Closed catalogue of observations; additions require an explicit API change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsLoaderChannel {
    /// File or directory named after the executable with a .local suffix.
    DotLocal,
    /// Package-root microsoft.system.package.metadata/application.local.
    PackagedDotLocal,
    /// Configured DevOverrideEnable registry value, not its effective state.
    DevOverrideRegistry,
    /// Effective post-restart DevOverrideEnable state; no retained probe establishes it.
    DevOverrideEffective,
    /// Exact API-set resolution; unavailable with the retained documented probes.
    ApiSets,
    /// Assemblies and files reported for the active activation context.
    ActivationContext,
    /// Dated inventory of mapped module paths, without atomicity guarantees.
    LoadedModules,
    /// Values read from the appropriate KnownDLLs registry view.
    KnownDlls,
    /// Effective package dependency graph; no retained probe establishes it.
    PackageDependencyGraph,
    /// Requested module path, application/system directories and local flags.
    SearchDirectories,
    /// Other global search contributions; not inferred from local flags.
    GlobalSearchState,
}

/// Independent requirements; None of them means absence of a redirection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsLoaderRequests {
    /// Executable .local path.
    pub dot_local: WindowsLoaderRequest,
    /// Package .local path.
    pub packaged_dot_local: WindowsLoaderRequest,
    /// Configured registry value.
    pub dev_override_registry: WindowsLoaderRequest,
    /// Effective value after system restart.
    pub dev_override_effective: WindowsLoaderRequest,
    /// Exact API-set resolution.
    pub api_sets: WindowsLoaderRequest,
    /// Active context assemblies and files.
    pub activation_context: WindowsLoaderRequest,
    /// Mapped module inventory.
    pub loaded_modules: WindowsLoaderRequest,
    /// Architecture-appropriate KnownDLLs registry values.
    pub known_dlls: WindowsLoaderRequest,
    /// Effective package dependency graph.
    pub package_dependency_graph: WindowsLoaderRequest,
    /// Selected local search inputs.
    pub search_directories: WindowsLoaderRequest,
    /// Unobserved global search contributions.
    pub global_search_state: WindowsLoaderRequest,
}
impl WindowsLoaderRequests {
    /// Apply the same requirement to the whole versioned catalogue. Requiring
    /// all channels is refused before loading because some are unavailable.
    pub const fn all(request: WindowsLoaderRequest) -> Self {
        Self {
            dot_local: request,
            packaged_dot_local: request,
            dev_override_registry: request,
            dev_override_effective: request,
            api_sets: request,
            activation_context: request,
            loaded_modules: request,
            known_dlls: request,
            package_dependency_graph: request,
            search_directories: request,
            global_search_state: request,
        }
    }
}

/// Caller-selected bounds for one pre-load snapshot. Counts and per-value
/// capacities jointly bound each inventory; no retry increases these limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsLoaderObservationLimits {
    /// UTF-16 units, including a terminator, for each path or registry name.
    pub maximum_path_code_units: NonZeroUsize,
    /// Maximum number of KnownDLLs values retained.
    pub maximum_registry_entries: usize,
    /// Maximum bytes of each registry value.
    pub maximum_registry_value_bytes: NonZeroUsize,
    /// Maximum number of modules retained.
    pub maximum_modules: usize,
    /// Maximum number of activation assemblies retained.
    pub maximum_activation_assemblies: usize,
    /// Maximum total files across activation assemblies.
    pub maximum_activation_files: usize,
    /// Maximum bytes returned by any single QueryActCtx call.
    pub maximum_activation_query_bytes: NonZeroUsize,
}

/// Optional loader inspection. The ordinary loading path performs no probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsLoaderObservations {
    /// All catalogue entries remain NotRequested.
    NotRequested,
    /// Inspect the selected channels just before loading on that same thread.
    Selected {
        /// Per-channel availability requirements.
        requests: WindowsLoaderRequests,
        /// Explicit resource bounds.
        limits: WindowsLoaderObservationLimits,
    },
}

/// Why a requested observation is unavailable; no path or registry data leaks
/// through an error. OS codes remain distinct from PKCS#11 CK_RV values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsLoaderUnavailable {
    /// Native observation function returned this Win32 code.
    Os {
        /// Static OS function name, not a path or registry value.
        function: &'static str,
        /// Exact Win32 error code.
        code: u32,
    },
    /// A standard-library OS failure did not expose a native status code.
    OsErrorWithoutCode {
        /// Static operation name.
        function: &'static str,
    },
    /// No documented probe retained by this implementation establishes the state.
    NoDocumentedProbe,
    /// Process/package/architecture provenance cannot be established.
    ProvenanceUnavailable,
    /// Caller-selected capacity or checked integer representation was exceeded.
    ResourceLimit,
    /// Fallible allocation failed.
    Allocation,
    /// Native output was inconsistent or outside its owned buffer.
    InvalidOutput,
    /// A source changed between sizing and its single bounded fill.
    ChangedDuringObservation,
}

/// A point-in-time observation, never an atomic exclusion of loader changes.
#[derive(Clone, Debug)]
pub enum WindowsLoaderObservation<T> {
    /// No observation was requested.
    NotRequested,
    /// Value read from the named source. This does not mean safe or absent.
    Known {
        /// Wall-clock instant immediately before this probe began.
        observed_at: SystemTime,
        /// Owned value actually read.
        value: T,
    },
    /// Requested information could not be established.
    Unavailable {
        /// Wall-clock instant immediately before this probe began.
        observed_at: SystemTime,
        /// Why the requested source did not yield a usable observation.
        cause: WindowsLoaderUnavailable,
    },
}

/// Type observed at a redirection path. Access failure is not Missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsLoaderPathKind {
    /// File system reported that this path does not exist.
    Missing,
    /// A regular file was observed.
    File,
    /// A directory was observed.
    Directory,
    /// Another file type, including an unresolved reparse point, was observed.
    Other,
}

/// Observed redirection path and its file-system classification.
#[derive(Clone, Debug)]
pub struct WindowsLoaderPath {
    /// Exact path inspected; not an authenticated file identity.
    pub path: PathBuf,
    /// Classification obtained without interpreting an access error as absence.
    pub kind: WindowsLoaderPathKind,
}

/// A value as read from KnownDLLs. Unknown registry types are retained intact;
/// this inventory does not expand strings or validate dependency identities.
#[derive(Clone, Debug)]
pub struct WindowsLoaderRegistryValue {
    /// Value name, without a terminating NUL.
    pub name: OsString,
    /// Win32 registry type identifier.
    pub value_type: u32,
    /// Exact bounded value bytes.
    pub data: Vec<u8>,
}

/// A file reported in an active-context assembly.
#[derive(Clone, Debug)]
pub struct WindowsActivationFile {
    /// File name returned by QueryActCtx.
    pub name: OsString,
    /// File path returned by QueryActCtx.
    pub path: OsString,
}

/// Owned information copied from an active-context assembly.
#[derive(Clone, Debug)]
pub struct WindowsActivationAssembly {
    /// Encoded assembly identity returned by the OS.
    pub identity: OsString,
    /// Assembly manifest path, empty when not supplied.
    pub manifest: OsString,
    /// Applied policy path, empty when not supplied.
    pub policy: OsString,
    /// Assembly directory returned by the OS.
    pub directory: OsString,
    /// Files reported for this assembly; not a transitive dependency inventory.
    pub files: Vec<WindowsActivationFile>,
}

/// Inventory returned by QueryActCtx on the loading thread. This inventory
/// does not prove the absence of all side-by-side redirections.
#[derive(Clone, Debug)]
pub struct WindowsActivationContext {
    /// Root manifest path, empty when not supplied.
    pub root_manifest: OsString,
    /// Configuration file path, empty when not supplied.
    pub root_configuration: OsString,
    /// Application directory in the queried context.
    pub application_directory: OsString,
    /// All assemblies in the bounded returned inventory.
    pub assemblies: Vec<WindowsActivationAssembly>,
}

/// Local search inputs, distinct from global contributions and resolution.
#[derive(Clone, Debug)]
pub struct WindowsLoaderSearchDirectories {
    /// Main module path supplied to this load.
    pub requested_module: PathBuf,
    /// Parent directory of the current executable.
    pub application_directory: PathBuf,
    /// Process-architecture system directory reported by Windows.
    pub system_directory: PathBuf,
    /// Exact directory contributions passed to the load operation.
    pub selection: WindowsDependencySearch,
}

/// Pre-load observations owned by the opened module's public information.
/// No provider calls, callbacks or activation changes occur between the final
/// active-context observation and the load. Concurrent process changes remain possible.
#[derive(Clone, Debug)]
pub struct WindowsLoaderReport {
    /// Executable .local file or directory observation.
    pub dot_local: WindowsLoaderObservation<WindowsLoaderPath>,
    /// Package .local observation, unavailable when package provenance is absent.
    pub packaged_dot_local: WindowsLoaderObservation<WindowsLoaderPath>,
    /// Configured DWORD or observed missing value, not effective restart state.
    pub dev_override_registry: WindowsLoaderObservation<Option<u32>>,
    /// Effective state is unavailable with the retained documented probes.
    pub dev_override_effective: WindowsLoaderObservation<bool>,
    /// Exact API-set resolution is unavailable with the retained probes.
    pub api_sets: WindowsLoaderObservation<()>,
    /// Active context queried last, on the same thread as the load.
    pub activation_context: WindowsLoaderObservation<WindowsActivationContext>,
    /// Observed mapped NT paths; concurrent changes are not excluded.
    pub loaded_modules: WindowsLoaderObservation<Vec<PathBuf>>,
    /// Raw KnownDLLs registry values in the established native architecture view.
    pub known_dlls: WindowsLoaderObservation<Vec<WindowsLoaderRegistryValue>>,
    /// Effective dependency graph is unavailable with the retained probes.
    pub package_dependency_graph: WindowsLoaderObservation<()>,
    /// Local search inputs; separate from global contributions.
    pub search_directories: WindowsLoaderObservation<WindowsLoaderSearchDirectories>,
    /// Global contributions are not inferred from local search flags.
    pub global_search_state: WindowsLoaderObservation<()>,
}
impl WindowsLoaderReport {
    pub(crate) fn not_requested() -> Self {
        use WindowsLoaderObservation::NotRequested;
        Self {
            dot_local: NotRequested,
            packaged_dot_local: NotRequested,
            dev_override_registry: NotRequested,
            dev_override_effective: NotRequested,
            api_sets: NotRequested,
            activation_context: NotRequested,
            loaded_modules: NotRequested,
            known_dlls: NotRequested,
            package_dependency_graph: NotRequested,
            search_directories: NotRequested,
            global_search_state: NotRequested,
        }
    }
}
