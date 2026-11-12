// SPDX-License-Identifier: Apache-2.0
//! Explicit file controls; loading native code remains application trust.
use crate::Observation;
use std::num::NonZeroUsize;

/// Local dependency-directory selection for the Windows load operation.
/// Redirections, API sets and already loaded modules remain loader behavior;
/// this choice does not authenticate dependencies or sandbox their initializers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsDependencySearch {
    /// Preserve the application's ordinary loader configuration on any platform.
    ApplicationConfigured,
    /// Select contributions to LOAD_LIBRARY_SEARCH_* for this load only.
    /// At least one must be selected: zero flags would mean ordinary loading,
    /// not an empty directory search. Refused outside Windows before loading.
    Directories {
        /// Directory containing the absolute path of the main module.
        module_directory: bool,
        /// Directory containing the process executable.
        application_directory: bool,
        /// Directories configured by the application through AddDllDirectory
        /// or SetDllDirectory. Their mutual search order is not guaranteed.
        application_added_directories: bool,
        /// The process-architecture system directory (LOAD_LIBRARY_SEARCH_SYSTEM32).
        system32: bool,
    },
}

/// Treatment of reparse points in a caller-selected Windows file pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsReparseHandling {
    /// Reject reparse points in the selected file and ancestor chain.
    Reject,
    /// Resolve the opened file once, then pin its resolved path and ancestors.
    /// A changed identity at the final lookup is refused without retry.
    ResolveAndPin,
}

/// Optional Windows file/ancestor handle retention. No loader redirection,
/// dependency identity or protection against hostile DllMain is implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsFilePinning {
    /// Use ordinary loading under the application's loader configuration.
    NotRequested,
    /// Keep the file without WRITE/DELETE sharing and ancestors without DELETE
    /// sharing until the image lease ends. Unavailable controls refuse loading.
    Pin {
        /// Caller-selected reparse-point semantics.
        reparse: WindowsReparseHandling,
        /// Maximum UTF-16 units in the final-path buffer, including terminator.
        maximum_path_code_units: NonZeroUsize,
        /// Maximum retained ancestor handles; None adds no application ceiling.
        maximum_ancestors: Option<usize>,
    },
}

/// Observation of the requested file pin, separate from loaded-image checks.
#[derive(Clone, Debug)]
pub struct WindowsFilePinningReport {
    selection: WindowsFilePinning,
    observation: Observation<bool>,
}
impl WindowsFilePinningReport {
    pub(super) fn new(selection: WindowsFilePinning, observation: Observation<bool>) -> Self {
        Self {
            selection,
            observation,
        }
    }
    /// Immutable caller choice used for this load.
    pub fn selection(&self) -> &WindowsFilePinning {
        &self.selection
    }
    /// NotRequested or an established pin. Failure prevents the module opening.
    pub fn observation(&self) -> &Observation<bool> {
        &self.observation
    }
}

/// Optional post-load comparison under the application's trusted host/loader.
/// Native initializers have already run; this is not a sandbox or a dependency audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsImageConsistency {
    /// No comparison of the loaded image with the pinned source file.
    NotRequested,
    /// Require FilePinned and compare the main mapping and table-selection exports.
    /// A mismatch or unavailable observation refuses before PKCS#11 calls.
    CompareToPinnedFile {
        /// Maximum UTF-16 units for a mapped-path buffer, including terminator.
        maximum_mapped_path_code_units: NonZeroUsize,
    },
}

/// Result of the explicitly requested post-load image/export comparison.
#[derive(Clone, Debug)]
pub struct WindowsImageConsistencyReport {
    selection: WindowsImageConsistency,
    observation: Observation<bool>,
}
impl WindowsImageConsistencyReport {
    pub(super) fn new(selection: WindowsImageConsistency, observation: Observation<bool>) -> Self {
        Self {
            selection,
            observation,
        }
    }
    /// Exact immutable choice supplied for this load.
    pub fn selection(&self) -> &WindowsImageConsistency {
        &self.selection
    }
    /// NotRequested or a completed comparison; no success is published on refusal.
    pub fn observation(&self) -> &Observation<bool> {
        &self.observation
    }
}
