// SPDX-License-Identifier: Apache-2.0
//! Explicit optional component selection. This module never links OpenSSL.
//!
//! A component executes native code under the application's loader trust
//! boundary. File observations are not a sandbox or an attestation of its code.
//! The process keeps selected component images loaded, while each request owns
//! and releases its cryptographic resources inside that component.
mod calls;
mod loading;
mod platform;

use crate::{
    ModuleIntegrity, ModuleIntegrityReport, Observation, Result, WindowsDependencySearch,
    WindowsFilePinning, WindowsImageConsistency, WindowsLoaderObservations, WindowsLoaderReport,
};
use std::{path::PathBuf, sync::Arc};

/// Provenance of this explicit open, separate from the component's operation
/// capabilities. A present service must still accept each exact parameter set.
#[derive(Clone, Debug)]
pub struct VerifyEngineInfo {
    /// Canonical source path opened for this selection.
    pub source_path: PathBuf,
    /// Digest of that opened file; this alone does not attest the loaded image.
    pub source_sha256: [u8; 32],
    /// Caller-selected expected digest comparison and its actual outcome.
    pub integrity: ModuleIntegrityReport,
    /// File-pinning observation for this open, kept alive by this handle's lease.
    pub windows_file_pinned: Observation<bool>,
    /// Selected image/export comparison, with its platform-specific scope.
    pub image_matches_source: Observation<bool>,
    /// Dated Windows observations made before this load attempt.
    pub windows_loader: WindowsLoaderReport,
    /// Exact software-component ABI, independent of any PKCS#11 interface.
    pub abi_version: u32,
    /// Component's own reported implementation version.
    pub implementation_version: [u32; 3],
    /// Component's private OpenSSL version number, not the application's copy.
    pub openssl_version: u64,
    /// Both preparation and verification entry points are present.
    pub verification_service: bool,
    /// Keyless implementation availability can be queried before generation.
    /// This entry point alone does not establish support for an algorithm or key.
    pub verification_algorithms_service: bool,
    /// A whole-message digest entry point is present.
    pub digest_service: bool,
}

/// A shareable lease on an explicitly selected software component.
///
/// Dropping every handle releases per-open observations/pins, but does not unload
/// the process-pinned image or reset its private engine. Updating an already
/// selected image requires restarting the process. There is no implicit default
/// component and no search by name. Requests are synchronous and independent
/// across threads; no OpenSSL pointer is exposed to callers.
#[derive(Clone)]
pub struct VerifyEngine {
    lease: Arc<loading::Lease>,
}

impl VerifyEngine {
    /// Configure a trusted component by absolute path and explicit integrity
    /// selection. Construction alone performs no file or native operation.
    pub fn builder(path: PathBuf, integrity: ModuleIntegrity) -> VerifyEngineBuilder {
        VerifyEngineBuilder {
            path,
            integrity,
            windows_file_pinning: WindowsFilePinning::NotRequested,
            windows_dependency_search: WindowsDependencySearch::ApplicationConfigured,
            windows_loader_observations: WindowsLoaderObservations::NotRequested,
            windows_image_consistency: WindowsImageConsistency::NotRequested,
        }
    }

    /// Immutable evidence from this open. Entry-point presence is not an
    /// algorithm support claim or a successful cryptographic observation.
    pub fn info(&self) -> &VerifyEngineInfo {
        &self.lease.info
    }
}

/// Independent loader choices. The optional controls have the same scope as
/// their ModuleBuilder counterparts; engine image lifetime is handled separately.
#[must_use = "A verification engine configuration has no effect until open is called"]
pub struct VerifyEngineBuilder {
    path: PathBuf,
    integrity: ModuleIntegrity,
    windows_file_pinning: WindowsFilePinning,
    windows_dependency_search: WindowsDependencySearch,
    windows_loader_observations: WindowsLoaderObservations,
    windows_image_consistency: WindowsImageConsistency,
}

impl VerifyEngineBuilder {
    /// Retain the requested file/ancestor pins during this handle's lease.
    /// A non-Windows platform refuses an explicitly selected Windows control.
    pub fn windows_file_pinning(mut self, selection: WindowsFilePinning) -> Self {
        self.windows_file_pinning = selection;
        self
    }

    /// Choose local dependency-search flags; never alter process-global state.
    pub fn windows_dependency_search(mut self, selection: WindowsDependencySearch) -> Self {
        self.windows_dependency_search = selection;
        self
    }

    /// Request selected pre-load observations with explicit unavailable behavior.
    pub fn windows_loader_observations(mut self, selection: WindowsLoaderObservations) -> Self {
        self.windows_loader_observations = selection;
        self
    }

    /// Compare the loaded image with an explicitly pinned source file. This
    /// happens after native initializers, and cannot protect against a hostile DLL.
    pub fn windows_image_consistency(mut self, selection: WindowsImageConsistency) -> Self {
        self.windows_image_consistency = selection;
        self
    }

    /// Load once, pin the image, validate the component ABI and read its version.
    /// A failure never triggers another search, image load or engine fallback.
    pub fn open(self) -> Result<VerifyEngine> {
        loading::open(self)
    }
}


