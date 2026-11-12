// SPDX-License-Identifier: Apache-2.0
//! Shared file provenance checks for read-only loading observations.
use super::ModuleBuilder;
use crate::native::{platform, Native};
use crate::{InterfaceInventory, InterfaceInventoryLimits, Result};

pub(super) enum ObservationSource {
    File {
        load_path: std::path::PathBuf,
        identity: platform::FileIdentity,
        source: platform::SourceFiles,
        export_check: platform::ExportFileCheck,
    },
    Process,
}

impl ModuleBuilder {
    /// Observe every interface advertised by `C_GetInterfaceList`, without
    /// selecting a table or calling Initialize/Finalize. This ignores the
    /// builder's interface selection, but applies its file integrity and loader
    /// options. Loading can execute native constructors; the module and loader
    /// configuration remain in the application's trust boundary.
    ///
    /// Names, standard version prefixes and flags are copied while the image is
    /// retained. Nonstandard tables remain opaque. The result neither reserves
    /// a future image nor proves operational support. Missing list exports are
    /// errors, including on legacy modules. Bounds and retries are explicit.
    /// Native count diagnostics use descriptor units, not bytes.
    pub fn observe_interfaces(
        &self,
        limits: InterfaceInventoryLimits,
    ) -> Result<InterfaceInventory> {
        match self.observation_source()? {
            ObservationSource::File {
                load_path,
                identity,
                source,
                export_check,
            } => Native::observe_interfaces_file(
                &load_path,
                identity,
                source,
                export_check,
                limits,
                self.windows_dependency_search,
                self.windows_loader_observations,
            ),
            ObservationSource::Process => Native::observe_interfaces_process(limits),
        }
    }

    pub(super) fn observation_source(&self) -> Result<ObservationSource> {
        use crate::native::platform;
        platform::validate_image_selection(
            self.windows_file_pinning,
            self.windows_image_consistency,
        )?;
        platform::dependency_search_flags(self.windows_dependency_search)?;
        platform::validate_observations(self.windows_loader_observations)?;
        match &self.config {
            super::super::provenance::Source::File(config) => {
                if !config.path.is_absolute() {
                    return Err(crate::Error::Rejected(
                        crate::RejectionReason::ModuleLifecycle(
                            crate::ModuleLifecycleRejection::AbsoluteModulePathRequired,
                        ),
                    ));
                }
                let (path, mut source, _) =
                    platform::open_source(&config.path, self.windows_file_pinning)?;
                if !source
                    .file
                    .metadata()
                    .map_err(|_| {
                        crate::Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                            crate::ModuleLifecycleRejection::ModuleMetadata,
                        ))
                    })?
                    .is_file()
                {
                    return Err(crate::Error::Rejected(
                        crate::RejectionReason::ModuleLifecycle(
                            crate::ModuleLifecycleRejection::ModuleIsNotRegularFile,
                        ),
                    ));
                }
                let digest = super::super::provenance::digest(&mut source.file)?;
                config.integrity.clone().evaluate(digest)?;
                let (load_path, identity, export_check) =
                    platform::prepare(&source.file, &path, self.windows_image_consistency)?;
                Ok(ObservationSource::File {
                    load_path,
                    identity,
                    source,
                    export_check,
                })
            }
            super::super::provenance::Source::Process(_) => {
                if !matches!(
                    self.windows_file_pinning,
                    super::super::WindowsFilePinning::NotRequested
                ) || !matches!(
                    self.windows_image_consistency,
                    super::super::WindowsImageConsistency::NotRequested
                ) || !matches!(
                    self.windows_dependency_search,
                    super::super::WindowsDependencySearch::ApplicationConfigured
                ) || !matches!(
                    self.windows_loader_observations,
                    super::super::WindowsLoaderObservations::NotRequested
                ) {
                    return Err(crate::Error::Unsupported(
                        crate::UnsupportedReason::ModuleLifecycle(
                            crate::ModuleLifecycleUnsupported::FileLoadingOptionsForProcessSource,
                        ),
                    ));
                }
                Ok(ObservationSource::Process)
            }
        }
    }
}
