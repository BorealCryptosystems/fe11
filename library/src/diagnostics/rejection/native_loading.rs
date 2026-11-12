// SPDX-License-Identifier: Apache-2.0
//! NativeLoading causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native loading.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_loading.md")]
pub enum NativeLoadingRejection {
    /// A required lifecycle entry is absent from the selected native table. [Detection, owner and recovery](#cause-RequiredFunctionMissing).
    RequiredFunctionMissing {
        /// Exact PKCS#11 function name; no module path or native handle.
        function: &'static str,
    },
    /// Windows dependency search unavailable. [Detection, owner and recovery](#cause-WindowsDependencySearchUnavailable).
    WindowsDependencySearchUnavailable,
    /// Windows file pinning unavailable. [Detection, owner and recovery](#cause-WindowsFilePinningUnavailable).
    WindowsFilePinningUnavailable,
    /// Windows image comparison requires file pinning. [Detection, owner and recovery](#cause-WindowsImageComparisonRequiresFilePinning).
    WindowsImageComparisonRequiresFilePinning,
    /// Windows image comparison unavailable. [Detection, owner and recovery](#cause-WindowsImageComparisonUnavailable).
    WindowsImageComparisonUnavailable,
    /// Windows loader observations unavailable. [Detection, owner and recovery](#cause-WindowsLoaderObservationsUnavailable).
    WindowsLoaderObservationsUnavailable,
    /// Competing initializer cannot own Finalize. [Detection, owner and recovery](#cause-CompetingInitializerCannotOwnFinalize).
    CompetingInitializerCannotOwnFinalize,
    /// Current process image unavailable. [Detection, owner and recovery](#cause-CurrentProcessImageUnavailable).
    CurrentProcessImageUnavailable,
    /// Empty Windows dependency search selection. [Detection, owner and recovery](#cause-EmptyWindowsDependencySearchSelection).
    EmptyWindowsDependencySearchSelection,
    /// External image already has a runtime. [Detection, owner and recovery](#cause-ExternalImageAlreadyHasARuntime).
    ExternalImageAlreadyHasARuntime,
    /// Image dispatch allocation. [Detection, owner and recovery](#cause-ImageDispatchAllocation).
    ImageDispatchAllocation,
    /// Image generation exhausted. [Detection, owner and recovery](#cause-ImageGenerationExhausted).
    ImageGenerationExhausted,
    /// Image initialization generation changed. [Detection, owner and recovery](#cause-ImageInitializationGenerationChanged).
    ImageInitializationGenerationChanged,
    /// Image reservation allocation. [Detection, owner and recovery](#cause-ImageReservationAllocation).
    ImageReservationAllocation,
    /// Initialization attempt count exhausted. [Detection, owner and recovery](#cause-InitializationAttemptCountExhausted).
    InitializationAttemptCountExhausted,
    /// Loaded image check incomplete. [Detection, owner and recovery](#cause-LoadedImageCheckIncomplete).
    LoadedImageCheckIncomplete,
    /// Loaded image file identity mismatch. [Detection, owner and recovery](#cause-LoadedImageFileIdentityMismatch).
    LoadedImageFileIdentityMismatch,
    /// Loaded module identity mismatch. [Detection, owner and recovery](#cause-LoadedModuleIdentityMismatch).
    LoadedModuleIdentityMismatch,
    /// Mapped image file unavailable. [Detection, owner and recovery](#cause-MappedImageFileUnavailable).
    MappedImageFileUnavailable,
    /// Mapped image path allocation. [Detection, owner and recovery](#cause-MappedImagePathAllocation).
    MappedImagePathAllocation,
    /// Mapped image path namespace unavailable. [Detection, owner and recovery](#cause-MappedImagePathNamespaceUnavailable).
    MappedImagePathNamespaceUnavailable,
    /// Mapped image path size. [Detection, owner and recovery](#cause-MappedImagePathSize).
    MappedImagePathSize,
    /// Mapped image path unavailable or truncated. [Detection, owner and recovery](#cause-MappedImagePathUnavailableOrTruncated).
    MappedImagePathUnavailableOrTruncated,
    /// Module accepted competing initialization. [Detection, owner and recovery](#cause-ModuleAcceptedCompetingInitialization).
    ModuleAcceptedCompetingInitialization,
    /// Module ancestor allocation. [Detection, owner and recovery](#cause-ModuleAncestorAllocation).
    ModuleAncestorAllocation,
    /// Module ancestor count. [Detection, owner and recovery](#cause-ModuleAncestorCount).
    ModuleAncestorCount,
    /// Module ancestor is not a plain directory. [Detection, owner and recovery](#cause-ModuleAncestorIsNotAPlainDirectory).
    ModuleAncestorIsNotAPlainDirectory,
    /// Module ancestor limit. [Detection, owner and recovery](#cause-ModuleAncestorLimit).
    ModuleAncestorLimit,
    /// Module ancestor metadata. [Detection, owner and recovery](#cause-ModuleAncestorMetadata).
    ModuleAncestorMetadata,
    /// Module ancestor pin unavailable. [Detection, owner and recovery](#cause-ModuleAncestorPinUnavailable).
    ModuleAncestorPinUnavailable,
    /// Module file. [Detection, owner and recovery](#cause-ModuleFile).
    ModuleFile,
    /// Module file identity size. [Detection, owner and recovery](#cause-ModuleFileIdentitySize).
    ModuleFileIdentitySize,
    /// Module file identity unavailable. [Detection, owner and recovery](#cause-ModuleFileIdentityUnavailable).
    ModuleFileIdentityUnavailable,
    /// Module file pin metadata. [Detection, owner and recovery](#cause-ModuleFilePinMetadata).
    ModuleFilePinMetadata,
    /// Module file pin unavailable. [Detection, owner and recovery](#cause-ModuleFilePinUnavailable).
    ModuleFilePinUnavailable,
    /// Module final path allocation. [Detection, owner and recovery](#cause-ModuleFinalPathAllocation).
    ModuleFinalPathAllocation,
    /// Module final path changed or invalid. [Detection, owner and recovery](#cause-ModuleFinalPathChangedOrInvalid).
    ModuleFinalPathChangedOrInvalid,
    /// Module final path is not absolute. [Detection, owner and recovery](#cause-ModuleFinalPathIsNotAbsolute).
    ModuleFinalPathIsNotAbsolute,
    /// Module final path size. [Detection, owner and recovery](#cause-ModuleFinalPathSize).
    ModuleFinalPathSize,
    /// Module final path unavailable or over limit. [Detection, owner and recovery](#cause-ModuleFinalPathUnavailableOrOverLimit).
    ModuleFinalPathUnavailableOrOverLimit,
    /// Module load. [Detection, owner and recovery](#cause-ModuleLoad).
    ModuleLoad,
    /// Module loading platform unavailable. [Detection, owner and recovery](#cause-ModuleLoadingPlatformUnavailable).
    ModuleLoadingPlatformUnavailable,
    /// Module mapping unavailable. [Detection, owner and recovery](#cause-ModuleMappingUnavailable).
    ModuleMappingUnavailable,
    /// Module path. [Detection, owner and recovery](#cause-ModulePath).
    ModulePath,
    /// Module pinned file identity changed. [Detection, owner and recovery](#cause-ModulePinnedFileIdentityChanged).
    ModulePinnedFileIdentityChanged,
    /// Module pinned target is not a plain file. [Detection, owner and recovery](#cause-ModulePinnedTargetIsNotAPlainFile).
    ModulePinnedTargetIsNotAPlainFile,
    /// Module resolved ancestor chain changed. [Detection, owner and recovery](#cause-ModuleResolvedAncestorChainChanged).
    ModuleResolvedAncestorChainChanged,
    /// Native entry image mapping changed. [Detection, owner and recovery](#cause-NativeEntryImageMappingChanged).
    NativeEntryImageMappingChanged,
    /// Native entry image owner allocation. [Detection, owner and recovery](#cause-NativeEntryImageOwnerAllocation).
    NativeEntryImageOwnerAllocation,
    /// Native image identity unavailable. [Detection, owner and recovery](#cause-NativeImageIdentityUnavailable).
    NativeImageIdentityUnavailable,
    /// Native image not initialized. [Detection, owner and recovery](#cause-NativeImageNotInitialized).
    NativeImageNotInitialized,
    /// Native image owner withdrawn. [Detection, owner and recovery](#cause-NativeImageOwnerWithdrawn).
    NativeImageOwnerWithdrawn,
    /// Null loaded image address. [Detection, owner and recovery](#cause-NullLoadedImageAddress).
    NullLoadedImageAddress,
    /// Process export image unavailable. [Detection, owner and recovery](#cause-ProcessExportImageUnavailable).
    ProcessExportImageUnavailable,
    /// Process export mapping changed. [Detection, owner and recovery](#cause-ProcessExportMappingChanged).
    ProcessExportMappingChanged,
    /// Process export mapping unavailable. [Detection, owner and recovery](#cause-ProcessExportMappingUnavailable).
    ProcessExportMappingUnavailable,
    /// Process image name allocation. [Detection, owner and recovery](#cause-ProcessImageNameAllocation).
    ProcessImageNameAllocation,
    /// Process image no longer loaded. [Detection, owner and recovery](#cause-ProcessImageNoLongerLoaded).
    ProcessImageNoLongerLoaded,
    /// Process image owner allocation. [Detection, owner and recovery](#cause-ProcessImageOwnerAllocation).
    ProcessImageOwnerAllocation,
    /// Process loader metadata width. [Detection, owner and recovery](#cause-ProcessLoaderMetadataWidth).
    ProcessLoaderMetadataWidth,
    /// Retained process export unavailable. [Detection, owner and recovery](#cause-RetainedProcessExportUnavailable).
    RetainedProcessExportUnavailable,
    /// Successor image identity absent. [Detection, owner and recovery](#cause-SuccessorImageIdentityAbsent).
    SuccessorImageIdentityAbsent,
    /// Successor image reservation mismatch. [Detection, owner and recovery](#cause-SuccessorImageReservationMismatch).
    SuccessorImageReservationMismatch,
    /// Successor registry allocation. [Detection, owner and recovery](#cause-SuccessorRegistryAllocation).
    SuccessorRegistryAllocation,
    /// Successor reservation allocation. [Detection, owner and recovery](#cause-SuccessorReservationAllocation).
    SuccessorReservationAllocation,
    /// Successor selects a different native image. [Detection, owner and recovery](#cause-SuccessorSelectsADifferentNativeImage).
    SuccessorSelectsADifferentNativeImage,
    /// Table selection export belongs to another image. [Detection, owner and recovery](#cause-TableSelectionExportBelongsToAnotherImage).
    TableSelectionExportBelongsToAnotherImage,
}

impl std::fmt::Display for NativeLoadingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequiredFunctionMissing { function } => {
                write!(f, "required native function {function} is unavailable")
            }
            Self::WindowsDependencySearchUnavailable => {
                f.write_str("Windows dependency search unavailable")
            }
            Self::WindowsFilePinningUnavailable => f.write_str("Windows file pinning unavailable"),
            Self::WindowsImageComparisonRequiresFilePinning => {
                f.write_str("Windows image comparison requires file pinning")
            }
            Self::WindowsImageComparisonUnavailable => {
                f.write_str("Windows image comparison unavailable")
            }
            Self::WindowsLoaderObservationsUnavailable => {
                f.write_str("Windows loader observations unavailable")
            }
            Self::CompetingInitializerCannotOwnFinalize => {
                f.write_str("competing initializer cannot own Finalize")
            }
            Self::CurrentProcessImageUnavailable => {
                f.write_str("current process image unavailable")
            }
            Self::EmptyWindowsDependencySearchSelection => {
                f.write_str("empty Windows dependency search selection")
            }
            Self::ExternalImageAlreadyHasARuntime => {
                f.write_str("external image already has a runtime")
            }
            Self::ImageDispatchAllocation => f.write_str("image dispatch allocation"),
            Self::ImageGenerationExhausted => f.write_str("image generation exhausted"),
            Self::ImageInitializationGenerationChanged => {
                f.write_str("image initialization generation changed")
            }
            Self::ImageReservationAllocation => f.write_str("image reservation allocation"),
            Self::InitializationAttemptCountExhausted => {
                f.write_str("initialization attempt count exhausted")
            }
            Self::LoadedImageCheckIncomplete => f.write_str("loaded image check incomplete"),
            Self::LoadedImageFileIdentityMismatch => {
                f.write_str("loaded image file identity mismatch")
            }
            Self::LoadedModuleIdentityMismatch => f.write_str("loaded module identity mismatch"),
            Self::MappedImageFileUnavailable => f.write_str("mapped image file unavailable"),
            Self::MappedImagePathAllocation => f.write_str("mapped image path allocation"),
            Self::MappedImagePathNamespaceUnavailable => {
                f.write_str("mapped image path namespace unavailable")
            }
            Self::MappedImagePathSize => f.write_str("mapped image path size"),
            Self::MappedImagePathUnavailableOrTruncated => {
                f.write_str("mapped image path unavailable or truncated")
            }
            Self::ModuleAcceptedCompetingInitialization => {
                f.write_str("module accepted competing initialization")
            }
            Self::ModuleAncestorAllocation => f.write_str("module ancestor allocation"),
            Self::ModuleAncestorCount => f.write_str("module ancestor count"),
            Self::ModuleAncestorIsNotAPlainDirectory => {
                f.write_str("module ancestor is not a plain directory")
            }
            Self::ModuleAncestorLimit => f.write_str("module ancestor limit"),
            Self::ModuleAncestorMetadata => f.write_str("module ancestor metadata"),
            Self::ModuleAncestorPinUnavailable => f.write_str("module ancestor pin unavailable"),
            Self::ModuleFile => f.write_str("module file"),
            Self::ModuleFileIdentitySize => f.write_str("module file identity size"),
            Self::ModuleFileIdentityUnavailable => f.write_str("module file identity unavailable"),
            Self::ModuleFilePinMetadata => f.write_str("module file pin metadata"),
            Self::ModuleFilePinUnavailable => f.write_str("module file pin unavailable"),
            Self::ModuleFinalPathAllocation => f.write_str("module final path allocation"),
            Self::ModuleFinalPathChangedOrInvalid => {
                f.write_str("module final path changed or invalid")
            }
            Self::ModuleFinalPathIsNotAbsolute => f.write_str("module final path is not absolute"),
            Self::ModuleFinalPathSize => f.write_str("module final path size"),
            Self::ModuleFinalPathUnavailableOrOverLimit => {
                f.write_str("module final path unavailable or over limit")
            }
            Self::ModuleLoad => f.write_str("module load"),
            Self::ModuleLoadingPlatformUnavailable => {
                f.write_str("module loading platform unavailable")
            }
            Self::ModuleMappingUnavailable => f.write_str("module mapping unavailable"),
            Self::ModulePath => f.write_str("module path"),
            Self::ModulePinnedFileIdentityChanged => {
                f.write_str("module pinned file identity changed")
            }
            Self::ModulePinnedTargetIsNotAPlainFile => {
                f.write_str("module pinned target is not a plain file")
            }
            Self::ModuleResolvedAncestorChainChanged => {
                f.write_str("module resolved ancestor chain changed")
            }
            Self::NativeEntryImageMappingChanged => {
                f.write_str("native entry image mapping changed")
            }
            Self::NativeEntryImageOwnerAllocation => {
                f.write_str("native entry image owner allocation")
            }
            Self::NativeImageIdentityUnavailable => {
                f.write_str("native image identity unavailable")
            }
            Self::NativeImageNotInitialized => f.write_str("native image not initialized"),
            Self::NativeImageOwnerWithdrawn => f.write_str("native image owner withdrawn"),
            Self::NullLoadedImageAddress => f.write_str("null loaded image address"),
            Self::ProcessExportImageUnavailable => f.write_str("process export image unavailable"),
            Self::ProcessExportMappingChanged => f.write_str("process export mapping changed"),
            Self::ProcessExportMappingUnavailable => {
                f.write_str("process export mapping unavailable")
            }
            Self::ProcessImageNameAllocation => f.write_str("process image name allocation"),
            Self::ProcessImageNoLongerLoaded => f.write_str("process image no longer loaded"),
            Self::ProcessImageOwnerAllocation => f.write_str("process image owner allocation"),
            Self::ProcessLoaderMetadataWidth => f.write_str("process loader metadata width"),
            Self::RetainedProcessExportUnavailable => {
                f.write_str("retained process export unavailable")
            }
            Self::SuccessorImageIdentityAbsent => f.write_str("successor image identity absent"),
            Self::SuccessorImageReservationMismatch => {
                f.write_str("successor image reservation mismatch")
            }
            Self::SuccessorRegistryAllocation => f.write_str("successor registry allocation"),
            Self::SuccessorReservationAllocation => f.write_str("successor reservation allocation"),
            Self::SuccessorSelectsADifferentNativeImage => {
                f.write_str("successor selects a different native image")
            }
            Self::TableSelectionExportBelongsToAnotherImage => {
                f.write_str("table selection export belongs to another image")
            }
        }
    }
}
