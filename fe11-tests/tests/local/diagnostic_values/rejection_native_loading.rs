// SPDX-License-Identifier: Apache-2.0
//! Public NativeLoadingRejection values retain identity through category conversion.
use fe11::{Error, NativeLoadingRejection, RejectionReason};

#[test]
fn variants_preserve_category_and_payload() {
    let cases = [
        NativeLoadingRejection::RequiredFunctionMissing { function: "" },
        NativeLoadingRejection::RequiredFunctionMissing { function: "C_Test" },
        NativeLoadingRejection::RequiredFunctionMissing {
            function: "fonction_é",
        },
        NativeLoadingRejection::RequiredFunctionMissing { function: "a\0b" },
        NativeLoadingRejection::WindowsDependencySearchUnavailable,
        NativeLoadingRejection::WindowsFilePinningUnavailable,
        NativeLoadingRejection::WindowsImageComparisonRequiresFilePinning,
        NativeLoadingRejection::WindowsImageComparisonUnavailable,
        NativeLoadingRejection::WindowsLoaderObservationsUnavailable,
        NativeLoadingRejection::CompetingInitializerCannotOwnFinalize,
        NativeLoadingRejection::CurrentProcessImageUnavailable,
        NativeLoadingRejection::EmptyWindowsDependencySearchSelection,
        NativeLoadingRejection::ExternalImageAlreadyHasARuntime,
        NativeLoadingRejection::ImageDispatchAllocation,
        NativeLoadingRejection::ImageGenerationExhausted,
        NativeLoadingRejection::ImageInitializationGenerationChanged,
        NativeLoadingRejection::ImageReservationAllocation,
        NativeLoadingRejection::InitializationAttemptCountExhausted,
        NativeLoadingRejection::LoadedImageCheckIncomplete,
        NativeLoadingRejection::LoadedImageFileIdentityMismatch,
        NativeLoadingRejection::LoadedModuleIdentityMismatch,
        NativeLoadingRejection::MappedImageFileUnavailable,
        NativeLoadingRejection::MappedImagePathAllocation,
        NativeLoadingRejection::MappedImagePathNamespaceUnavailable,
        NativeLoadingRejection::MappedImagePathSize,
        NativeLoadingRejection::MappedImagePathUnavailableOrTruncated,
        NativeLoadingRejection::ModuleAcceptedCompetingInitialization,
        NativeLoadingRejection::ModuleAncestorAllocation,
        NativeLoadingRejection::ModuleAncestorCount,
        NativeLoadingRejection::ModuleAncestorIsNotAPlainDirectory,
        NativeLoadingRejection::ModuleAncestorLimit,
        NativeLoadingRejection::ModuleAncestorMetadata,
        NativeLoadingRejection::ModuleAncestorPinUnavailable,
        NativeLoadingRejection::ModuleFile,
        NativeLoadingRejection::ModuleFileIdentitySize,
        NativeLoadingRejection::ModuleFileIdentityUnavailable,
        NativeLoadingRejection::ModuleFilePinMetadata,
        NativeLoadingRejection::ModuleFilePinUnavailable,
        NativeLoadingRejection::ModuleFinalPathAllocation,
        NativeLoadingRejection::ModuleFinalPathChangedOrInvalid,
        NativeLoadingRejection::ModuleFinalPathIsNotAbsolute,
        NativeLoadingRejection::ModuleFinalPathSize,
        NativeLoadingRejection::ModuleFinalPathUnavailableOrOverLimit,
        NativeLoadingRejection::ModuleLoad,
        NativeLoadingRejection::ModuleLoadingPlatformUnavailable,
        NativeLoadingRejection::ModuleMappingUnavailable,
        NativeLoadingRejection::ModulePath,
        NativeLoadingRejection::ModulePinnedFileIdentityChanged,
        NativeLoadingRejection::ModulePinnedTargetIsNotAPlainFile,
        NativeLoadingRejection::ModuleResolvedAncestorChainChanged,
        NativeLoadingRejection::NativeEntryImageMappingChanged,
        NativeLoadingRejection::NativeEntryImageOwnerAllocation,
        NativeLoadingRejection::NativeImageIdentityUnavailable,
        NativeLoadingRejection::NativeImageNotInitialized,
        NativeLoadingRejection::NativeImageOwnerWithdrawn,
        NativeLoadingRejection::NullLoadedImageAddress,
        NativeLoadingRejection::ProcessExportImageUnavailable,
        NativeLoadingRejection::ProcessExportMappingChanged,
        NativeLoadingRejection::ProcessExportMappingUnavailable,
        NativeLoadingRejection::ProcessImageNameAllocation,
        NativeLoadingRejection::ProcessImageNoLongerLoaded,
        NativeLoadingRejection::ProcessImageOwnerAllocation,
        NativeLoadingRejection::ProcessLoaderMetadataWidth,
        NativeLoadingRejection::RetainedProcessExportUnavailable,
        NativeLoadingRejection::SuccessorImageIdentityAbsent,
        NativeLoadingRejection::SuccessorImageReservationMismatch,
        NativeLoadingRejection::SuccessorRegistryAllocation,
        NativeLoadingRejection::SuccessorReservationAllocation,
        NativeLoadingRejection::SuccessorSelectsADifferentNativeImage,
        NativeLoadingRejection::TableSelectionExportBelongsToAnotherImage,
    ];
    for value in cases {
        let category: RejectionReason = value.into();
        assert!(matches!(category, RejectionReason::NativeLoading(actual) if actual == value));
        let error = Error::Rejected(category);
        assert_eq!(error.clone(), error);
        assert!(
            matches!(&error, Error::Rejected(RejectionReason::NativeLoading(actual)) if *actual == value)
        );
        assert!(!value.to_string().is_empty());
        assert!(!category.to_string().is_empty());
        assert!(!error.to_string().is_empty());
        assert!(!format!("{value:?}").is_empty());
    }
}
