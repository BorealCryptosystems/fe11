Cause contracts for `NativeLoadingRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-RequiredFunctionMissing"></a>

### `RequiredFunctionMissing`


Local detection/handling phase and implementation owner:

- `required` (module-level helper) — `src/native/functions.rs`.
- `check` (module-level helper) — `src/native/loading.rs`. Enclosing true branch: `!present(function)`.


<a id="cause-WindowsDependencySearchUnavailable"></a>

### `WindowsDependencySearchUnavailable`


Local detection/handling phase and implementation owner:

- `dependency_search_flags` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `!cfg!(windows)`.


<a id="cause-WindowsFilePinningUnavailable"></a>

### `WindowsFilePinningUnavailable`


Local detection/handling phase and implementation owner:

- `open_source` (module-level helper) — `src/native/platform.rs`. Enclosing match alternative: `crate::WindowsFilePinning::Pin { .. }`.


<a id="cause-WindowsImageComparisonRequiresFilePinning"></a>

### `WindowsImageComparisonRequiresFilePinning`


Local detection/handling phase and implementation owner:

- `validate_image_selection` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `!matches!(pinning, crate::WindowsFilePinning::Pin { .. })`.


<a id="cause-WindowsImageComparisonUnavailable"></a>

### `WindowsImageComparisonUnavailable`


Local detection/handling phase and implementation owner:

- `validate_image_selection` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `!cfg!(windows)`.


<a id="cause-WindowsLoaderObservationsUnavailable"></a>

### `WindowsLoaderObservationsUnavailable`


Local detection/handling phase and implementation owner:

- `validate_observations` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `!cfg!(windows)`.


<a id="cause-CompetingInitializerCannotOwnFinalize"></a>

### `CompetingInitializerCannotOwnFinalize`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::publish` — `src/native/image_reservation.rs`. Enclosing true branch: `self.borrowed_owner()`.


<a id="cause-CurrentProcessImageUnavailable"></a>

### `CurrentProcessImageUnavailable`


Local detection/handling phase and implementation owner:

- `open_scope` (module-level helper) — `src/native/process_image.rs`.


<a id="cause-EmptyWindowsDependencySearchSelection"></a>

### `EmptyWindowsDependencySearchSelection`


Local detection/handling phase and implementation owner:

- `dependency_search_flags` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `flags == 0`.


<a id="cause-ExternalImageAlreadyHasARuntime"></a>

### `ExternalImageAlreadyHasARuntime`


Local detection/handling phase and implementation owner:

- `establish` (module-level helper) — `src/native/initialization.rs`. Enclosing true branch: `reservation.borrowed_owner()`.


<a id="cause-ImageDispatchAllocation"></a>

### `ImageDispatchAllocation`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`.


<a id="cause-ImageGenerationExhausted"></a>

### `ImageGenerationExhausted`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing false branch: `let Some(image) = images.entries.get_mut(&address)`.
- `reserve_successor` (module-level helper) — `src/native/image_reservation.rs`.


<a id="cause-ImageInitializationGenerationChanged"></a>

### `ImageInitializationGenerationChanged`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::check_borrowed` — `src/native/image_reservation.rs`.
- `Reservation<'a>::publish` — `src/native/image_reservation.rs`. Enclosing true branch: `!self.owned.iter().all(|lease| { images.entries.get(&lease.address).is_some_and(|image| { image.generation == lease.generation && matches!(image.phase, Phase::Loading) }) })`.


<a id="cause-ImageReservationAllocation"></a>

### `ImageReservationAllocation`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`.
- `Reservation<'a>::include` — `src/native/image_reservation.rs`.
- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing false branch: `let Some(image) = images.entries.get_mut(&address)`.


<a id="cause-InitializationAttemptCountExhausted"></a>

### `InitializationAttemptCountExhausted`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `let Some(image) = images.entries.get_mut(&address)`.


<a id="cause-LoadedImageCheckIncomplete"></a>

### `LoadedImageCheckIncomplete`


Local detection/handling phase and implementation owner:

- `ExportFileCheck::check` — `src/native/platform.rs`. Enclosing match alternative: `Self::WindowsRequested { .. }`.
- `ExportFileCheck::completed_observation` — `src/native/platform.rs`. Enclosing match alternative: `Self::WindowsRequested { .. }`.


<a id="cause-LoadedImageFileIdentityMismatch"></a>

### `LoadedImageFileIdentityMismatch`


Local detection/handling phase and implementation owner:

- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `file_identity(&file)? != expected`.


<a id="cause-LoadedModuleIdentityMismatch"></a>

### `LoadedModuleIdentityMismatch`


Local detection/handling phase and implementation owner:

- `ExportFileCheck::check` — `src/native/platform.rs`. Enclosing true branch: `!super::mapped_image_matches(address, identity)?`.


<a id="cause-MappedImageFileUnavailable"></a>

### `MappedImageFileUnavailable`


Local detection/handling phase and implementation owner:

- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-MappedImagePathAllocation"></a>

### `MappedImagePathAllocation`


Local detection/handling phase and implementation owner:

- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`.
- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-MappedImagePathNamespaceUnavailable"></a>

### `MappedImagePathNamespaceUnavailable`


Local detection/handling phase and implementation owner:

- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `!units[..length].starts_with(DEVICE)`.


<a id="cause-MappedImagePathSize"></a>

### `MappedImagePathSize`


Local detection/handling phase and implementation owner:

- `validate_image_selection` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `let crate::WindowsImageConsistency::CompareToPinnedFile { maximum_mapped_path_code_units, } = selection`.
- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`.
- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`.
- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-MappedImagePathUnavailableOrTruncated"></a>

### `MappedImagePathUnavailableOrTruncated`


Local detection/handling phase and implementation owner:

- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `length == 0 || length >= units.len() || units[length] != 0 || units[..length].contains(&0)`.


<a id="cause-ModuleAcceptedCompetingInitialization"></a>

### `ModuleAcceptedCompetingInitialization`


Local detection/handling phase and implementation owner:

- `establish` (module-level helper) — `src/native/initialization.rs`. Enclosing true branch: `reservation.borrowed_owner()`.


<a id="cause-ModuleAncestorAllocation"></a>

### `ModuleAncestorAllocation`


Local detection/handling phase and implementation owner:

- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`.
- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleAncestorCount"></a>

### `ModuleAncestorCount`


Local detection/handling phase and implementation owner:

- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleAncestorIsNotAPlainDirectory"></a>

### `ModuleAncestorIsNotAPlainDirectory`


Local detection/handling phase and implementation owner:

- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `!metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0`.


<a id="cause-ModuleAncestorLimit"></a>

### `ModuleAncestorLimit`


Local detection/handling phase and implementation owner:

- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `maximum.is_some_and(|maximum| count > maximum)`.


<a id="cause-ModuleAncestorMetadata"></a>

### `ModuleAncestorMetadata`


Local detection/handling phase and implementation owner:

- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleAncestorPinUnavailable"></a>

### `ModuleAncestorPinUnavailable`


Local detection/handling phase and implementation owner:

- `pin_ancestors` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleFile"></a>

### `ModuleFile`


Local detection/handling phase and implementation owner:

- `open_source` (module-level helper) — `src/native/platform.rs`. Enclosing match alternative: `crate::WindowsFilePinning::NotRequested`.


<a id="cause-ModuleFileIdentitySize"></a>

### `ModuleFileIdentitySize`


Local detection/handling phase and implementation owner:

- `file_identity` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleFileIdentityUnavailable"></a>

### `ModuleFileIdentityUnavailable`


Local detection/handling phase and implementation owner:

- `file_identity` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `ok == 0`.


<a id="cause-ModuleFilePinMetadata"></a>

### `ModuleFilePinMetadata`


Local detection/handling phase and implementation owner:

- `pinned_file` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleFilePinUnavailable"></a>

### `ModuleFilePinUnavailable`


Local detection/handling phase and implementation owner:

- `pinned_file` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleFinalPathAllocation"></a>

### `ModuleFinalPathAllocation`


Local detection/handling phase and implementation owner:

- `final_path` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleFinalPathChangedOrInvalid"></a>

### `ModuleFinalPathChangedOrInvalid`


Local detection/handling phase and implementation owner:

- `final_path` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `length == 0 || length >= units.len() || units[length] != 0 || units[..length].contains(&0)`.


<a id="cause-ModuleFinalPathIsNotAbsolute"></a>

### `ModuleFinalPathIsNotAbsolute`


Local detection/handling phase and implementation owner:

- `final_path` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `!path.is_absolute()`.


<a id="cause-ModuleFinalPathSize"></a>

### `ModuleFinalPathSize`


Local detection/handling phase and implementation owner:

- `final_path` (module-level helper) — `src/native/platform/windows.rs`.
- `final_path` (module-level helper) — `src/native/platform/windows.rs`.


<a id="cause-ModuleFinalPathUnavailableOrOverLimit"></a>

### `ModuleFinalPathUnavailableOrOverLimit`


Local detection/handling phase and implementation owner:

- `final_path` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `required == 0 || required_usize > maximum.get()`.


<a id="cause-ModuleLoad"></a>

### `ModuleLoad`


Local detection/handling phase and implementation owner:

- `load_library` (module-level helper) — `src/native/platform.rs`.
- `load_library` (module-level helper) — `src/native/platform.rs`.


<a id="cause-ModuleLoadingPlatformUnavailable"></a>

### `ModuleLoadingPlatformUnavailable`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/native/platform.rs`.


<a id="cause-ModuleMappingUnavailable"></a>

### `ModuleMappingUnavailable`


Local detection/handling phase and implementation owner:

- `mapped_image_matches` (module-level helper) — `src/native/mapping.rs`.
- `mapped_image_matches` (module-level helper) — `src/native/mapping.rs`. Enclosing match alternative: `Err(_)`.


<a id="cause-ModulePath"></a>

### `ModulePath`


Local detection/handling phase and implementation owner:

- `open_source` (module-level helper) — `src/native/platform.rs`. Enclosing match alternative: `crate::WindowsFilePinning::NotRequested`.


<a id="cause-ModulePinnedFileIdentityChanged"></a>

### `ModulePinnedFileIdentityChanged`


Local detection/handling phase and implementation owner:

- `open_pinned` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `file_identity(&file)? != file_identity(&checked)?`.


<a id="cause-ModulePinnedTargetIsNotAPlainFile"></a>

### `ModulePinnedTargetIsNotAPlainFile`


Local detection/handling phase and implementation owner:

- `pinned_file` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `!metadata.is_file() || (reject_reparse && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)`.


<a id="cause-ModuleResolvedAncestorChainChanged"></a>

### `ModuleResolvedAncestorChainChanged`


Local detection/handling phase and implementation owner:

- `open_pinned` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `expected_resolved .as_ref() .is_some_and(|expected| expected != &resolved)`.


<a id="cause-NativeEntryImageMappingChanged"></a>

### `NativeEntryImageMappingChanged`


Local detection/handling phase and implementation owner:

- `LoadingImage<'a>::retain_entry_image` — `src/native/loading.rs`. Enclosing true branch: `super::platform::local_image_identity(address)? != identity`.


<a id="cause-NativeEntryImageOwnerAllocation"></a>

### `NativeEntryImageOwnerAllocation`


Local detection/handling phase and implementation owner:

- `LoadingImage<'a>::retain_entry_image` — `src/native/loading.rs`.


<a id="cause-NativeImageIdentityUnavailable"></a>

### `NativeImageIdentityUnavailable`


Local detection/handling phase and implementation owner:

- `local_image_identity` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `unsafe { GetModuleHandleExW(0x4 | 0x2, address as *const u16, &mut base) } == 0 || base.is_null()`.
- `local_image_identity` (module-level helper) — `src/native/platform.rs`. Enclosing true branch: `unsafe { dladdr(address as *const c_void, &mut info) } == 0 || info.base.is_null()`.


<a id="cause-NativeImageNotInitialized"></a>

### `NativeImageNotInitialized`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::check_borrowed` — `src/native/image_reservation.rs`.


<a id="cause-NativeImageOwnerWithdrawn"></a>

### `NativeImageOwnerWithdrawn`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `let Some(image) = images.entries.get_mut(&address)`.
- `Reservation<'a>::check_borrowed` — `src/native/image_reservation.rs`.


<a id="cause-NullLoadedImageAddress"></a>

### `NullLoadedImageAddress`


Local detection/handling phase and implementation owner:

- `check_mapping` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `address == 0`.


<a id="cause-ProcessExportImageUnavailable"></a>

### `ProcessExportImageUnavailable`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/native/process_image.rs`. Enclosing true branch: `found == 0 || handle.is_null()`.


<a id="cause-ProcessExportMappingChanged"></a>

### `ProcessExportMappingChanged`


Local detection/handling phase and implementation owner:

- `open_scope` (module-level helper) — `src/native/process_image.rs`. Enclosing true branch: `*retained as usize != address`.


<a id="cause-ProcessExportMappingUnavailable"></a>

### `ProcessExportMappingUnavailable`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/native/process_image.rs`.


<a id="cause-ProcessImageNameAllocation"></a>

### `ProcessImageNameAllocation`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/native/process_image.rs`. Enclosing true branch: `name.try_reserve_exact(bytes.len()).is_err()`.


<a id="cause-ProcessImageNoLongerLoaded"></a>

### `ProcessImageNoLongerLoaded`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/native/process_image.rs`. Enclosing match alternative: `Some(name)`.


<a id="cause-ProcessImageOwnerAllocation"></a>

### `ProcessImageOwnerAllocation`


Local detection/handling phase and implementation owner:

- `open_scope` (module-level helper) — `src/native/process_image.rs`.


<a id="cause-ProcessLoaderMetadataWidth"></a>

### `ProcessLoaderMetadataWidth`


Local detection/handling phase and implementation owner:

- `retain` (module-level helper) — `src/native/process_image.rs`. Enclosing true branch: `size < std::mem::size_of::<Info>() || info.is_null()`.


<a id="cause-RetainedProcessExportUnavailable"></a>

### `RetainedProcessExportUnavailable`


Local detection/handling phase and implementation owner:

- `open_scope` (module-level helper) — `src/native/process_image.rs`.


<a id="cause-SuccessorImageIdentityAbsent"></a>

### `SuccessorImageIdentityAbsent`


Local detection/handling phase and implementation owner:

- `reserve_successor` (module-level helper) — `src/native/image_reservation.rs`. Enclosing true branch: `previous.is_empty()`.


<a id="cause-SuccessorImageReservationMismatch"></a>

### `SuccessorImageReservationMismatch`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `let Some(successor) = self.successor`.


<a id="cause-SuccessorRegistryAllocation"></a>

### `SuccessorRegistryAllocation`


Local detection/handling phase and implementation owner:

- `reserve_successor` (module-level helper) — `src/native/image_reservation.rs`.


<a id="cause-SuccessorReservationAllocation"></a>

### `SuccessorReservationAllocation`


Local detection/handling phase and implementation owner:

- `reserve_successor` (module-level helper) — `src/native/image_reservation.rs`.


<a id="cause-SuccessorSelectsADifferentNativeImage"></a>

### `SuccessorSelectsADifferentNativeImage`


Local detection/handling phase and implementation owner:

- `Reservation<'a>::include` — `src/native/image_reservation.rs`. Enclosing true branch: `self.successor.is_some()`.


<a id="cause-TableSelectionExportBelongsToAnotherImage"></a>

### `TableSelectionExportBelongsToAnotherImage`


Local detection/handling phase and implementation owner:

- `check_export` (module-level helper) — `src/native/platform/windows.rs`. Enclosing true branch: `found == 0 || owner.is_null() || owner as usize != image_base`.
