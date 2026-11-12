// SPDX-License-Identifier: Apache-2.0
//! Functions used by opening itself; resource routes admit their own cleanup.
use super::platform::SourceFiles;
use crate::{Error, Result};
use std::cell::Cell;

/// Retain both the mapped image and its open file if a loading call has not
/// completed. The open file also protects the /proc/self/fd loader identity.
pub(super) struct LoadingImage<'a> {
    library: Option<libloading::Library>,
    file: Option<SourceFiles>,
    providers: std::cell::RefCell<Vec<libloading::Library>>,
    pub uncertain: &'a Cell<bool>,
}

impl<'a> LoadingImage<'a> {
    pub fn new(
        library: libloading::Library,
        file: Option<SourceFiles>,
        providers: Vec<libloading::Library>,
        uncertain: &'a Cell<bool>,
    ) -> Self {
        Self {
            library: Some(library),
            file,
            providers: std::cell::RefCell::new(providers),
            uncertain,
        }
    }

    // Only consuming into_parts and Drop remove the library. A borrowed
    // loading owner therefore always retains the image, even after uncertainty.
    pub fn library(&self) -> &libloading::Library {
        self.library.as_ref().expect("loading image owns library")
    }

    /// Extend image ownership for an entry discovered after the first lookup,
    /// including legacy selection and the selected initializer. The trusted
    /// provider keeps returned table pointers valid during selection. This
    /// reference follows finalization and the same uncertainty quarantine.
    pub fn retain_entry_image(&self, address: usize) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        {
            let mut providers = self.providers.borrow_mut();
            providers.try_reserve_exact(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::NativeEntryImageOwnerAllocation,
                ))
            })?;
            let identity = super::platform::local_image_identity(address)?;
            let provider = super::process_image::retain(address)?;
            if super::platform::local_image_identity(address)? != identity {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::NativeEntryImageMappingChanged,
                )));
            }
            providers.push(provider);
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = address;
            Err(Error::Unsupported(crate::UnsupportedReason::NativeLoading(
                crate::NativeLoadingUnsupported::CurrentProcessLoaderPlatform,
            )))
        }
    }

    pub fn into_parts(
        mut self,
    ) -> (
        Option<libloading::Library>,
        Option<SourceFiles>,
        Vec<libloading::Library>,
    ) {
        (
            self.library.take(),
            self.file.take(),
            std::mem::take(self.providers.get_mut()),
        )
    }
}

impl Drop for LoadingImage<'_> {
    fn drop(&mut self) {
        if self.uncertain.get() {
            std::mem::forget(std::mem::take(self.providers.get_mut()));
            // No synchronous owner can prove completion. Do not unload code
            // or recycle the file descriptor while a retained frame is live.
            if let Some(library) = self.library.take() {
                std::mem::forget(library);
            }
            if let Some(file) = self.file.take() {
                std::mem::forget(file);
            }
        }
    }
}

const REQUIRED: [&str; 3] = ["C_Initialize", "C_Finalize", "C_GetInfo"];

// The caller observes the immutable, exact selected table. This pure gate
// neither negotiates another interface nor calls or substitutes a function.
pub(super) fn check(present: impl Fn(&'static str) -> bool) -> Result<()> {
    for function in REQUIRED {
        if !present(function) {
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::RequiredFunctionMissing { function },
            )));
        }
    }
    Ok(())
}

use super::*;

impl Native {
    pub fn open(
        path: &Path,
        identity: FileIdentity,
        file: platform::SourceFiles,
        export_check: ExportFileCheck,
        selection: crate::InterfaceSelection,
        request: initialization::Request<'_>,
        interface_discovery: crate::InterfaceDiscoveryLimits,
        windows_dependency_search: crate::WindowsDependencySearch,
        windows_loader_observations: crate::WindowsLoaderObservations,
        notifications: crate::notify::NotifyRegistry,
    ) -> Result<(Self, crate::WindowsLoaderReport)> {
        Self::open_file(
            path,
            identity,
            file,
            export_check,
            selection,
            LoadPurpose::Open {
                request,
                notifications,
            },
            interface_discovery,
            windows_dependency_search,
            windows_loader_observations,
        )?
        .initialized()
    }

    pub(crate) fn observe_file(
        path: &Path,
        identity: FileIdentity,
        file: platform::SourceFiles,
        export_check: ExportFileCheck,
        selection: crate::InterfaceSelection,
        interface_discovery: crate::InterfaceDiscoveryLimits,
        windows_dependency_search: crate::WindowsDependencySearch,
        windows_loader_observations: crate::WindowsLoaderObservations,
    ) -> Result<crate::FunctionCatalog> {
        Self::open_file(
            path,
            identity,
            file,
            export_check,
            selection,
            LoadPurpose::Observe,
            interface_discovery,
            windows_dependency_search,
            windows_loader_observations,
        )?
        .observed()
    }

    pub(super) fn open_file(
        path: &Path,
        identity: FileIdentity,
        file: platform::SourceFiles,
        export_check: ExportFileCheck,
        selection: crate::InterfaceSelection,
        purpose: LoadPurpose<'_>,
        interface_discovery: crate::InterfaceDiscoveryLimits,
        windows_dependency_search: crate::WindowsDependencySearch,
        windows_loader_observations: crate::WindowsLoaderObservations,
    ) -> Result<LoadingOutcome> {
        // File references retain provenance, not exclusive initialization
        // authority. The actual export-image domain coordinates aliases and
        // preserves the active owner's dispatch and Finalize contract.
        reserve_file(identity)?;
        let image_uncertain = std::cell::Cell::new(false);
        let result = Self::load(
            Some(path),
            Some(identity),
            Some(file),
            export_check,
            selection,
            purpose,
            interface_discovery,
            windows_dependency_search,
            windows_loader_observations,
            &image_uncertain,
        );
        if (result.is_err() || matches!(&result, Ok(LoadingOutcome::Observed(_))))
            && !image_uncertain.get()
        {
            release_file(identity);
        }
        result
    }

    pub(crate) fn open_process(
        selection: crate::InterfaceSelection,
        request: initialization::Request<'_>,
        discovery: crate::InterfaceDiscoveryLimits,
        notifications: crate::notify::NotifyRegistry,
    ) -> Result<(Self, crate::WindowsLoaderReport)> {
        let uncertain = std::cell::Cell::new(false);
        Self::load(
            None,
            None,
            None,
            ExportFileCheck::NotRequested,
            selection,
            LoadPurpose::Open {
                request,
                notifications,
            },
            discovery,
            crate::WindowsDependencySearch::ApplicationConfigured,
            crate::WindowsLoaderObservations::NotRequested,
            &uncertain,
        )?
        .initialized()
    }

    pub(crate) fn observe_process(
        selection: crate::InterfaceSelection,
        discovery: crate::InterfaceDiscoveryLimits,
    ) -> Result<crate::FunctionCatalog> {
        let uncertain = std::cell::Cell::new(false);
        Self::load(
            None,
            None,
            None,
            ExportFileCheck::NotRequested,
            selection,
            LoadPurpose::Observe,
            discovery,
            crate::WindowsDependencySearch::ApplicationConfigured,
            crate::WindowsLoaderObservations::NotRequested,
            &uncertain,
        )?
        .observed()
    }

    pub(super) fn load(
        path: Option<&Path>,
        identity: Option<FileIdentity>,
        file: Option<platform::SourceFiles>,
        export_check: ExportFileCheck,
        selection: crate::InterfaceSelection,
        purpose: LoadPurpose<'_>,
        interface_discovery: crate::InterfaceDiscoveryLimits,
        windows_dependency_search: crate::WindowsDependencySearch,
        windows_loader_observations: crate::WindowsLoaderObservations,
        image_uncertain: &std::cell::Cell<bool>,
    ) -> Result<LoadingOutcome> {
        let (library, loader_report, providers, mut process_exports) = match path {
            Some(path) => {
                // SAFETY: the application selected this trusted native image;
                // file observations provide no sandbox for its initializers.
                let (library, report) = unsafe {
                    platform::load_library(
                        path,
                        windows_dependency_search,
                        windows_loader_observations,
                    )
                }?;
                (library, report, Vec::new(), None)
            }
            None => {
                let image = process_image::open(selection)?;
                (
                    image.library,
                    crate::WindowsLoaderReport::not_requested(),
                    image.providers,
                    Some(image.exports),
                )
            }
        };
        let (library, export_check) = platform::check_loaded_image(library, export_check)?;
        let image = loading::LoadingImage::new(library, file, providers, image_uncertain);
        let library = image.library();
        // Discovery does not infer shared runtime state from visible exports.
        // The application coordinates its native lifecycle; LoadingImage keeps
        // code and borrowed descriptors alive independently of runtime leases.
        // SAFETY: C_GetFunctionList is the standard exported C ABI; its result is
        // retained only while this library owner lives. A dishonest provider is TCB.
        // On Linux, dlclose need not unmap a library. A recycled /proc/self/fd/N name
        // can resolve to an older loader cache entry: verify the actual mapping
        // before invoking any PKCS#11 entry point, not merely the loader name.
        // Ordinary Windows loading explicitly reports that check NotRequested.
        let mut selection_calls = crate::interfaces::SelectionCalls::default();
        let mut legacy = |calls: &mut crate::interfaces::SelectionCalls, expected| -> Result<_> {
            // SAFETY: standard exported signature, retained library.
            let entry = unsafe {
                library.get::<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>(
                    b"C_GetFunctionList\0",
                )
            }
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::FunctionTableExport,
                ))
            })?;
            export_check.check(*entry as usize)?;
            // ProviderDefault may reach legacy after a successful interface
            // query. Retain that actual export before invoking it;
            // it need not come from the GetInterface image already reserved.
            if let Some(exports) = process_exports.as_mut() {
                image.retain_entry_image(*entry as usize)?;
                if !exports.contains(&(*entry as usize)) {
                    // Keep this late selection export in the file-provenance
                    // observation too. Reserve its slot and the initializer's
                    // later slot before C, without an implicit Vec allocation.
                    exports.try_reserve_exact(2).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::NativeExecution(
                            crate::NativeExecutionRejection::ProcessExportAllocation,
                        ))
                    })?;
                    exports.push(*entry as usize);
                }
            }
            let mut ptr = frame::NativeFrame::new(std::ptr::null_mut::<CK_FUNCTION_LIST>())?;
            crate::interfaces::record_selection(&mut calls.list)?;
            // SAFETY: ptr is an aligned live output slot.
            let rv = unsafe { entry(&mut *ptr) };
            ptr.loading_result(rv, "C_GetFunctionList", &image.uncertain, false)?;
            if (*ptr).is_null() {
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::NullFunctionTable,
                )));
            }
            // SAFETY: the provider owns the version prefix, read before layout.
            let version = unsafe { std::ptr::read_unaligned((*ptr).cast::<CK_VERSION>()) };
            qualified_table_version(version, expected)?;
            // SAFETY: 2.20, draft 2.30 and 2.40 have the same 68 declarations
            // in the archived headers. The exact selected version was checked;
            // trust in the provider's allocation is the native-module boundary.
            Ok((
                crate::interfaces::SelectedTable::V240(unsafe { std::ptr::read_unaligned(*ptr) }),
                0,
            ))
        };
        let (selected, interface_flags) = match selection {
            crate::InterfaceSelection::Legacy220 => legacy(&mut selection_calls, (2, 20))?,
            crate::InterfaceSelection::Legacy230Draft => legacy(&mut selection_calls, (2, 30))?,
            crate::InterfaceSelection::Legacy240 => legacy(&mut selection_calls, (2, 40))?,
            crate::InterfaceSelection::ProviderDefault => {
                match crate::interfaces::select_default(
                    library,
                    export_check,
                    &mut selection_calls,
                    &image.uncertain,
                )? {
                    Some(selected) => selected,
                    None => legacy(&mut selection_calls, (2, 40))?,
                }
            }
            crate::InterfaceSelection::Standard {
                version,
                required_flags,
            } => crate::interfaces::select(
                library,
                export_check,
                version,
                required_flags,
                interface_discovery,
                &mut selection_calls,
                &image.uncertain,
            )?,
        };
        let export_file_identity = export_check.completed_observation()?;
        let views = selected.views();
        let table = views.common;
        let catalog = selected.catalog();
        let (request, notifications) = match purpose {
            // Presence observation does not initialize or attach a runtime.
            LoadPurpose::Observe => return Ok(LoadingOutcome::Observed(catalog)),
            LoadPurpose::Open {
                request,
                notifications,
            } => (request, notifications),
        };
        loading::check(|name| catalog.observation(name) == Some(crate::FunctionPresence::Present))?;
        let lifecycle = functions::Lifecycle::resolve(&table)?;
        if process_exports.is_some() {
            image.retain_entry_image(lifecycle.initialize as usize)?;
        }
        // Both source kinds reserve the same actual initializer image while their
        // libraries retain its image. An address is never an archive binding.
        let image_reservation = image_reservation::Reservation::for_initializer(
            platform::local_image_identity(lifecycle.initialize as usize)?,
            image_uncertain,
            request.successor(),
        )?;
        let process_file = process_exports.map(|mut addresses| {
            addresses.push(lifecycle.initialize as usize);
            crate::module::provenance::observe_process_file(&addresses)
        });
        let prepared = initialization::establish(
            request,
            &table,
            lifecycle.initialize,
            interface_flags,
            &image,
            &image_reservation,
        )?;
        let mut calls = BTreeMap::new();
        calls.insert("C_GetFunctionList", selection_calls.list);
        calls.insert("C_GetInterfaceList", selection_calls.interfaces);
        calls.insert("C_GetInterface", selection_calls.interface);
        calls.insert("C_Initialize", prepared.initialize_calls);
        // Reserve the Drop diagnostic slot while building the owner.
        calls.insert("C_Finalize", 0);
        // Symmetric-operation counters exist before secret sequences, avoiding map allocation
        // between Init and Final. Zero is an uncalled function, not evidence.
        for name in [
            "C_GenerateKey",
            "C_EncryptInit",
            "C_Encrypt",
            "C_EncryptUpdate",
            "C_EncryptFinal",
            "C_DecryptInit",
            "C_Decrypt",
            "C_DecryptUpdate",
            "C_DecryptFinal",
            "C_SignInit",
            "C_Sign",
            "C_SignUpdate",
            "C_SignFinal",
            "C_VerifyInit",
            "C_Verify",
            "C_VerifyUpdate",
            "C_VerifyFinal",
            "C_VerifySignatureInit",
            "C_VerifySignature",
            "C_VerifySignatureUpdate",
            "C_VerifySignatureFinal",
            "C_MessageEncryptInit",
            "C_EncryptMessage",
            "C_MessageEncryptFinal",
        ] {
            calls.insert(name, 0);
        }
        // Advanced-operation counters are inserted before any advanced sequence.
        for name in [
            "C_DigestInit",
            "C_DigestUpdate",
            "C_DigestFinal",
            "C_MessageEncryptInit",
            "C_EncryptMessage",
            "C_EncryptMessageBegin",
            "C_EncryptMessageNext",
            "C_MessageEncryptFinal",
            "C_MessageDecryptInit",
            "C_DecryptMessage",
            "C_DecryptMessageBegin",
            "C_DecryptMessageNext",
            "C_MessageDecryptFinal",
            "C_MessageSignInit",
            "C_SignMessage",
            "C_SignMessageBegin",
            "C_SignMessageNext",
            "C_MessageSignFinal",
            "C_MessageVerifyInit",
            "C_VerifyMessage",
            "C_VerifyMessageBegin",
            "C_VerifyMessageNext",
            "C_MessageVerifyFinal",
            "C_SessionCancel",
            "C_DigestEncryptUpdate",
            "C_DecryptDigestUpdate",
            "C_SignEncryptUpdate",
            "C_DecryptVerifyUpdate",
            "C_GetOperationState",
            "C_SetOperationState",
            "C_AsyncComplete",
            "C_AsyncGetID",
            "C_AsyncJoin",
            "C_GetSessionValidationFlags",
        ] {
            calls.entry(name).or_insert(0);
        }
        let (library, file, providers) = image.into_parts();
        let image = Arc::new(image::LoadedImage::with_initialization(
            library,
            file,
            providers,
            prepared.owner,
        ));
        let dispatch = prepared.serialized.then(|| dispatch::Dispatch::new(&image));
        let uncertainty = Arc::new(Uncertainty::default());
        let image_leases = image_reservation.publish(dispatch.as_ref(), &uncertainty)?;
        Ok(LoadingOutcome::Initialized(
            Self {
                catalog,
                process_file,
                table,
                lifecycle,
                login_user: views.login_user,
                interface_flags,
                export_file_identity,
                authenticated_transport: views.authenticated_transport,
                messages: views.messages,
                asynchronous: views.asynchronous,
                kem: views.kem,
                verify_signature: views.verify_signature,
                image,
                dispatch: dispatch.clone(),
                notifications,
                finalization: Finalization::NotIssued,
                drop_policy: prepared.drop_policy,
                events: Arc::new(events::EventRegistry::with_dispatch(
                    identity,
                    image_leases,
                    dispatch,
                )),
                uncertain: uncertainty,
                calls: Mutex::new(CallCounters {
                    values: calls,
                    incomplete: false,
                }),
            },
            loader_report,
        ))
    }
}
