// SPDX-License-Identifier: Apache-2.0
//! Assemble module configuration, native ownership and initial discovery.
//! Initialization, shared resource domains and their retained owners are established together.

use super::*;

impl Module {
    /// Load the selected native module with all opening choices supplied by the caller.
    /// This owning mode controls its initialization and private sessions. Other
    /// processes may use the same token. For coordinated participants in this
    /// process use ModuleBuilder::open_shared or attach_initialized; independent
    /// native calls must not bypass their lifecycle and buffer-loan protocol.
    /// No interface, budget or representation is selected here.
    /// The application must establish that its trusted native module matches the
    /// Fe11-sys ABI: natural C alignment on Linux GNU x86_64, packed(1) on Windows
    /// MSVC x86_64. PKCS#11 version negotiation cannot establish that packing.
    pub fn open(config: ModuleConfig, options: ModuleOptions) -> Result<Self> {
        Self::builder(config, options).open()
    }

    /// Read the context's immutable choice without probing the native module.
    pub fn chacha_nonce_length_encoding(&self) -> crate::ChaChaNonceLengthEncoding {
        self.inner.chacha_nonce_length_encoding
    }

    /// Immutable local object-count choices; does not query the module.
    pub fn object_limits(&self) -> ObjectLimits {
        self.inner.object_limits
    }

    /// The explicitly selected optional software component, if any. Reading this
    /// choice does not load an image or probe a cryptographic capability.
    pub fn verify_engine(&self) -> Option<&crate::VerifyEngine> {
        self.inner.verify_engine.as_ref()
    }

    pub(super) fn open_selected_symmetric(
        config: provenance::Source,
        discovery: DiscoverySelection,
        initialization: InitializationOptions,
        reserved_initialization: Option<InitializationReserved>,
        initialization_mutexes: Option<InitializationMutexes>,
        interface_discovery: crate::InterfaceDiscoveryLimits,
        object_limits: ObjectLimits,
        selection: crate::InterfaceSelection,
        crypto_options: crate::CryptoOptions,
        session_policy: crate::SessionPolicy,
        symmetric_limits: crate::SymmetricLimits,
        chacha_nonce_length_encoding: crate::ChaChaNonceLengthEncoding,
        windows_file_pinning: WindowsFilePinning,
        windows_dependency_search: WindowsDependencySearch,
        windows_loader_observations: WindowsLoaderObservations,
        windows_image_consistency: WindowsImageConsistency,
        verify_engine: Option<crate::VerifyEngine>,
        external_initialization: Option<ExternalInitialization>,
        successor: Option<&runtime::SuccessorContext>,
        initialization_diagnostic: &mut Option<crate::error::PreparedCompletion>,
    ) -> Result<Self> {
        crate::native::platform::validate_image_selection(
            windows_file_pinning,
            windows_image_consistency,
        )?;
        crate::native::platform::dependency_search_flags(windows_dependency_search)?;
        crate::native::platform::validate_observations(windows_loader_observations)?;
        selection.validate()?;
        crypto_options.limits.validate()?;
        let symmetric_budget = match successor {
            Some(context) => context.budget.clone(),
            None => Arc::new(crate::symmetric::memory::Budget::new(symmetric_limits)?),
        };
        let finalization = crate::admission_wait::ResourceRwLock::new(
            FinalizationDiagnostics::prepare(&symmetric_budget)?,
        );
        let notifications = crate::notify::NotifyRegistry::prepare(&symmetric_budget)?;
        let l = config.limits();
        session_policy.validate()?;
        let (native, windows_loader_report, provenance, pinning_observation) = match config {
            provenance::Source::File(config) => {
                if !config.path.is_absolute() {
                    return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::AbsoluteModulePathRequired,
                    )));
                }
                // Inspect reparse ancestry before canonicalization erases it.
                let (path, mut source, pinning) =
                    crate::native::platform::open_source(&config.path, windows_file_pinning)?;
                if !source
                    .file
                    .metadata()
                    .map_err(|_| {
                        Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                            crate::ModuleLifecycleRejection::ModuleMetadata,
                        ))
                    })?
                    .is_file()
                {
                    return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::ModuleIsNotRegularFile,
                    )));
                }
                let sha256 = provenance::digest(&mut source.file)?;
                let integrity = config.integrity.evaluate(sha256)?;
                let (load_path, identity, export_check) = crate::native::platform::prepare(
                    &source.file,
                    &path,
                    windows_image_consistency,
                )?;
                let request = crate::native::initialization::Request::prepare(
                    external_initialization,
                    initialization,
                    reserved_initialization,
                    initialization_mutexes,
                    &symmetric_budget,
                    initialization_diagnostic,
                    successor.map(|context| &context.image),
                )?;
                let (native, report) = Native::open(
                    &load_path,
                    identity,
                    source,
                    export_check,
                    selection,
                    request,
                    interface_discovery,
                    windows_dependency_search,
                    windows_loader_observations,
                    notifications,
                )?;
                (
                    native,
                    report,
                    ModuleProvenance::File {
                        file: ModuleFileObservation { path, sha256 },
                        integrity,
                    },
                    pinning,
                )
            }
            provenance::Source::Process(_) => {
                // These choices refer to a file load that will not occur.
                // Refuse incompatible requests before Initialize, never report
                // successful pinning or directory selection for a fake path.
                if !matches!(windows_file_pinning, WindowsFilePinning::NotRequested)
                    || !matches!(
                        windows_image_consistency,
                        WindowsImageConsistency::NotRequested
                    )
                    || !matches!(
                        windows_dependency_search,
                        WindowsDependencySearch::ApplicationConfigured
                    )
                    || !matches!(
                        windows_loader_observations,
                        WindowsLoaderObservations::NotRequested
                    )
                {
                    return Err(Error::Unsupported(
                        crate::UnsupportedReason::ModuleLifecycle(
                            crate::ModuleLifecycleUnsupported::FileLoadingOptionsForProcessSource,
                        ),
                    ));
                }
                let request = crate::native::initialization::Request::prepare(
                    external_initialization,
                    initialization,
                    reserved_initialization,
                    initialization_mutexes,
                    &symmetric_budget,
                    initialization_diagnostic,
                    successor.map(|context| &context.image),
                )?;
                let (mut native, report) =
                    Native::open_process(selection, request, interface_discovery, notifications)?;
                let file = native.process_file.take().ok_or(Error::Rejected(
                    crate::RejectionReason::ModuleLifecycle(
                        crate::ModuleLifecycleRejection::ProcessObservationOwnerAbsent,
                    ),
                ))?;
                (
                    native,
                    report,
                    ModuleProvenance::Process { file },
                    crate::Observation::NotRequested,
                )
            }
        };
        let binding_identity = provenance.binding()?;
        // Native::load has published the image so another loader may already
        // share its dispatch. Keep initial discovery serialized until StateLock
        // and its context notifications take over, including every error path.
        let _discovery_dispatch = native
            .dispatch
            .as_ref()
            .map(|dispatch| {
                dispatch.enter_loading(&crate::admission_wait::current(), &|| {
                    if native.is_uncertain() {
                        Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                            crate::ModuleLifecycleRejection::NativeStateUncertain,
                        )))
                    } else {
                        Ok(())
                    }
                })
            })
            .transpose()?;
        if native.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        let mut raw = crate::native::frame::NativeFrame::new(crate::native::output::info())?;
        native.record("C_GetInfo")?;
        // SAFETY: output is initialized and sized for CK_INFO; native owner is live.
        let rv = unsafe { (native.lifecycle.information)(&mut *raw) };
        raw.retain_if_pending(rv, &native);
        check_discovery(&native, rv, "C_GetInfo")?;
        // CK_INFO describes the module; its version never selects an ABI layout
        // or grants capabilities. Native already checked the exact table prefix.
        let initial_discovery = discover_selected(&native, l, discovery, &|_, _| {})?;
        let discovered = initial_discovery.tokens.clone();
        let tokens = discovered
            .iter()
            .filter(|t| t.flags & CKF_TOKEN_INITIALIZED as u64 != 0)
            .cloned()
            .collect();
        let generation_base = successor.map_or(0, |context| context.generation);
        let next_generation =
            generation_base
                .checked_add(discovered.len() as u64)
                .ok_or(Error::Rejected(
                    crate::RejectionReason::TokenAdministration(
                        crate::TokenAdministrationRejection::TokenGenerationExhausted,
                    ),
                ))?;
        let foreign = Arc::new(foreign::Registry::new(
            native.image.clone(),
            native.dispatch.clone(),
        ));
        let current_tokens = discovered
            .into_iter()
            .enumerate()
            .map(|(i, capabilities)| {
                let domain = foreign.domain(capabilities.identity.slot)?;
                Ok(Arc::new(TokenSnapshot::with_domain(
                    capabilities,
                    generation_base + i as u64 + 1,
                    domain,
                )))
            })
            .collect::<Result<Vec<_>>>()?;
        let info = ModuleInfo {
            provenance,
            windows_loader_report,
            windows_loader_observations,
            windows_dependency_search,
            export_file_identity: native.export_file_identity.clone(),
            windows_image_consistency: WindowsImageConsistencyReport::new(
                windows_image_consistency,
                match windows_image_consistency {
                    WindowsImageConsistency::NotRequested => crate::Observation::NotRequested,
                    WindowsImageConsistency::CompareToPinnedFile { .. } => {
                        native.export_file_identity.clone()
                    }
                },
            ),
            windows_file_pinning: WindowsFilePinningReport::new(
                windows_file_pinning,
                pinning_observation,
            ),
            interface_version: (raw.cryptokiVersion.major, raw.cryptokiVersion.minor),
            function_list_version: (native.table.version.major, native.table.version.minor),
            interface_flags: native.interface_flags,
            functions: native.function_catalog(),
            library_version: (raw.libraryVersion.major, raw.libraryVersion.minor),
            manufacturer: raw.manufacturerID,
            description: raw.libraryDescription,
        };
        let session_limit = crate::SessionLimit {
            total: l.sessions,
            read_write: session_policy.module_read_write,
        };
        let session_ledger = Arc::new(match successor {
            Some(context) => crate::session_budget::SessionLedger::successor(
                context.sessions.clone(),
                session_limit,
            )?,
            None => crate::session_budget::SessionLedger::new(session_limit),
        });
        let slot_events = native.events.clone();
        let availability = native.uncertainty_flag();
        let objects = crate::registry::Registry::new(object_limits.object_references);
        let managed = crate::registry::Registry::new(object_limits.managed_references);
        let catalog = crate::managed::Catalog::new_with_budget(
            object_limits.destination_reservations,
            symmetric_budget.clone(),
        );
        let object_wake = objects.admission_wake();
        let managed_wake = managed.admission_wake();
        let dispatch = native.dispatch.clone();
        let state = State {
            foreign: foreign.clone(),
            operations: crate::advanced::Ledger::new(
                Arc::clone(&symmetric_budget),
                [objects.admission_wake(), managed.admission_wake()],
            ),
            native,
            closed: false,
            session_ledger: session_ledger.clone(),
            objects,
            managed,
            current_tokens: Arc::new(Mutex::new(TokenRegistry {
                tokens: current_tokens,
                next_generation,
                revision: 0,
            })),
        };
        let state = crate::state_lock::StateLock::with_dispatch(state, dispatch)?;
        let context_wakes = Arc::new(crate::admission_wait::ContextWakes::new([
            session_ledger.admission_wake(),
            symmetric_budget.admission_wake(),
            object_wake,
            managed_wake,
            catalog.scan_wake(),
            state.admission_wake(),
        ]));
        availability.bind_admission(&context_wakes)?;
        slot_events.bind_admission(&context_wakes)?;
        Ok(Self {
            inner: Arc::new(Inner {
                foreign,
                next_client: std::sync::atomic::AtomicU64::new(0),
                attribute_extension_scope: std::sync::OnceLock::new(),
                availability,
                slot_events,
                module_binding: ModuleBinding {
                    identity: binding_identity,
                    table_version: info.function_list_version,
                    interface_flags: info.interface_flags,
                },
                object_limits,
                reservations: Mutex::new(catalog),
                state,
                finalization,
                tokens,
                limits: l,
                session_policy,
                session_ledger,
                crypto_options,
                symmetric_budget,
                context_wakes,
                chacha_nonce_length_encoding,
                verify_engine,
            }),
            info: Arc::new(info),
            initial_discovery: Arc::new(initial_discovery),
            lifecycle_access: LifecycleAccess::Owner,
        })
    }

    /// Exact initial scope, successful observations and local failures.
    /// This immutable report performs no native calls.
    pub fn initial_discovery(&self) -> &DiscoveryReport {
        &self.initial_discovery
    }

    /// Verified module provenance and observed version information.
    pub fn info(&self) -> &ModuleInfo {
        &self.info
    }

    /// Immutable initial token discovery; no native calls.
    pub fn tokens(&self) -> &[Capabilities] {
        &self.inner.tokens
    }

    /// Select exactly the supplied slot/manufacturer/model/serial tuple.
    pub fn select(&self, identity: &TokenIdentity) -> Result<TokenContext> {
        let state = self.inner.read()?;
        let registry = state.token_registry()?;
        let matches: Vec<_> = registry
            .tokens
            .iter()
            .filter(|t| {
                &t.capabilities.identity == identity
                    && t.capabilities.flags & CKF_TOKEN_INITIALIZED as u64 != 0
            })
            .collect();
        if matches.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::TokenSelectorNotUnique,
            )));
        }
        matches[0].check()?;
        Ok(TokenContext {
            inner: self.inner.clone(),
            snapshot: matches[0].clone(),
            lifecycle_access: self.lifecycle_access,
        })
    }

    /// The caller's immutable session selection, without a native query.
    pub fn session_policy(&self) -> &crate::SessionPolicy {
        &self.inner.session_policy
    }

    /// The caller's discovery/resource ceilings retained by this module.
    /// This observation does not query the native module.
    pub fn resource_limits(&self) -> Limits {
        self.inner.limits
    }

    /// Module-wide session ceilings. Token ceilings also apply independently.
    pub fn session_limits(&self) -> crate::SessionLimit {
        crate::SessionLimit {
            total: self.inner.limits.sessions,
            read_write: self.inner.session_policy.module_read_write,
        }
    }

    /// Local resource snapshot, including uncertain reservations. This takes no
    /// lifecycle guard and makes no native call, even during an active operation.
    pub fn resource_status(&self) -> Result<crate::ModuleResourceStatus> {
        self.inner.session_ledger.status()
    }

    /// Counts of actual native dispatches, without arguments or secret values.
    /// Returns an error when diagnostic bookkeeping cannot establish exact counts.
    pub fn call_counts(&self) -> Result<BTreeMap<&'static str, u64>> {
        self.inner.state.observe()?.native.counters()
    }

    /// Attempt at most `maximum` deferred first closures. Busy resources stay
    /// counted; returns the number closed. A native failure is returned unchanged
    /// and is never retried. Inspect resource_status for outstanding resources.
    /// A shared client selects only sessions it created; the runtime owner's
    /// administrative view may reap deferred sessions from all its clients.
    pub fn reap_sessions(&self, maximum: usize) -> Result<usize> {
        let mut diagnostics = None;
        crate::session::reap_entries(
            &self.inner,
            maximum,
            None,
            self.cleanup_client(),
            crate::session::CleanupAdmission::Ordinary,
            &mut diagnostics,
        )
    }

    /// Finalize only when every session is closed. On failure this owner remains
    /// available for explicit cleanup; child contexts subsequently reject calls.
    /// Shared clients return a local "runtime owner required" error without
    /// dispatch. Use RuntimeOwner::module for explicit global finalization.
    pub fn close(&self) -> Result<()> {
        self.lifecycle_access.require_owner()?;
        self.inner.foreign.wait_callbacks(&self.inner, None)?;
        // The diagnostic lease leaves before any retired application capture
        // can run its destructor and reenter close. Both outlive native guards.
        let mut retired = FinalizationRetired::default();
        close_owner(&self.inner, false, &mut retired)
    }

    /// Stop ordinary admissions to this owner without waiting for native calls.
    /// Keep the unique permit for bounded maintenance; Drop releases admission
    /// ownership but never revives a closed or uncertain native owner.
    /// An uncertain owner allows only explicit session cleanup and finalization;
    /// ordinary operations remain refused even after the permit is dropped.
    /// Shared clients cannot acquire this global lifecycle permit.
    pub fn begin_drain(&self) -> Result<ModuleDrain> {
        self.lifecycle_access.require_owner()?;
        self.inner.check_lifecycle_reentry()?;
        let state = self.inner.state.read()?;
        Inner::validate_open(&state)?;
        self.inner.state.begin_drain()?;
        // Every resource waiter must recheck drain, including publication
        // behind an object writer. Release possession before waking them.
        drop(state);
        self.inner.context_wakes.notify();
        Ok(ModuleDrain {
            inner: self.inner.clone(),
        })
    }
}
