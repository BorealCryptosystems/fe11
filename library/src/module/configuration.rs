// SPDX-License-Identifier: Apache-2.0
//! One owned configuration path for the existing module-opening contracts.
mod observation;
use super::{Module, ModuleConfig};
use crate::{
    ChaChaNonceLengthEncoding, CryptoOptions, InterfaceSelection, Result, SessionPolicy,
    SymmetricLimits,
};

/// Caller-selected counts for local reference and reservation owners.
/// Each field is explicit: None means no application count ceiling, Some(0)
/// permits no positive reservation. Checked arithmetic and fallible allocation
/// remain mandatory. These are not limits on objects stored inside the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectLimits {
    /// Live ordinary object references plus unpublished reserved references.
    pub object_references: Option<usize>,
    /// Live managed references plus unpublished reserved managed references.
    pub managed_references: Option<usize>,
    /// Concurrent ordinary destination reservations. Existing cleanup may
    /// exceed this quota to release resources; allocation and exclusion remain.
    pub destination_reservations: Option<usize>,
}

/// Native locking selected by the application before initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeConcurrency {
    /// Supply CKF_OS_LOCKING_OK and permit concurrent calls as previously.
    Concurrent,
    /// Omit CKF_OS_LOCKING_OK and serialize access to this initialized instance.
    /// Interface discovery precedes runtime ownership and is not covered by
    /// this serialization. The application coordinates concurrent discovery.
    /// A blocking slot-event wait excludes Finalize; close returns Busy until
    /// that call returns. This does not coordinate calls made outside Fe11.
    Serialized,
    /// Omit CKF_OS_LOCKING_OK and use the application's supplied mutexes.
    /// All four callbacks permit concurrent dispatch after successful Initialize.
    /// Null/partial callback selections still reach Initialize unchanged; if the
    /// module accepts them, Fe11 serializes access because no complete locking
    /// contract was supplied. No retry or replacement callback is introduced.
    ApplicationMutexes,
}

/// Explicit initialization flags and matching Fe11 dispatch behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitializationOptions {
    /// Tell the module that it must not create operating-system threads.
    /// CKR_NEED_TO_CREATE_THREADS remains a native refusal, without retry.
    /// Application mutex callbacks are selected separately on ModuleBuilder.
    pub cannot_create_os_threads: bool,
    /// Locking guarantees requested from the native module.
    pub concurrency: NativeConcurrency,
}

/// Explicit opening choices. There is no implicit selection or `Default`.
/// These settings are owned by the builder and become immutable on opening.
pub struct ModuleOptions {
    /// Explicit initial discovery scope. Local failures remain observations.
    pub discovery: super::DiscoverySelection,
    /// Caller-selected native initialization behavior.
    pub initialization: InitializationOptions,
    /// Allocation and count/fill retry limits for explicit interface discovery.
    pub interface_discovery: crate::InterfaceDiscoveryLimits,
    /// Independent local object/reference/reservation count choices.
    pub object_limits: ObjectLimits,
    /// Provider-default or exact function-table selection, without error fallback.
    pub interface: InterfaceSelection,
    /// Crypto resource limits and representation semantics.
    pub crypto_options: CryptoOptions,
    /// Local module and token session limits.
    pub session_policy: SessionPolicy,
    /// Aggregate budget for owned buffers and derivation metadata.
    pub symmetric_limits: SymmetricLimits,
    /// Explicit native representation of the ChaCha nonce-length field.
    pub chacha_nonce_length_encoding: ChaChaNonceLengthEncoding,
}

#[doc = include_str!("../../docs/api/module/configuration/ModuleBuilder.md")]
#[must_use = "A module configuration has no effect until open is called"]
pub struct ModuleBuilder {
    config: super::provenance::Source,
    windows_file_pinning: super::WindowsFilePinning,
    windows_dependency_search: super::WindowsDependencySearch,
    windows_loader_observations: super::WindowsLoaderObservations,
    windows_image_consistency: super::WindowsImageConsistency,
    discovery: super::DiscoverySelection,
    initialization: InitializationOptions,
    reserved_initialization: Option<super::InitializationReserved>,
    initialization_mutexes: Option<super::InitializationMutexes>,
    interface_discovery: crate::InterfaceDiscoveryLimits,
    object_limits: ObjectLimits,
    interface: InterfaceSelection,
    crypto_options: CryptoOptions,
    verify_engine: Option<crate::VerifyEngine>,
    session_policy: SessionPolicy,
    symmetric_limits: SymmetricLimits,
    chacha_nonce_length_encoding: ChaChaNonceLengthEncoding,
}

impl Module {
    /// Configure a module through independent named choices, then call
    /// [`ModuleBuilder::open`] to validate, load and discover it.
    /// No module is loaded or probed while configuring the builder.
    pub fn builder(config: ModuleConfig, options: ModuleOptions) -> ModuleBuilder {
        Self::source_builder(super::provenance::Source::File(config), options)
    }

    /// Resolve PKCS#11 exports already linked or loaded into this process.
    /// No source file or integrity digest is fabricated for this loading mode.
    pub fn process_builder(limits: super::Limits, options: ModuleOptions) -> ModuleBuilder {
        Self::source_builder(super::provenance::Source::Process(limits), options)
    }

    fn source_builder(config: super::provenance::Source, options: ModuleOptions) -> ModuleBuilder {
        ModuleBuilder {
            config,
            windows_file_pinning: super::WindowsFilePinning::NotRequested,
            windows_dependency_search: super::WindowsDependencySearch::ApplicationConfigured,
            windows_loader_observations: super::WindowsLoaderObservations::NotRequested,
            windows_image_consistency: super::WindowsImageConsistency::NotRequested,
            discovery: options.discovery,
            initialization: options.initialization,
            reserved_initialization: None,
            initialization_mutexes: None,
            interface_discovery: options.interface_discovery,
            object_limits: options.object_limits,
            interface: options.interface,
            crypto_options: options.crypto_options,
            verify_engine: None,
            session_policy: options.session_policy,
            symmetric_limits: options.symmetric_limits,
            chacha_nonce_length_encoding: options.chacha_nonce_length_encoding,
        }
    }
}

impl ModuleBuilder {
    /// Initialize once and return a lifecycle owner plus an ordinary client.
    /// All subsequent clients share the same table, dispatch and resource domain.
    /// Use the owner for explicit global actions; dropping a client never
    /// finalizes. Dropping the owner without close withdraws the generation and
    /// retains resources whose native termination is not established.
    ///
    /// Loading and discovery use the same options and return the same errors as
    /// open. A native ALREADY_INITIALIZED remains an error, not an attachment.
    /// This coordinates Fe11 clients; foreign-library attachment is separate.
    pub fn open_shared(self) -> Result<(super::RuntimeOwner, Module)> {
        self.open().and_then(super::RuntimeOwner::from_opened)
    }

    /// Attach to the application's existing initialization without Initialize.
    /// Interface selection, integrity and discovery still use this builder.
    /// Its initialization flags are not sent or assumed active: the supplied
    /// declaration determines dispatch. Supplying new mutex or pReserved
    /// arguments is an error. No failure authorizes automatic Finalize.
    ///
    /// # Safety
    /// The ExternalInitialization contract must hold at attachment and through
    /// the shared runtime's lifetime. In particular, attachment must be quiescent,
    /// all foreign users must join its participation protocol, and existing
    /// foreign sessions must be registered before clients are used/distributed.
    /// Keep global lifecycle actions under the returned owner's control.
    pub unsafe fn attach_initialized(
        self,
        initialization: super::ExternalInitialization,
    ) -> Result<(super::RuntimeOwner, Module)> {
        self.open_with_external(Some(initialization))
            .and_then(super::RuntimeOwner::from_opened)
    }

    /// Observe the selected table before C_Initialize, even when initialization
    /// would be refused or an operation pointer is absent. No Initialize,
    /// Finalize, token discovery or native cryptographic operation is issued.
    /// Loading may execute native image constructors under the application's
    /// existing trust boundary. The same file/integrity/loader choices and table
    /// selection as open are used; opaque initialization data is not consumed.
    ///
    /// The returned presence snapshot contains no callable pointer or native
    /// owner. A later open resolves its own image/table again; this observation
    /// neither reserves that future instance nor establishes native support.
    pub fn observe_functions(&self) -> Result<crate::FunctionCatalog> {
        use crate::native::Native;
        use observation::ObservationSource;
        self.interface.validate()?;
        match self.observation_source()? {
            ObservationSource::File {
                load_path,
                identity,
                source,
                export_check,
            } => Native::observe_file(
                &load_path,
                identity,
                source,
                export_check,
                self.interface,
                self.interface_discovery,
                self.windows_dependency_search,
                self.windows_loader_observations,
            ),
            ObservationSource::Process => {
                Native::observe_process(self.interface, self.interface_discovery)
            }
        }
    }

    /// Request Windows file/ancestor pins, with explicit reparse and resource
    /// choices. Ordinary loading leaves this control NotRequested. Selecting
    /// it on another platform is refused before loading, not silently ignored.
    pub fn windows_file_pinning(mut self, selection: super::WindowsFilePinning) -> Self {
        self.windows_file_pinning = selection;
        self
    }
    /// Compare the Windows image and table-selection exports with a pinned file.
    /// Requires an explicit file pin and is refused on other platforms. Native
    /// initializers run before this optional check; it does not sandbox a DLL.
    pub fn windows_image_consistency(mut self, selection: super::WindowsImageConsistency) -> Self {
        self.windows_image_consistency = selection;
        self
    }
    /// Select dependency-directory contributions for this Windows load only.
    /// This never modifies process-global loader settings or verifies dependency
    /// identities. The application retains responsibility for its loader state.
    pub fn windows_dependency_search(mut self, selection: super::WindowsDependencySearch) -> Self {
        self.windows_dependency_search = selection;
        self
    }
    /// Request dated observations of selected Windows loader channels.
    /// RequireKnown refuses before loading if that channel cannot be observed.
    /// Reports contain paths and public registry data; applications choose how
    /// to expose them. No observation proves absence of concurrent redirection.
    pub fn windows_loader_observations(
        mut self,
        selection: super::WindowsLoaderObservations,
    ) -> Self {
        self.windows_loader_observations = selection;
        self
    }
    /// Choose all present slots, exact slots, or deferred token discovery.
    pub fn discovery(mut self, selection: super::DiscoverySelection) -> Self {
        self.discovery = selection;
        self
    }
    /// Choose the standard thread-creation flag before loading the module.
    pub fn initialization(mut self, options: InitializationOptions) -> Self {
        self.initialization = options;
        self
    }

    /// Supply a previously declared initialization ABI owner. It stays alive
    /// with the image through Finalize; None restores the standard NULL request.
    pub fn reserved_initialization(mut self, owner: Option<super::InitializationReserved>) -> Self {
        self.reserved_initialization = owner;
        self
    }

    /// Supply application mutex callbacks, retaining their runtime through
    /// finalization. Flags remain those chosen by initialization: Concurrent
    /// permits OS locks too, ApplicationMutexes requests callback locking only,
    /// and Serialized retains Fe11's serialization. Native refusals never retry
    /// with different flags or callbacks. None passes four null pointers.
    pub fn initialization_mutexes(mut self, owner: Option<super::InitializationMutexes>) -> Self {
        self.initialization_mutexes = owner;
        self
    }

    /// Choose allocation and retry ceilings for interface enumeration.
    pub fn interface_discovery(mut self, limits: crate::InterfaceDiscoveryLimits) -> Self {
        self.interface_discovery = limits;
        self
    }

    /// Replace all local object-count choices before opening the module.
    pub fn object_limits(mut self, limits: ObjectLimits) -> Self {
        self.object_limits = limits;
        self
    }

    /// Select provider-default or exact interface behavior before opening.
    pub fn interface(mut self, interface: InterfaceSelection) -> Self {
        self.interface = interface;
        self
    }

    /// Select crypto ceilings and explicit representation semantics.
    /// Hashing origin remains an individual operation choice.
    pub fn crypto_options(mut self, options: CryptoOptions) -> Self {
        self.crypto_options = options;
        self
    }

    /// Select a previously opened software component for optional observations.
    /// None clears the selection; no component is loaded or chosen implicitly.
    /// Native PKCS#11 operations do not acquire a verify-engine requirement
    /// merely because another operation in this module requests an observation.
    pub fn verify_engine(mut self, engine: Option<crate::VerifyEngine>) -> Self {
        self.verify_engine = engine;
        self
    }

    /// Select module/token ceilings and whether to prefilter on announcements.
    /// These never reserve capacity in other processes.
    pub fn session_policy(mut self, policy: SessionPolicy) -> Self {
        self.session_policy = policy;
        self
    }

    /// Select the aggregate byte budget for owned buffers and derivation metadata.
    /// Caller copies and allocations inside the native module remain outside it.
    pub fn symmetric_limits(mut self, limits: SymmetricLimits) -> Self {
        self.symmetric_limits = limits;
        self
    }

    /// Select the explicit native ChaCha nonce-length encoding. Compatibility
    /// encodings retain their documented limits; this never changes nonce size.
    pub fn chacha_nonce_length_encoding(mut self, encoding: ChaChaNonceLengthEncoding) -> Self {
        self.chacha_nonce_length_encoding = encoding;
        self
    }

    /// Validate all settings, verify the selected module file and load it once.
    /// Own this initialization and its private sessions; other processes may
    /// use the token. Use open_shared or attach_initialized to coordinate other
    /// in-process users. Native refusals retain their existing effects and errors.
    pub fn open(self) -> Result<Module> {
        self.open_with_external(None)
    }

    fn open_with_external(self, external: Option<super::ExternalInitialization>) -> Result<Module> {
        self.open_selected(external, None)
    }

    pub(super) fn open_successor(
        self,
        external: Option<super::ExternalInitialization>,
        successor: &super::runtime::SuccessorContext,
    ) -> Result<Module> {
        successor
            .budget
            .check_successor_limit(self.symmetric_limits)?;
        self.open_selected(external, Some(successor))
    }

    fn open_selected(
        self,
        external: Option<super::ExternalInitialization>,
        successor: Option<&super::runtime::SuccessorContext>,
    ) -> Result<Module> {
        if external.is_some()
            && (self.reserved_initialization.is_some() || self.initialization_mutexes.is_some())
        {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::ModuleConfiguration(
                    crate::ModuleConfigurationRejection::InitializationArgumentsDuringAttachment,
                ),
            ));
        }
        let mut initialization_diagnostic = None;
        Module::open_selected_symmetric(
            self.config,
            self.discovery,
            self.initialization,
            self.reserved_initialization,
            self.initialization_mutexes,
            self.interface_discovery,
            self.object_limits,
            self.interface,
            self.crypto_options,
            self.session_policy,
            self.symmetric_limits,
            self.chacha_nonce_length_encoding,
            self.windows_file_pinning,
            self.windows_dependency_search,
            self.windows_loader_observations,
            self.windows_image_consistency,
            self.verify_engine,
            external,
            successor,
            &mut initialization_diagnostic,
        )
    }
}
