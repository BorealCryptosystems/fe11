// SPDX-License-Identifier: Apache-2.0
use crate::{error::check, Error, Result};
use fe11_sys::*;
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};

pub(crate) mod creation;
pub(crate) mod derivation;
pub(crate) mod dispatch;
pub(crate) mod events;
pub(crate) mod frame;
pub(crate) mod functions;
pub(crate) mod generation;
pub(crate) mod image;
pub(crate) mod image_reservation;
pub(crate) mod initialization;
mod interface_inventory;
mod loading;
#[cfg(target_os = "linux")]
mod mapping;
pub(crate) mod message_signature;
pub(crate) mod output;
pub(crate) mod platform;
mod process_image;
pub(crate) mod template;
#[cfg(target_os = "linux")]
pub(crate) use mapping::mapped_image_matches;

use platform::{ExportFileCheck, FileIdentity};
static OWNERS: OnceLock<Mutex<HashMap<FileIdentity, usize>>> = OnceLock::new();

fn reserve_file(identity: FileIdentity) -> Result<()> {
    let mut owners = OWNERS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Error::Poisoned)?;
    owners.try_reserve(1).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeExecution(
            crate::NativeExecutionRejection::FileReservationAllocation,
        ))
    })?;
    let count = owners
        .get(&identity)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
            crate::NativeExecutionRejection::FileReservationCountExhausted,
        )))?;
    owners.insert(identity, count);
    Ok(())
}

fn contains_file(identity: FileIdentity) -> bool {
    OWNERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&identity)
}

fn release_file(identity: FileIdentity) -> bool {
    let mut owners = OWNERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    match owners.get_mut(&identity) {
        Some(count) if *count > 1 => {
            *count -= 1;
            true
        }
        Some(_) => {
            owners.remove(&identity);
            true
        }
        None => false,
    }
}

/// Shared withdrawal observation without borrowing module admission.
/// Every publisher also wakes local capacity waiters; they cannot use a late
/// quota grant as permission to enter an already uncertain native context.
#[derive(Default)]
pub(crate) struct Uncertainty {
    // Wake predicates cannot borrow State. This mirrors its local lifecycle
    // solely to reject admission; it never supplies a resource-release proof.
    lifecycle: std::sync::atomic::AtomicU8,
    withdrawn: std::sync::atomic::AtomicBool,
    // A recorded loss of initialization is distinct from uncertain execution.
    // It withdraws old native authority, but supplies no memory-release proof.
    initialization_lost: std::sync::atomic::AtomicBool,
    // Dropping the lifecycle owner withdraws clients without asserting that
    // the native initialization ended or that any loan can be released.
    owner_withdrawn: std::sync::atomic::AtomicBool,
    token_registry_unverifiable: std::sync::atomic::AtomicBool,
    // Only controls of an asynchronous parent can publish this retained loan.
    async_execution_unproven: std::sync::atomic::AtomicBool,
    unscoped_pending: std::sync::atomic::AtomicBool,
    admission: OnceLock<std::sync::Weak<crate::admission_wait::ContextWakes>>,
}

#[repr(u8)]
enum AdmissionLifecycle {
    Open = 0,
    Finalizing = 1,
    Closed = 2,
}

impl Uncertainty {
    fn publish_lifecycle(&self, next: AdmissionLifecycle) {
        use std::sync::atomic::Ordering;
        // Closing a predecessor is permanent even without a Finalize receipt.
        let next = next as u8;
        let mut observed = self.lifecycle.load(Ordering::Acquire);
        while observed != AdmissionLifecycle::Closed as u8 {
            match self.lifecycle.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        self.notify_admission();
    }

    fn observe_finalization(&self, phase: Finalization) {
        let next = match phase {
            Finalization::Issued
            | Finalization::Returned(CKR_PENDING)
            | Finalization::Published(CKR_PENDING) => AdmissionLifecycle::Finalizing,
            Finalization::Returned(CKR_OK) | Finalization::Published(CKR_OK) => {
                AdmissionLifecycle::Closed
            }
            _ => AdmissionLifecycle::Open,
        };
        self.publish_lifecycle(next);
    }

    pub(crate) fn mark_token_registry_unverifiable(&self) {
        self.token_registry_unverifiable
            .store(true, std::sync::atomic::Ordering::Release);
        self.mark();
    }

    pub(crate) fn check_token_registry(&self) -> Result<()> {
        if self
            .token_registry_unverifiable
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Poisoned);
        }
        Ok(())
    }

    pub(crate) fn withdraw_owner(&self) {
        self.owner_withdrawn
            .store(true, std::sync::atomic::Ordering::Release);
        self.mark();
    }

    /// Atomic-only predicate, safe while an admission Wake is held. Cleanup
    /// publication has its own authority and must not use this native gate.
    pub(crate) fn check_native_authority(&self) -> Result<()> {
        match self.lifecycle.load(std::sync::atomic::Ordering::Acquire) {
            value if value == AdmissionLifecycle::Open as u8 => {}
            value if value == AdmissionLifecycle::Finalizing as u8 => {
                return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                    crate::ModuleLifecycleBusy::ModuleFinalizationCompletionUnproven,
                )));
            }
            value if value == AdmissionLifecycle::Closed as u8 => {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::ModuleClosed,
                )));
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::NativeAdmissionLifecycle,
                )))
            }
        }
        if self
            .owner_withdrawn
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::RuntimeOwnerWithdrawn,
            )));
        }
        if self.initialization_lost() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeInitializationRetired,
            )));
        }
        Ok(())
    }

    pub(crate) fn check_available(&self) -> Result<()> {
        self.check_native_authority()?;
        if self.is_uncertain() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        Ok(())
    }

    pub(crate) fn observe_runtime_return(&self, code: u64) {
        if code == CKR_CRYPTOKI_NOT_INITIALIZED as u64 {
            self.retire_initialization();
        }
    }

    pub(crate) fn observe_async_return(&self, code: u64) {
        self.observe_runtime_return(code);
        if code == CKR_GENERAL_ERROR as u64 {
            self.async_execution_unproven
                .store(true, std::sync::atomic::Ordering::Release);
            self.mark();
        }
    }
    pub(crate) fn retire_initialization(&self) {
        self.initialization_lost
            .store(true, std::sync::atomic::Ordering::Release);
        self.mark();
    }

    pub(crate) fn initialization_lost(&self) -> bool {
        self.initialization_lost
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn bind_admission(
        &self,
        wake: &Arc<crate::admission_wait::ContextWakes>,
    ) -> Result<()> {
        self.admission.set(Arc::downgrade(wake)).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeAdmissionAlreadyBound,
            ))
        })
    }

    pub(crate) fn is_uncertain(&self) -> bool {
        self.withdrawn.load(std::sync::atomic::Ordering::Acquire)
    }

    /// A local withdrawal or returned refusal is not uncertain execution.
    /// Unscoped PENDING and an unreturned async parent loan prohibit Finalize.
    pub(crate) fn execution_unproven(&self) -> bool {
        self.unscoped_pending
            .load(std::sync::atomic::Ordering::Acquire)
            || self
                .async_execution_unproven
                .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn mark(&self) {
        self.withdrawn
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify_admission();
    }

    fn notify_admission(&self) {
        if let Some(wake) = self.admission.get().and_then(std::sync::Weak::upgrade) {
            wake.notify();
        }
    }
}

/// Result recording is infallible; event/identity publication is a separate step.
/// A successful native return consumes this owner's finalization authority even
/// when its local publication is still outstanding. This records Fe11's own
/// lifecycle actions; it is not a live observation of external initialization.
#[derive(Clone, Copy)]
enum Finalization {
    NotIssued,
    Issued,
    Returned(CK_RV),
    Published(CK_RV),
}

impl Finalization {
    fn execution_unproven(self) -> bool {
        match self {
            Self::Issued => true,
            Self::Returned(code) | Self::Published(code) => {
                !crate::native_return::call_memory_returned(code)
            }
            Self::NotIssued => false,
        }
    }
}

/// Call counts are diagnostic evidence, never authority to release native owners.
struct CallCounters {
    values: BTreeMap<&'static str, u64>,
    incomplete: bool,
}

impl CallCounters {
    fn snapshot(&self) -> Result<BTreeMap<&'static str, u64>> {
        if self.incomplete {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeCallCountersIncomplete,
            )));
        }
        Ok(self.values.clone())
    }

    // The sole-owner Drop path must not allocate a missing map entry or refuse
    // safe finalization because diagnostic bookkeeping overflowed or panicked.
    // A lost count remains explicit; never publish a saturated count as exact.
    fn record_finalization(counters: &Mutex<Self>) {
        let mut counters = match counters.lock() {
            Ok(counters) => counters,
            Err(poisoned) => {
                let mut counters = poisoned.into_inner();
                counters.incomplete = true;
                counters
            }
        };
        if let Some(value) = counters.values.get_mut("C_Finalize") {
            if let Some(next) = value.checked_add(1) {
                *value = next;
                return;
            }
        }
        counters.incomplete = true;
    }
}

/// Private owner of the dynamic library. Function pointers never outlive it.
pub(crate) struct Native {
    pub(crate) process_file: Option<Result<crate::ModuleFileObservation>>,
    pub(crate) dispatch: Option<Arc<dispatch::Dispatch>>,
    // Derived once from the selected, copied table. The callable views below
    // retain its exact pointers; this catalogue contains presence states only.
    catalog: crate::FunctionCatalog,
    pub table: crate::interfaces::CommonFunctions,
    pub login_user: CK_C_LoginUser,
    pub(crate) lifecycle: functions::Lifecycle,
    pub interface_flags: u64,
    pub(crate) export_file_identity: crate::Observation<bool>,
    pub authenticated_transport: Option<crate::interfaces::AuthenticatedKeyTransportFunctions>,
    pub messages: Option<crate::interfaces::MessageFunctions>,
    pub asynchronous: Option<crate::interfaces::AsyncFunctions>,
    pub kem: Option<crate::interfaces::KemFunctions>,
    pub verify_signature: Option<crate::interfaces::VerifySignatureFunctions>,
    pub(crate) image: Arc<image::LoadedImage>,
    pub(crate) notifications: crate::notify::NotifyRegistry,
    // Construction follows successful C_Initialize. Finalization is the sole
    // record of whether this owner's authority has since been consumed.
    finalization: Finalization,
    drop_policy: initialization::DropPolicy,
    pub(crate) events: Arc<events::EventRegistry>,
    uncertain: Arc<Uncertainty>,
    calls: Mutex<CallCounters>,
}
/// A table observation cannot acquire initialization/finalization authority.
enum LoadPurpose<'a> {
    Observe,
    Open {
        request: initialization::Request<'a>,
        notifications: crate::notify::NotifyRegistry,
    },
}
enum LoadingOutcome {
    Observed(crate::FunctionCatalog),
    Initialized(Native, crate::WindowsLoaderReport),
}
impl LoadingOutcome {
    fn initialized(self) -> Result<(Native, crate::WindowsLoaderReport)> {
        match self {
            Self::Initialized(native, report) => Ok((native, report)),
            Self::Observed(_) => Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::InitializationOutcomeExpected,
            ))),
        }
    }
    fn observed(self) -> Result<crate::FunctionCatalog> {
        match self {
            Self::Observed(catalog) => Ok(catalog),
            Self::Initialized(_, _) => {
                Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::TableObservationExpected,
                )))
            }
        }
    }
}
impl Native {
    /// Record first, then publish the rejection mirror before any later
    /// fallible work. Local cleanup continues to inspect the recorded receipt.
    fn record_finalization(&mut self, phase: Finalization) {
        self.finalization = phase;
        self.uncertain.observe_finalization(phase);
    }

    pub(crate) fn close_admission(&self) {
        self.uncertain.publish_lifecycle(AdmissionLifecycle::Closed);
    }

    pub(crate) fn mark_token_registry_unverifiable(&self) {
        self.uncertain.mark_token_registry_unverifiable();
    }

    /// A pending invocation without a session receipt cannot participate in
    /// synchronous instance-finalization recovery. No timeout clears this proof.
    pub(crate) fn mark_unscoped_pending(&self) {
        self.uncertain
            .unscoped_pending
            .store(true, std::sync::atomic::Ordering::Release);
        self.mark_uncertain();
    }

    pub(crate) fn has_unscoped_pending(&self) -> bool {
        self.uncertain
            .unscoped_pending
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn function_catalog(&self) -> crate::FunctionCatalog {
        self.catalog.clone()
    }
    pub(crate) fn uncertainty_flag(&self) -> Arc<Uncertainty> {
        self.uncertain.clone()
    }
    pub(crate) fn allows_implicit_cleanup(&self) -> bool {
        self.drop_policy == initialization::DropPolicy::Automatic
    }
    pub fn is_uncertain(&self) -> bool {
        self.uncertain.is_uncertain()
    }
    pub(crate) fn check_available(&self) -> Result<()> {
        self.uncertain.check_available()
    }
    pub(crate) fn check_native_authority(&self) -> Result<()> {
        self.uncertain.check_native_authority()
    }
    pub fn mark_uncertain(&self) {
        self.uncertain.mark();
    }
    pub(crate) fn observe_runtime_return(&self, rv: CK_RV) {
        self.uncertain.observe_runtime_return(rv as u64);
    }
    pub(crate) fn observe_async_return(&self, rv: CK_RV) {
        self.uncertain.observe_async_return(rv as u64);
    }
    pub(crate) fn successor_ready(&self) -> Result<()> {
        if !self.finalization_succeeded() && !self.uncertainty_flag().initialization_lost() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::RuntimeRetirementNotEstablished,
            )));
        }
        if self.finalization_incomplete()
            || self.has_unscoped_pending()
            || !self.notifications.quiescent()
        {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::RuntimeNativeCompletionUnproven,
            )));
        }
        if !self.finalization_succeeded()
            && self
                .uncertain
                .async_execution_unproven
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::RuntimeNativeCompletionUnproven,
            )));
        }
        Ok(())
    }
    pub fn record(&self, name: &'static str) -> Result<()> {
        self.require_dispatch_functions(name)?;
        self.record_ready(name)
    }

    /// PRF and the random-only KEA phase have no object to clean up. They still
    /// resolve DeriveKey, wait for callbacks and count the exact native call.
    pub(crate) fn record_derivation_without_objects(&self) -> Result<()> {
        self.require_function("C_DeriveKey")?;
        self.record_ready("C_DeriveKey")
    }

    fn record_ready(&self, name: &'static str) -> Result<()> {
        if let Some(dispatch) = &self.dispatch {
            dispatch.wait_callbacks()?;
        }
        self.record_counter(name)
    }

    /// Maintenance Logout may cross generic uncertainty, never withdrawal.
    /// Its callback wait must observe the same context wake as its admission.
    pub(crate) fn record_checked(
        &self,
        name: &'static str,
        context: &Arc<crate::admission_wait::Wake>,
        validate: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        self.require_dispatch_functions(name)?;
        validate()?;
        if let Some(dispatch) = &self.dispatch {
            dispatch.wait_callbacks_checked(context, validate)?;
        }
        validate()?;
        self.record_counter(name)
    }

    fn record_counter(&self, name: &'static str) -> Result<()> {
        let mut calls = self.calls.lock().map_err(|_| Error::Poisoned)?;
        let n = calls.values.entry(name).or_default();
        *n = n
            .checked_add(1)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeInterfaces(
                crate::NativeInterfacesRejection::CounterExhausted,
            )))?;
        Ok(())
    }
    /// Resolve the immutable table before counting or issuing a native call.
    /// Creation cannot accept a resource whose promised cleanup is already
    /// known to be unavailable. Attribute observations are independent: their
    /// absence after creation must preserve the published native reference.
    fn require_dispatch_functions(&self, name: &'static str) -> Result<()> {
        let require = |function| self.require_function(function);
        require(name)?;
        match name {
            "C_OpenSession" => require("C_CloseSession"),
            "C_CreateObject"
            | "C_CopyObject"
            | "C_GenerateKey"
            | "C_GenerateKeyPair"
            | "C_UnwrapKey"
            | "C_UnwrapKeyAuthenticated"
            | "C_DeriveKey"
            | "C_EncapsulateKey"
            | "C_DecapsulateKey" => require("C_DestroyObject"),
            "C_FindObjectsInit" => {
                require("C_FindObjects")?;
                require("C_FindObjectsFinal")
            }
            _ => Ok(()),
        }
    }

    fn require_function(&self, function: &'static str) -> Result<()> {
        if self.catalog.observation(function) == Some(crate::FunctionPresence::Present) {
            Ok(())
        } else {
            Err(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction { function },
            ))
        }
    }

    pub fn counters(&self) -> Result<BTreeMap<&'static str, u64>> {
        self.calls.lock().map_err(|_| Error::Poisoned)?.snapshot()
    }
    pub fn finalize(
        &mut self,
        retired: &mut crate::notify::RetiredNotifications,
        diagnostic: crate::error::CompletionDiagnostic,
        publication: &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<()> {
        self.finalize_admitted(false, retired, diagnostic, publication)
    }
    pub(crate) fn finalization_succeeded(&self) -> bool {
        matches!(
            self.finalization,
            Finalization::Returned(CKR_OK) | Finalization::Published(CKR_OK)
        )
    }

    pub(crate) fn finalization_incomplete(&self) -> bool {
        self.finalization.execution_unproven()
    }

    pub(crate) fn execution_unproven(&self) -> bool {
        self.uncertain.execution_unproven()
    }

    /// Local repair only. The raw OK already makes the instance unavailable;
    /// callers use this while publishing their retained resource ledgers.
    pub(crate) fn repair_finalization(&mut self) -> Result<()> {
        if !self.finalization_succeeded() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeFinalizationSuccessAbsent,
            )));
        }
        // A last waiter may have failed publication after our own receipt was
        // published. Reconcile both cases locally; never repeat C_Finalize.
        self.events.finish_finalize(CKR_OK)?;
        self.record_finalization(Finalization::Published(CKR_OK));
        Ok(())
    }
    // Called only by explicit owner finalization under its exclusive state guard,
    // after every retained owner passed its completion/withdrawal gate. The drain
    // permit remains independent of this recovery path. Never clears uncertainty.
    pub(crate) fn finalize_recovery(
        &mut self,
        retired: &mut crate::notify::RetiredNotifications,
        diagnostic: crate::error::CompletionDiagnostic,
        publication: &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<()> {
        self.finalize_admitted(true, retired, diagnostic, publication)
    }
    fn finalize_admitted(
        &mut self,
        recovery: bool,
        retired: &mut crate::notify::RetiredNotifications,
        diagnostic: crate::error::CompletionDiagnostic,
        publication: &mut Option<crate::error::CompletionDiagnostic>,
    ) -> Result<()> {
        // Refuse a reused destination before any native effect: replacing it
        // could destroy application captures while the module writer is held.
        if !retired.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NotificationRetirementOwnerOccupied,
            )));
        }
        if self.uncertainty_flag().initialization_lost() && !self.finalization_succeeded() {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::RetiredRuntimeHasNoFinalizeAuthority,
            )));
        }
        if matches!(self.finalization, Finalization::Published(CKR_OK)) {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ModuleClosed,
            )));
        }
        if matches!(self.finalization, Finalization::Returned(CKR_OK)) {
            // The instance is already natively closed. Repair publication only;
            // even a prior local failure cannot authorize another C_Finalize.
            diagnostic.finish(self.events.finish_finalize(CKR_OK))?;
            self.record_finalization(Finalization::Published(CKR_OK));
            return Ok(());
        }
        if self.finalization_incomplete() {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::ModuleFinalizationCompletionUnproven,
            )));
        }
        if self.execution_unproven() {
            return Err(Error::Busy(crate::BusyReason::ModuleLifecycle(
                crate::ModuleLifecycleBusy::NativeCallCompletionUnproven,
            )));
        }
        if self.is_uncertain() && !recovery {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::NativeStateUncertain,
            )));
        }
        if !self.notifications.quiescent() {
            return Err(Error::Busy(crate::BusyReason::NativeExecution(
                crate::NativeExecutionBusy::NotificationCallback,
            )));
        }
        if let Finalization::Returned(code) = self.finalization {
            // A new explicit request first reconciles the previous refusal.
            // This is a local publication step, not an automatic native retry.
            if let Err(error) = self.events.finish_finalize(code) {
                return diagnostic.finish_native(code, Err(error));
            }
            self.record_finalization(Finalization::Published(code));
        }
        // A previous returned refusal permits a new explicit request. Its
        // receipt remains distinct from uncertainty and from an implicit Drop.
        // A returned refusal is admissible in the registry without granting
        // ordinary finalization the recovery path's poisoned-lock handling.
        self.events.begin_finalize(recovery)?;
        if let Err(error) = self
            .events
            .finalize_dispatched(|| self.record("C_Finalize"))
        {
            self.mark_uncertain();
            // Preserve the existing prohibition on repeating an already
            // compounded cleanup. Neither this path nor abort issues C.
            if matches!(error.without_object_marker(), Error::CleanupFailed { .. }) {
                return Err(error);
            }
            return Err(match self.events.abort_finalize() {
                Ok(()) => error,
                Err(cleanup) => diagnostic
                    .pair_with(publication.take().expect("finalization publication unused"))
                    .finish(error, cleanup),
            });
        }
        // SAFETY: the exclusive state guard drained ordinary calls/sessions.
        // PKCS#11 permits Finalize to release a blocking WaitForSlotEvent call.
        // Its image lease and identity reservation survive until native return.
        self.record_finalization(Finalization::Issued);
        let rv = unsafe { (self.lifecycle.finalize)(std::ptr::null_mut()) };
        self.record_finalization(Finalization::Returned(rv));
        self.observe_runtime_return(rv);
        let success = rv == CKR_OK;
        if success {
            let quarantined = self.is_uncertain();
            self.notifications.finalized(retired, quarantined);
            self.image.finalized();
        } else if !crate::native_return::call_memory_returned(rv) {
            self.mark_uncertain();
        }
        let publication = self.events.finish_finalize(rv);
        if publication.is_ok() {
            self.record_finalization(Finalization::Published(rv));
        }
        if publication.is_err() {
            self.mark_uncertain();
            retired.quarantine();
        }
        // Both causes survive a simultaneous native refusal/publication error.
        // Diagnostic storage was prepared before module possession and dispatch.
        diagnostic.finish_native(rv, publication)?;
        check(rv, "C_Finalize", !success)?;
        Ok(())
    }
}

// Pure prefix validation, before any access to the full function-table layout.
fn qualified_table_version(version: CK_VERSION, expected: (u8, u8)) -> Result<()> {
    if !matches!(expected, (2, 20) | (2, 30) | (2, 40))
        || (version.major, version.minor) != expected
    {
        return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
            crate::NativeExecutionRejection::UnqualifiedInterfaceVersion,
        )));
    }
    Ok(())
}

// Parse only the kernel's fixed leading fields; filenames are neither trusted
// nor needed. Non-UTF8 filenames, spaces, and deleted-file suffixes are harmless.
#[cfg(target_os = "linux")]
pub(crate) fn mapping_matches(maps: &[u8], address: usize, identity: FileIdentity) -> bool {
    for line in maps.split(|b| *b == b'\n') {
        let mut fields = line
            .split(|b| b.is_ascii_whitespace())
            .filter(|x| !x.is_empty());
        let Some(range) = fields.next().and_then(|x| std::str::from_utf8(x).ok()) else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };
        if !(start <= address && address < end) {
            continue;
        }
        let Some(perms) = fields.next() else {
            return false;
        };
        if perms.get(2) != Some(&b'x') {
            return false;
        }
        if fields.next().is_none() {
            return false;
        }
        let Some(device) = fields.next().and_then(|x| std::str::from_utf8(x).ok()) else {
            return false;
        };
        let Some((major, minor)) = device.split_once(':') else {
            return false;
        };
        let (Ok(major), Ok(minor)) = (
            u32::from_str_radix(major, 16),
            u32::from_str_radix(minor, 16),
        ) else {
            return false;
        };
        let Some(inode) = fields
            .next()
            .and_then(|x| std::str::from_utf8(x).ok())
            .and_then(|x| x.parse::<u64>().ok())
        else {
            return false;
        };
        return inode != 0
            && u128::from(inode) == identity.1
            && major == libc::major(identity.0)
            && minor == libc::minor(identity.0);
    }
    false
}

impl Drop for Native {
    fn drop(&mut self) {
        if !self.allows_implicit_cleanup() && !self.finalization_succeeded() {
            self.mark_uncertain();
        }
        // Sole-owner destruction has no live module guard. Keep captures until
        // after the finalization result has been published, even on refusal.
        let mut retired_notifications = crate::notify::RetiredNotifications::default();
        if !self.notifications.quiescent() {
            self.mark_uncertain();
        }
        if !self.finalization_succeeded() && !matches!(self.finalization, Finalization::NotIssued) {
            // Only a new explicit request may follow a recorded refusal.
            // Drop must retain the unresolved owner, never replay its call.
            self.mark_uncertain();
        }
        if !self.finalization_succeeded() && !self.is_uncertain() {
            // A waiter owns Inner independently, so the last Native drop cannot
            // race its native call. Use the same reservation transition as close.
            if self.events.begin_finalize(false).is_ok()
                && self
                    .events
                    .finalize_dispatched(|| {
                        CallCounters::record_finalization(&self.calls);
                        Ok(())
                    })
                    .is_ok()
            {
                // SAFETY: outer State drop closed its resources; no waiter lease remains.
                self.record_finalization(Finalization::Issued);
                let rv = unsafe { (self.lifecycle.finalize)(std::ptr::null_mut()) };
                self.record_finalization(Finalization::Returned(rv));
                self.observe_runtime_return(rv);
                let success = rv == CKR_OK;
                if success {
                    let quarantined = self.is_uncertain();
                    self.notifications
                        .finalized(&mut retired_notifications, quarantined);
                    self.image.finalized();
                }
                let publication = self.events.finish_finalize(rv);
                if publication.is_ok() {
                    self.record_finalization(Finalization::Published(rv));
                }
                if !success || publication.is_err() {
                    self.mark_uncertain();
                    retired_notifications.quarantine();
                }
            } else {
                self.mark_uncertain();
            }
        }
        // LoadedImage and NotifyRegistry independently retain image, file and
        // pApplication unless finalization was established. The event registry
        // retains the initialization identity while completion is unproven.
    }
}
