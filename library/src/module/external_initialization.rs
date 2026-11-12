// SPDX-License-Identifier: Apache-2.0
//! An application's existing initialization, not a second Initialize request.

use crate::{Error, Result};

/// Actual concurrency contract of an initialization performed outside Fe11.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalConcurrency {
    /// The initialized module permits parallel calls on distinct sessions,
    /// through OS locking or a complete, retained application mutex runtime.
    Concurrent,
    /// All participants use Fe11's common serialized dispatch. No flags or
    /// callbacks are sent again to the already initialized module.
    Serialized,
}

/// Identity of the interface used by an external initializer. Function addresses
/// are transient process identities, never persistent bindings or vendor filters.
#[derive(Clone, Copy)]
pub struct ExternalModuleIdentity {
    /// C_Initialize from the interface whose initialization is being transferred.
    pub initialize: fe11_sys::CK_C_Initialize,
    /// C_Finalize belonging to that same interface and initialization.
    pub finalize: fe11_sys::CK_C_Finalize,
    /// Version of the selected function table, not CK_INFO.cryptokiVersion.
    pub function_list_version: (u8, u8),
    /// Flags of the selected interface, or zero for a historical function list.
    pub interface_flags: u64,
}

/// Retained state of an initialization already performed by the application.
///
/// Construction makes no native call. Attachment consumes this declaration;
/// it never infers ownership from CKR_CRYPTOKI_ALREADY_INITIALIZED. If it is
/// abandoned before a proven Finalize, the owner is deliberately retained:
/// dropping a Rust value cannot end native use of callbacks or pReserved.
/// Application-owned storage remains outside Fe11's owned-buffer budget.
pub struct ExternalInitialization {
    identity: ExternalModuleIdentity,
    concurrency: ExternalConcurrency,
    owner: Option<Box<dyn Send + Sync>>,
}

impl ExternalInitialization {
    /// Declare the current external initialization and retain everything it uses.
    /// `owner` must also retain the external library's image and callback runtime.
    ///
    /// # Safety
    /// The identified interface must currently be successfully initialized with
    /// the stated concurrency contract and the Fe11-sys ABI. Every entry in the
    /// selected table must belong to this same live initialization. Function
    /// addresses and version fields alone cannot prove that native generation.
    /// The owner must keep all initialization arguments, mutex state, callback
    /// code and dependent images valid, with stable addresses, through Finalize
    /// and the return of outstanding callbacks/waiters. Its destructor must not
    /// issue native lifecycle calls. No native invocation may overlap attachment.
    /// After attachment, every foreign call/callback and pending graph must
    /// participate in the shared runtime; all existing foreign sessions must be
    /// registered, with their outstanding graphs, before any ordinary or global
    /// action through the owner or its clients. Keep other users quiescent until
    /// this integration is complete; a failed adoption is not completion. Global
    /// lifecycle actions must go through its owner, never another library's Drop.
    /// Participants may not access another participant's private sessions or
    /// secretly reset/reinitialize the module. An opaque library that cannot
    /// honor this protocol is not made safe merely by retaining its Arc.
    pub unsafe fn new<T: Send + Sync + 'static>(
        identity: ExternalModuleIdentity,
        concurrency: ExternalConcurrency,
        owner: T,
    ) -> Self {
        Self {
            identity,
            concurrency,
            owner: Some(Box::new(owner)),
        }
    }

    /// Release an unattached declaration after external finalization.
    ///
    /// # Safety
    /// C_Finalize must have returned CKR_OK for this exact initialization, every
    /// native invocation/callback/waiter must have returned, and no native loan
    /// may still use the owner's code or data. An error, timeout, token removal
    /// or notification is not that proof. No attachment may have occurred.
    pub unsafe fn release_after_finalize(mut self) {
        drop(self.owner.take());
    }

    pub(crate) fn check(
        &self,
        table: &crate::interfaces::CommonFunctions,
        interface_flags: u64,
    ) -> Result<()> {
        if self.identity.initialize.is_none()
            || self.identity.finalize.is_none()
            || self.identity.initialize.map(|f| f as usize)
                != table.C_Initialize.map(|f| f as usize)
            || self.identity.finalize.map(|f| f as usize) != table.C_Finalize.map(|f| f as usize)
            || self.identity.function_list_version != (table.version.major, table.version.minor)
            || self.identity.interface_flags != interface_flags
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::ExternalInitializationIdentityMismatch,
            )));
        }
        Ok(())
    }

    pub(crate) fn serialized(&self) -> bool {
        self.concurrency == ExternalConcurrency::Serialized
    }

    // Called only after LoadedImage recorded successful native finalization and
    // its final strong image lease is released, including any outstanding waiter.
    pub(crate) fn finalized(&mut self) {
        drop(self.owner.take());
    }
}

impl Drop for ExternalInitialization {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            std::mem::forget(owner);
        }
    }
}
